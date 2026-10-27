// SPDX-License-Identifier: Apache-2.0
//
// Byte-for-byte check against vectors/qoresign-v1.json, generated from the
// TypeScript reference implementation.

use qoresign::*;
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/qoresign-v1.json"
    );
    let text = std::fs::read_to_string(path).expect("read vectors/qoresign-v1.json");
    serde_json::from_str(&text).expect("parse vectors")
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("missing string {key}"))
}

fn h(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(s(v, key)).unwrap_or_else(|_| panic!("bad hex in {key}"))
}

fn sha256_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(b))
}

struct Ctx {
    v: Value,
    mnemonic: String,
    chain_id: String,
    classical: ClassicalKey,
    pq: PqKeyPair,
    address: String,
}

fn ctx() -> Ctx {
    let v = vectors();
    let mnemonic = s(&v, "mnemonic").to_owned();
    let chain_id = s(&v, "chainId").to_owned();
    let classical = derive_classical_key(&mnemonic, ClassicalKeyType::Secp256k1, 0).unwrap();
    let address = address_from_public_key(&classical.public_key, ClassicalKeyType::Secp256k1)
        .unwrap()
        .bech32;
    let pq = derive_canonical_pq_key(&mnemonic, &address).unwrap();
    Ctx {
        v,
        mnemonic,
        chain_id,
        classical,
        pq,
        address,
    }
}

#[test]
fn format() {
    assert_eq!(s(&vectors(), "format"), "qoresign-vectors-v1");
}

#[test]
fn accounts() {
    let c = ctx();
    for (name, key_type) in [
        ("secp256k1", ClassicalKeyType::Secp256k1),
        ("eth_secp256k1", ClassicalKeyType::EthSecp256k1),
    ] {
        let a = &c.v["accounts"][name];
        assert_eq!(default_classical_path(key_type, 0), s(a, "path"));
        let k = derive_classical_key_at(&c.mnemonic, key_type, s(a, "path"), "").unwrap();
        assert_eq!(k, derive_classical_key(&c.mnemonic, key_type, 0).unwrap());
        assert_eq!(hex::encode(k.private_key), s(a, "privateKey"), "{name}");
        assert_eq!(hex::encode(k.public_key), s(a, "publicKey"), "{name}");
        let addr = address_from_public_key(&k.public_key, key_type).unwrap();
        assert_eq!(addr.bech32, s(a, "address"), "{name}");
        assert_eq!(addr.hex, s(a, "hex"), "{name}");
        assert_eq!(parse_address(s(a, "hex")).unwrap(), addr);
        assert_eq!(parse_address(s(a, "address")).unwrap(), addr);
        assert_eq!(
            classical_key_type_for(&k.public_key, &addr.bech32).unwrap(),
            Some(key_type)
        );
        let again = classical_key_from_private(&k.private_key, key_type).unwrap();
        assert_eq!(again, k);
    }
}

#[test]
fn canonical_keys() {
    let c = ctx();
    let list = c.v["canonical"].as_array().unwrap();
    assert_eq!(list.len(), 2);
    for item in list {
        let k = derive_canonical_pq_key(&c.mnemonic, s(item, "address")).unwrap();
        assert_eq!(k.public_key.len(), ML_DSA_87_PUBLIC_KEY_LENGTH);
        assert_eq!(k.secret_key.len(), ML_DSA_87_SECRET_KEY_LENGTH);
        assert_eq!(hex::encode(&k.public_key), s(item, "publicKey"));
        assert_eq!(sha256_hex(&k.public_key), s(item, "publicKeySha256"));
        // The 0x form of the same account gives the same key.
        let hex_form = parse_address(s(item, "address")).unwrap().hex;
        assert_eq!(derive_canonical_pq_key(&c.mnemonic, &hex_form).unwrap(), k);
    }
    assert_eq!(hex::encode(&c.pq.public_key), s(&list[0], "publicKey"));
}

#[test]
fn hd_keys() {
    let c = ctx();
    let list = c.v["hd"].as_array().unwrap();
    assert_eq!(list.len(), 3);
    for item in list {
        let k = derive_hd_pq_key(&c.mnemonic, s(item, "path"), "").unwrap();
        assert_eq!(
            hex::encode(&k.public_key),
            s(item, "publicKey"),
            "{}",
            s(item, "path")
        );
        assert_eq!(sha256_hex(&k.public_key), s(item, "publicKeySha256"));
    }
    assert_eq!(default_hd_path(0, 118), s(&list[0], "path"));
    assert_eq!(default_hd_path(1, 118), s(&list[1], "path"));
    assert_eq!(default_hd_path(0, 60), s(&list[2], "path"));

    let rejected: Vec<&str> = c.v["hdRejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p.as_str().unwrap())
        .collect();
    assert_eq!(rejected.len(), 3);
    let codes: Vec<&str> = rejected
        .iter()
        .map(|p| derive_hd_pq_key(&c.mnemonic, p, "").unwrap_err().code())
        .collect();
    assert_eq!(
        codes,
        ["HD_NON_HARDENED", "HD_INVALID_PATH", "HD_INVALID_PATH"]
    );
}

#[test]
fn hybrid_tx() {
    let c = ctx();
    let t = &c.v["hybridTx"];
    let account_number = t["accountNumber"].as_u64().unwrap();
    let body = h(t, "bodyBytes");
    let auth = h(t, "authInfoBytes");
    let cases = t["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases {
        let version: SignBytesVersion = s(case, "signBytesVersion").parse().unwrap();
        let sign_bytes = hybrid_sign_bytes(&c.chain_id, &body, &auth, version).unwrap();
        assert_eq!(hex::encode(&sign_bytes), s(case, "signBytes"));

        let mut args = SignHybridArgs::new(
            &c.chain_id,
            account_number,
            &body,
            &auth,
            &c.classical,
            Some(&c.pq),
        );
        args.options.sign_bytes_version = version;
        let signed = sign_hybrid(&args).unwrap();
        let pq_sig = signed.pq_signature.as_deref().unwrap();
        assert_eq!(pq_sig.len(), ML_DSA_87_SIGNATURE_LENGTH);
        assert_eq!(hex::encode(pq_sig), s(case, "pqSignature"), "{version:?}");
        assert_eq!(hex::encode(&signed.body_bytes), s(case, "signedBodyBytes"));
        assert_eq!(
            hex::encode(signed.classical_signature),
            s(case, "classicalSignature")
        );
        assert_eq!(hex::encode(&signed.tx_bytes), s(case, "txBytes"));

        // The vector bytes decode and verify.
        let tx_bytes = h(case, "txBytes");
        let mut vargs = VerifyHybridTxArgs::new(
            &tx_bytes,
            &c.chain_id,
            account_number,
            &c.classical.public_key,
            Some(&c.pq.public_key),
        );
        vargs.version = match version {
            SignBytesVersion::V1 => VerifyVersion::V1,
            SignBytesVersion::V2 => VerifyVersion::V2,
        };
        let res = verify_hybrid_tx(&vargs).unwrap();
        assert!(res.valid && res.classical);
        assert_eq!(res.pq.unwrap().sign_bytes_version, Some(version));

        vargs.version = VerifyVersion::Either;
        let res = verify_hybrid_tx(&vargs).unwrap();
        assert!(res.valid);
        assert_eq!(res.pq.unwrap().sign_bytes_version, Some(version));

        // Re-signing the already-layered body replaces the layer and gives the same bytes.
        let mut again = args;
        again.body_bytes = &signed.body_bytes;
        assert_eq!(sign_hybrid(&again).unwrap(), signed);

        // The layer alone.
        let layer = sign_pq_layer(&c.chain_id, &body, &auth, &c.pq, &args.options).unwrap();
        assert_eq!(layer.body_bytes, signed.body_bytes);
        let layers = pqc_layers(&layer.body_bytes).unwrap();
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].algorithm_id, ALGORITHM_ML_DSA_87);
        assert_eq!(layers[0].public_key, None);
    }
}

#[test]
fn proof_of_possession() {
    let c = ctx();
    let p = &c.v["proofOfPossession"];
    assert_eq!(s(p, "account"), c.address);
    let msg = proof_of_possession_message(&c.chain_id, &c.address, &c.pq.public_key).unwrap();
    assert_eq!(String::from_utf8(msg).unwrap(), s(p, "message"));
    let proof = sign_proof_of_possession(&c.chain_id, &c.address, &c.pq, false).unwrap();
    assert_eq!(hex::encode(&proof), s(p, "signature"));
    assert!(verify_proof_of_possession(&c.chain_id, &c.address, &c.pq.public_key, &proof).unwrap());
}

#[test]
fn register_message() {
    let c = ctx();
    let r = &c.v["registerMessage"];
    let msg = build_register_pq_key_message(
        &c.chain_id,
        &c.address,
        &c.pq,
        &c.classical.public_key,
        false,
    )
    .unwrap();
    assert_eq!(msg.type_url, s(r, "typeUrl"));
    assert_eq!(hex::encode(&msg.value), s(r, "value"));
}

#[test]
fn siwq() {
    let c = ctx();
    let q = &c.v["siwq"];
    let fields: SiwqFields = serde_json::from_value(q["fields"].clone()).unwrap();
    let message = create_siwq_message(&fields).unwrap();
    assert_eq!(message, s(q, "message"));

    let parsed = parse_siwq_message(&message).unwrap();
    assert_eq!(create_siwq_message(&parsed).unwrap(), message);
    assert_eq!(
        parsed,
        SiwqFields {
            version: Some("1".into()),
            ..fields
        }
    );

    assert_eq!(
        hex::encode(adr36_sign_bytes(&c.address, message.as_bytes())),
        s(q, "adr36SignBytes")
    );
    assert_eq!(
        hex::encode(siwq_pq_sign_bytes(&message)),
        s(q, "pqSignBytes")
    );

    let sig = sign_siwq(&message, &c.classical, Some(&c.pq), false).unwrap();
    assert_eq!(serde_json::to_value(&sig).unwrap(), q["signature"]);
    let from_vector: SiwqSignature = serde_json::from_value(q["signature"].clone()).unwrap();
    assert_eq!(from_vector, sig);

    let now = parse_timestamp_ms(s(q, "verifyAt")).unwrap();
    let mut args = VerifySiwqArgs::new(
        &message,
        &from_vector,
        "app.example.com",
        "a1b2c3d4e5",
        Some(&c.pq.public_key),
    );
    args.now_ms = Some(now);
    args.chain_id = Some(&c.chain_id);
    let verified = verify_siwq(&args).unwrap();
    assert_eq!(verified, parsed);
}

#[test]
fn message() {
    let c = ctx();
    let m = &c.v["message"];
    assert_eq!(s(m, "signer"), c.address);
    let cases = m["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases {
        let data = h(case, "data");
        if let Some(text) = case["text"].as_str() {
            assert_eq!(text.as_bytes(), data.as_slice());
        }
        assert_eq!(
            hex::encode(adr36_sign_bytes(&c.address, &data)),
            s(case, "adr36SignBytes")
        );
        assert_eq!(
            hex::encode(message_pq_sign_bytes(&c.chain_id, &data).unwrap()),
            s(case, "pqSignBytes")
        );

        let sig = sign_message(
            &c.chain_id,
            &c.address,
            &data,
            &c.classical,
            Some(&c.pq),
            false,
        )
        .unwrap();
        assert_eq!(serde_json::to_value(&sig).unwrap(), case["signature"]);
        let from_vector: MessageSignature =
            serde_json::from_value(case["signature"].clone()).unwrap();
        assert_eq!(from_vector, sig);

        let args = VerifyMessageArgs::new(
            &c.chain_id,
            &c.address,
            &data,
            &from_vector,
            Some(&c.pq.public_key),
        );
        verify_message(&args).unwrap();
    }
}
