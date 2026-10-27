// SPDX-License-Identifier: Apache-2.0
//
// The FFI surface against vectors/qoresign-v1.json (the core crate has the
// full vector suite; this checks the conversions).

use qoresign_ffi::*;
use serde_json::Value;

fn vectors() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vectors/qoresign-v1.json"
    );
    serde_json::from_str(&std::fs::read_to_string(path).expect("read vectors")).expect("parse")
}

fn s<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key].as_str().unwrap_or_else(|| panic!("missing {key}"))
}

fn h(v: &Value, key: &str) -> Vec<u8> {
    hex::decode(s(v, key)).expect("hex")
}

fn code<T: std::fmt::Debug>(r: Result<T, QoreSignError>) -> String {
    match r.unwrap_err() {
        QoreSignError::Failure { code, .. } => code,
    }
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
    let classical = derive_classical_key(
        mnemonic.clone(),
        ClassicalKeyType::Secp256k1,
        0,
        None,
        "".into(),
    )
    .unwrap();
    let address =
        address_from_public_key(classical.public_key.clone(), ClassicalKeyType::Secp256k1)
            .unwrap()
            .bech32;
    let pq = derive_canonical_pq_key(mnemonic.clone(), address.clone()).unwrap();
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
fn accounts_and_keys() {
    let c = ctx();
    for (name, kt) in [
        ("secp256k1", ClassicalKeyType::Secp256k1),
        ("eth_secp256k1", ClassicalKeyType::EthSecp256k1),
    ] {
        let a = &c.v["accounts"][name];
        let by_index = derive_classical_key(c.mnemonic.clone(), kt, 0, None, "".into()).unwrap();
        let by_path = derive_classical_key(
            c.mnemonic.clone(),
            kt,
            9,
            Some(s(a, "path").into()),
            "".into(),
        )
        .unwrap();
        assert_eq!(by_index, by_path);
        assert_eq!(default_classical_path(kt, 0), s(a, "path"));
        assert_eq!(hex::encode(&by_index.private_key), s(a, "privateKey"));
        assert_eq!(hex::encode(&by_index.public_key), s(a, "publicKey"));
        let addr = address_from_public_key(by_index.public_key.clone(), kt).unwrap();
        assert_eq!(addr.bech32, s(a, "address"));
        assert_eq!(addr.hex, s(a, "hex"));
        assert_eq!(parse_address(s(a, "hex").into()).unwrap(), addr);
        assert_eq!(
            classical_key_type_for(by_index.public_key.clone(), addr.bech32.clone()).unwrap(),
            Some(kt)
        );
        assert_eq!(
            classical_key_from_private(by_index.private_key.clone(), kt).unwrap(),
            by_index
        );
    }
    for item in c.v["canonical"].as_array().unwrap() {
        let k = derive_canonical_pq_key(c.mnemonic.clone(), s(item, "address").into()).unwrap();
        assert_eq!(hex::encode(&k.public_key), s(item, "publicKey"));
    }
    for item in c.v["hd"].as_array().unwrap() {
        let k = derive_hd_pq_key(c.mnemonic.clone(), s(item, "path").into(), "".into()).unwrap();
        assert_eq!(hex::encode(&k.public_key), s(item, "publicKey"));
    }
    assert_eq!(default_hd_path(0, 118), "m/44'/118'/0'/0'/0'");
    let codes: Vec<String> = c.v["hdRejected"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            code(derive_hd_pq_key(
                c.mnemonic.clone(),
                p.as_str().unwrap().into(),
                "".into(),
            ))
        })
        .collect();
    assert_eq!(
        codes,
        ["HD_NON_HARDENED", "HD_INVALID_PATH", "HD_INVALID_PATH"]
    );
    assert_eq!(
        code(derive_classical_key(
            "abandon  abandon".into(),
            ClassicalKeyType::Secp256k1,
            0,
            None,
            "".into()
        )),
        "INVALID_MNEMONIC"
    );
    assert_eq!(code(pq_key_from_seed(vec![0; 31])), "BAD_KEY_LENGTH");
}

#[test]
fn hybrid_tx() {
    let c = ctx();
    let t = &c.v["hybridTx"];
    let account_number = t["accountNumber"].as_u64().unwrap();
    let (body, auth) = (h(t, "bodyBytes"), h(t, "authInfoBytes"));
    for case in t["cases"].as_array().unwrap() {
        let (sv, vv) = match s(case, "signBytesVersion") {
            "v1" => (SignBytesVersion::V1, VerifyVersion::V1),
            _ => (SignBytesVersion::V2, VerifyVersion::V2),
        };
        let sign_bytes =
            hybrid_sign_bytes(c.chain_id.clone(), body.clone(), auth.clone(), Some(sv)).unwrap();
        assert_eq!(hex::encode(sign_bytes), s(case, "signBytes"));
        let options = SignOptions {
            sign_bytes_version: Some(sv),
            include_public_key: false,
            hedged: false,
        };
        let signed = sign_hybrid(
            c.chain_id.clone(),
            account_number,
            body.clone(),
            auth.clone(),
            c.classical.clone(),
            Some(c.pq.clone()),
            None,
            Some(options),
        )
        .unwrap();
        assert_eq!(
            hex::encode(signed.pq_signature.as_ref().unwrap()),
            s(case, "pqSignature")
        );
        assert_eq!(hex::encode(&signed.body_bytes), s(case, "signedBodyBytes"));
        assert_eq!(
            hex::encode(&signed.classical_signature),
            s(case, "classicalSignature")
        );
        assert_eq!(hex::encode(&signed.tx_bytes), s(case, "txBytes"));
        let layer = sign_pq_layer(
            c.chain_id.clone(),
            body.clone(),
            auth.clone(),
            c.pq.clone(),
            Some(options),
        )
        .unwrap();
        assert_eq!(layer.body_bytes, signed.body_bytes);
        let r = verify_hybrid_tx(
            signed.tx_bytes.clone(),
            c.chain_id.clone(),
            account_number,
            c.classical.public_key.clone(),
            Some(c.pq.public_key.clone()),
            None,
            Some(vv),
        )
        .unwrap();
        assert!(r.valid && r.classical);
        assert_eq!(r.pq.unwrap().sign_bytes_version, Some(sv));
        let wrong = verify_hybrid_tx(
            signed.tx_bytes.clone(),
            c.chain_id.clone(),
            account_number + 1,
            c.classical.public_key.clone(),
            Some(c.pq.public_key.clone()),
            None,
            Some(VerifyVersion::Either),
        )
        .unwrap();
        assert!(!wrong.valid && !wrong.classical);
    }
    let missing = verify_pq_layer(
        c.chain_id.clone(),
        body.clone(),
        auth.clone(),
        c.pq.public_key.clone(),
        None,
    )
    .unwrap();
    assert_eq!(missing.reason, Some(PqLayerFailure::Missing));
    assert_eq!(
        code(sign_hybrid(
            c.chain_id.clone(),
            7,
            body.clone(),
            auth.clone(),
            c.classical.clone(),
            None,
            None,
            None
        )),
        "INVALID_ARGUMENT"
    );
    assert_eq!(
        code(sign_hybrid(
            c.chain_id,
            7,
            body,
            auth,
            c.classical,
            None,
            Some(SigningMode::PqOnly),
            None
        )),
        "LANE_NOT_AVAILABLE"
    );
}

#[test]
fn registration() {
    let c = ctx();
    let p = &c.v["proofOfPossession"];
    let msg = proof_of_possession_message(
        c.chain_id.clone(),
        c.address.clone(),
        c.pq.public_key.clone(),
    )
    .unwrap();
    assert_eq!(String::from_utf8(msg).unwrap(), s(p, "message"));
    let proof =
        sign_proof_of_possession(c.chain_id.clone(), c.address.clone(), c.pq.clone(), false)
            .unwrap();
    assert_eq!(hex::encode(&proof), s(p, "signature"));
    assert!(verify_proof_of_possession(
        c.chain_id.clone(),
        c.address.clone(),
        c.pq.public_key.clone(),
        proof
    )
    .unwrap());
    let r = &c.v["registerMessage"];
    let any = build_register_pq_key_message(
        c.chain_id.clone(),
        c.address.clone(),
        c.pq.clone(),
        c.classical.public_key.clone(),
        false,
    )
    .unwrap();
    assert_eq!(any.type_url, s(r, "typeUrl"));
    assert_eq!(hex::encode(any.value), s(r, "value"));
    assert!(!is_degenerate_pq_public_key(c.pq.public_key.clone()));
    let mut degenerate = c.pq.public_key.clone();
    degenerate[32..].fill(0);
    assert!(is_degenerate_pq_public_key(degenerate));
}

#[test]
fn siwq() {
    let c = ctx();
    let q = &c.v["siwq"];
    let f = &q["fields"];
    let fields = SiwqFields {
        domain: s(f, "domain").into(),
        address: s(f, "address").into(),
        uri: s(f, "uri").into(),
        chain_id: s(f, "chainId").into(),
        nonce: s(f, "nonce").into(),
        issued_at: s(f, "issuedAt").into(),
        scheme: Some(s(f, "scheme").into()),
        statement: Some(s(f, "statement").into()),
        version: None,
        expiration_time: Some(s(f, "expirationTime").into()),
        not_before: None,
        request_id: None,
        resources: Some(
            f["resources"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| r.as_str().unwrap().to_owned())
                .collect(),
        ),
    };
    let message = create_siwq_message(fields.clone()).unwrap();
    assert_eq!(message, s(q, "message"));
    let parsed = parse_siwq_message(message.clone()).unwrap();
    assert_eq!(parsed.version.as_deref(), Some("1"));
    assert_eq!(
        hex::encode(adr36_sign_bytes(
            c.address.clone(),
            message.clone().into_bytes()
        )),
        s(q, "adr36SignBytes")
    );
    assert_eq!(
        hex::encode(siwq_pq_sign_bytes(message.clone())),
        s(q, "pqSignBytes")
    );

    let sig = sign_siwq(
        message.clone(),
        c.classical.clone(),
        Some(c.pq.clone()),
        false,
    )
    .unwrap();
    let json: Value = serde_json::from_str(&siwq_signature_to_json(sig.clone()).unwrap()).unwrap();
    assert_eq!(json, q["signature"]);
    let from_vector = siwq_signature_from_json(q["signature"].to_string()).unwrap();
    assert_eq!(from_vector, sig);

    // 2026-10-27T10:01:00Z
    let now = 1_793_095_260_000;
    let verified = verify_siwq(
        message.clone(),
        from_vector.clone(),
        "app.example.com".into(),
        "a1b2c3d4e5".into(),
        Some(c.pq.public_key.clone()),
        Some(c.chain_id.clone()),
        true,
        Some(now),
        60,
    )
    .unwrap();
    assert_eq!(verified, parsed);
    let verify = |domain: &str, nonce: &str, now_ms: i64| {
        verify_siwq(
            message.clone(),
            from_vector.clone(),
            domain.into(),
            nonce.into(),
            Some(c.pq.public_key.clone()),
            None,
            true,
            Some(now_ms),
            60,
        )
    };
    assert_eq!(
        code(verify("evil.example.com", "a1b2c3d4e5", now)),
        "SIWQ_DOMAIN_MISMATCH"
    );
    assert_eq!(
        code(verify("app.example.com", "zzzzzzzzzz", now)),
        "SIWQ_NONCE_MISMATCH"
    );
    assert_eq!(
        code(verify("app.example.com", "a1b2c3d4e5", now + 3_600_000)),
        "SIWQ_EXPIRED"
    );
}

#[test]
fn lanes() {
    assert_eq!(lane_support(Lane::Native), LaneSupport::Hybrid);
    assert_eq!(lane_support(Lane::Evm), LaneSupport::QuantumReady);
    assert_eq!(lane_support(Lane::Svm), LaneSupport::Unavailable);
    assert!(assert_hybrid_lane(Lane::Native).is_ok());
    assert_eq!(code(assert_hybrid_lane(Lane::Svm)), "LANE_NOT_AVAILABLE");
    let d = decide_lane(LaneRequest {
        is_qor_transfer: true,
        explicit_lane: None,
        dapp_required_lane: Some(Lane::Evm),
    });
    assert_eq!(
        (d.lane, d.leaves_hybrid_default, d.reason),
        (Lane::Evm, true, LaneReason::DappRequired)
    );
    let state = |urls: Option<Vec<String>>| {
        evaluate_layer_state(LayerStateInput {
            lane: Lane::Native,
            on_qore_chain: true,
            signed_with_pq_layer: true,
            committed_extension_type_urls: urls,
        })
    };
    assert_eq!(state(None), LayerState::Pending);
    assert_eq!(
        state(Some(vec!["/qorechain.pqc.v1.PQCHybridSignature".into()])),
        LayerState::Protected
    );
    assert_eq!(state(Some(vec![])), LayerState::Downgraded);
}
