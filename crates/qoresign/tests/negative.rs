// SPDX-License-Identifier: Apache-2.0
//
// Negative cases: every check must fail closed with its stable code.

use base64::Engine;
use qoresign::*;

const MNEMONIC: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const CHAIN_ID: &str = "qorechain-diana";
const BODY: &str = "0a83010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e6412630a2a716f723139726c34636d32686d7238616679346b6c6470787a33666b61346a677571306167743637326812";

struct Keys {
    classical: ClassicalKey,
    pq: PqKeyPair,
    address: String,
}

fn keys() -> Keys {
    let classical = derive_classical_key(MNEMONIC, ClassicalKeyType::Secp256k1, 0).unwrap();
    let address = address_from_public_key(&classical.public_key, ClassicalKeyType::Secp256k1)
        .unwrap()
        .bech32;
    let pq = derive_canonical_pq_key(MNEMONIC, &address).unwrap();
    Keys {
        classical,
        pq,
        address,
    }
}

fn field(n: u8, payload: &[u8]) -> Vec<u8> {
    assert!(payload.len() < 128);
    let mut out = vec![(n << 3) | 2, payload.len() as u8];
    out.extend_from_slice(payload);
    out
}

/// A small TxBody: one Any message and a memo.
fn body() -> Vec<u8> {
    let msg = encode_any(&AnyMessage {
        type_url: "/cosmos.bank.v1beta1.MsgSend".into(),
        value: hex::decode(BODY).unwrap(),
    });
    let mut out = field(1, &msg);
    out.extend_from_slice(&field(2, b"memo"));
    out
}

const AUTH: &[u8] = &[0x12, 0x02, 0x10, 0x01];

fn signed(k: &Keys) -> SignedTx {
    let body = body();
    sign_hybrid(&SignHybridArgs::new(
        CHAIN_ID,
        7,
        &body,
        AUTH,
        &k.classical,
        Some(&k.pq),
    ))
    .unwrap()
}

fn verify(k: &Keys, tx: &[u8], chain_id: &str, pq: &[u8]) -> HybridTxResult {
    verify_hybrid_tx(&VerifyHybridTxArgs::new(
        tx,
        chain_id,
        7,
        &k.classical.public_key,
        Some(pq),
    ))
    .unwrap()
}

#[test]
fn hybrid_round_trip() {
    let k = keys();
    let tx = signed(&k);
    let res = verify(&k, &tx.tx_bytes, CHAIN_ID, &k.pq.public_key);
    assert!(res.valid && res.classical);
    assert_eq!(
        res.pq.unwrap().sign_bytes_version,
        Some(SignBytesVersion::V2)
    );
}

#[test]
fn tampered_tx_fails() {
    let k = keys();
    let tx = signed(&k);
    let mut parts = decode_tx_raw(&tx.tx_bytes).unwrap();
    // Change one memo byte: both signatures must break.
    let pos = parts
        .body_bytes
        .windows(4)
        .position(|w| w == b"memo")
        .unwrap();
    parts.body_bytes[pos] = b'M';
    let res = verify(&k, &encode_tx_raw(&parts), CHAIN_ID, &k.pq.public_key);
    assert!(!res.valid);
    assert!(!res.classical);
    assert_eq!(
        res.pq.unwrap().reason,
        Some(PqLayerFailure::InvalidSignature)
    );

    // Tampered classical signature only.
    let mut parts = decode_tx_raw(&tx.tx_bytes).unwrap();
    parts.signatures[0][10] ^= 1;
    let res = verify(&k, &encode_tx_raw(&parts), CHAIN_ID, &k.pq.public_key);
    assert!(!res.valid && !res.classical);
    assert!(res.pq.unwrap().valid);
}

#[test]
fn wrong_chain_id_fails() {
    let k = keys();
    let tx = signed(&k);
    let res = verify(&k, &tx.tx_bytes, "qorechain-vladi", &k.pq.public_key);
    assert!(!res.valid && !res.classical);
    assert_eq!(
        res.pq.unwrap().reason,
        Some(PqLayerFailure::InvalidSignature)
    );
}

#[test]
fn wrong_key_fails() {
    let k = keys();
    let tx = signed(&k);
    let other = derive_hd_pq_key(MNEMONIC, &default_hd_path(0, 118), "").unwrap();
    let res = verify(&k, &tx.tx_bytes, CHAIN_ID, &other.public_key);
    assert!(!res.valid && res.classical);
    assert_eq!(
        res.pq.unwrap().reason,
        Some(PqLayerFailure::InvalidSignature)
    );

    let eth = derive_classical_key(MNEMONIC, ClassicalKeyType::EthSecp256k1, 0).unwrap();
    let res = verify_hybrid_tx(&VerifyHybridTxArgs::new(
        &tx.tx_bytes,
        CHAIN_ID,
        7,
        &eth.public_key,
        None,
    ))
    .unwrap();
    assert!(!res.valid && !res.classical && res.pq.is_none());

    // Malformed keys never panic.
    assert!(!pq_verify(
        &[1, 2, 3],
        b"m",
        &[0; ML_DSA_87_SIGNATURE_LENGTH]
    ));
    assert!(!classical_verify(
        ClassicalKeyType::Secp256k1,
        &[2; 33],
        b"m",
        &[1; 64]
    ));
    assert!(!classical_verify(
        ClassicalKeyType::Secp256k1,
        &k.classical.public_key,
        b"m",
        &[1; 63]
    ));
}

#[test]
fn embedded_key_mismatch() {
    let k = keys();
    let other = derive_hd_pq_key(MNEMONIC, &default_hd_path(0, 118), "").unwrap();
    let opts = SignOptions {
        include_public_key: true,
        ..SignOptions::default()
    };
    let layer = sign_pq_layer(CHAIN_ID, &body(), AUTH, &other, &opts).unwrap();
    let res = verify_pq_layer(
        CHAIN_ID,
        &layer.body_bytes,
        AUTH,
        &k.pq.public_key,
        VerifyVersion::V2,
    )
    .unwrap();
    assert_eq!(res.reason, Some(PqLayerFailure::EmbeddedKeyMismatch));
    let res = verify_pq_layer(
        CHAIN_ID,
        &layer.body_bytes,
        AUTH,
        &other.public_key,
        VerifyVersion::V2,
    )
    .unwrap();
    assert!(res.valid);
    // v2 signature does not verify as v1.
    let res = verify_pq_layer(
        CHAIN_ID,
        &layer.body_bytes,
        AUTH,
        &other.public_key,
        VerifyVersion::V1,
    )
    .unwrap();
    assert_eq!(res.reason, Some(PqLayerFailure::InvalidSignature));
}

#[test]
fn missing_and_duplicated_layer() {
    let k = keys();
    let res =
        verify_pq_layer(CHAIN_ID, &body(), AUTH, &k.pq.public_key, VerifyVersion::V2).unwrap();
    assert_eq!(res.reason, Some(PqLayerFailure::Missing));
    assert!(!res.valid);

    let layer = sign_pq_layer(CHAIN_ID, &body(), AUTH, &k.pq, &SignOptions::default()).unwrap();
    let ext = &pqc_layers(&layer.body_bytes).unwrap()[0];
    let duplicate = AnyMessage {
        type_url: PQC_HYBRID_TYPE_URL.into(),
        value: encode_pqc_hybrid_signature(ext),
    };
    let doubled = append_extension(&layer.body_bytes, &duplicate).unwrap();
    let res = verify_pq_layer(
        CHAIN_ID,
        &doubled,
        AUTH,
        &k.pq.public_key,
        VerifyVersion::V2,
    )
    .unwrap();
    assert_eq!(res.reason, Some(PqLayerFailure::Duplicated));

    // Unsupported algorithm.
    let mut alt = ext.clone();
    alt.algorithm_id = 2;
    let body3 = append_extension(
        &body(),
        &AnyMessage {
            type_url: PQC_HYBRID_TYPE_URL.into(),
            value: encode_pqc_hybrid_signature(&alt),
        },
    )
    .unwrap();
    let res = verify_pq_layer(CHAIN_ID, &body3, AUTH, &k.pq.public_key, VerifyVersion::V2).unwrap();
    assert_eq!(res.reason, Some(PqLayerFailure::UnsupportedAlgorithm));

    // A classical-only transaction has no layer.
    let body = body();
    let mut args = SignHybridArgs::new(CHAIN_ID, 7, &body, AUTH, &k.classical, None);
    args.mode = SigningMode::ClassicalOnly;
    let tx = sign_hybrid(&args).unwrap();
    assert!(tx.pq_signature.is_none());
    let res = verify(&k, &tx.tx_bytes, CHAIN_ID, &k.pq.public_key);
    assert!(res.classical && !res.valid);
    assert_eq!(res.pq.unwrap().reason, Some(PqLayerFailure::Missing));
}

#[test]
fn signing_mode_errors() {
    let k = keys();
    let body = body();
    let mut args = SignHybridArgs::new(CHAIN_ID, 7, &body, AUTH, &k.classical, Some(&k.pq));
    args.mode = SigningMode::PqOnly;
    assert_eq!(sign_hybrid(&args).unwrap_err().code(), "LANE_NOT_AVAILABLE");

    let args = SignHybridArgs::new(CHAIN_ID, 7, &body, AUTH, &k.classical, None);
    assert_eq!(sign_hybrid(&args).unwrap_err().code(), "INVALID_ARGUMENT");

    let args = SignHybridArgs::new("", 7, &body, AUTH, &k.classical, Some(&k.pq));
    assert_eq!(sign_hybrid(&args).unwrap_err().code(), "INVALID_ARGUMENT");

    assert_eq!(
        "v3".parse::<SignBytesVersion>().unwrap_err().code(),
        "SIGN_BYTES_VERSION_UNKNOWN"
    );
    assert_eq!(
        pq_sign(&[0; 10], b"m", false).unwrap_err().code(),
        "BAD_KEY_LENGTH"
    );
    assert_eq!(
        hybrid_sign_bytes(CHAIN_ID, &[0xff], AUTH, SignBytesVersion::V2)
            .unwrap_err()
            .code(),
        "MALFORMED_PROTOBUF"
    );
}

#[test]
fn non_canonical_mnemonic() {
    let k = keys();
    for bad in [
        format!(" {MNEMONIC}"),
        format!("{MNEMONIC} "),
        MNEMONIC.replacen(' ', "  ", 1),
        MNEMONIC.replacen(' ', "\t", 1),
        MNEMONIC.to_uppercase(),
        MNEMONIC.replace("about", "abandon"),
        MNEMONIC.replacen(' ', "\u{a0}", 1),
    ] {
        let err = derive_canonical_pq_key(&bad, &k.address).unwrap_err();
        assert_eq!(err.code(), "INVALID_MNEMONIC", "{bad:?}");
        let err = derive_classical_key(&bad, ClassicalKeyType::Secp256k1, 0).unwrap_err();
        assert_eq!(err.code(), "INVALID_MNEMONIC", "{bad:?}");
        let err = derive_hd_pq_key(&bad, "m/44'/118'/0'/0'/0'", "").unwrap_err();
        assert_eq!(err.code(), "INVALID_MNEMONIC", "{bad:?}");
    }
}

#[test]
fn addresses() {
    let k = keys();
    let a = parse_address(&k.address).unwrap();
    assert_eq!(parse_address(&a.hex.to_lowercase()).unwrap(), a);
    assert_eq!(parse_address(&k.address.to_uppercase()).unwrap(), a);
    for bad in [
        "",
        "qor1",
        "cosmos19rl4cm2hmr8afy4kldpxz3fka4jguq0a5m7df8",
        "0x28Ff5c6d57D8cFD492B6FB42614536eD648E01F",
        "0X28Ff5c6d57D8cFD492B6FB42614536eD648E01Fd",
    ] {
        assert_eq!(
            parse_address(bad).unwrap_err().code(),
            "INVALID_ADDRESS",
            "{bad}"
        );
    }
    let mut flipped = k.address.clone().into_bytes();
    let last = flipped.len() - 1;
    flipped[last] = if flipped[last] == b'h' { b'g' } else { b'h' };
    assert_eq!(
        parse_address(core::str::from_utf8(&flipped).unwrap())
            .unwrap_err()
            .code(),
        "INVALID_ADDRESS"
    );
    assert_eq!(
        address_from_bytes(&[0; 19]).unwrap_err().code(),
        "BAD_KEY_LENGTH"
    );
}

#[test]
fn hd_paths() {
    for (path, code) in [
        ("m/44'/118'/0'/0/0", "HD_NON_HARDENED"),
        ("m/44'/1", "HD_NON_HARDENED"),
        ("44'/118'", "HD_INVALID_PATH"),
        ("m/44'/x'", "HD_INVALID_PATH"),
        ("m/", "HD_INVALID_PATH"),
        ("m/2147483648'", "HD_INVALID_PATH"),
        ("m/44h", "HD_INVALID_PATH"),
    ] {
        assert_eq!(
            derive_hd_pq_key(MNEMONIC, path, "").unwrap_err().code(),
            code,
            "{path}"
        );
    }
    assert!(derive_hd_pq_key(MNEMONIC, "m/2147483647'", "").is_ok());
    assert_eq!(
        derive_hd_pq_key_from_seed(&[0; 15], "m/0'")
            .unwrap_err()
            .code(),
        "INVALID_ARGUMENT"
    );
}

#[test]
fn registration_errors() {
    let k = keys();
    let eth = derive_classical_key(MNEMONIC, ClassicalKeyType::EthSecp256k1, 0).unwrap();
    let err = build_register_pq_key_message(CHAIN_ID, &k.address, &k.pq, &eth.public_key, false)
        .unwrap_err();
    assert_eq!(err.code(), "ADDRESS_MISMATCH");

    let mut degenerate = k.pq.clone();
    degenerate.public_key[32..].fill(0);
    assert!(is_degenerate_pq_public_key(&degenerate.public_key));
    let err = build_register_pq_key_message(
        CHAIN_ID,
        &k.address,
        &degenerate,
        &k.classical.public_key,
        false,
    )
    .unwrap_err();
    assert_eq!(err.code(), "INVALID_ARGUMENT");

    let proof = sign_proof_of_possession(CHAIN_ID, &k.address, &k.pq, true).unwrap();
    assert!(verify_proof_of_possession(CHAIN_ID, &k.address, &k.pq.public_key, &proof).unwrap());
    assert!(
        !verify_proof_of_possession("qorechain-vladi", &k.address, &k.pq.public_key, &proof)
            .unwrap()
    );
    assert_eq!(
        proof_of_possession_message("", &k.address, &k.pq.public_key)
            .unwrap_err()
            .code(),
        "INVALID_ARGUMENT"
    );
}

#[test]
fn hedged_signatures_verify() {
    let k = keys();
    let a = pq_sign(&k.pq.secret_key, b"message", true).unwrap();
    let b = pq_sign(&k.pq.secret_key, b"message", true).unwrap();
    assert_ne!(a, b);
    assert!(pq_verify(&k.pq.public_key, b"message", &a));
    assert!(pq_verify(&k.pq.public_key, b"message", &b));
    assert!(!pq_verify(&k.pq.public_key, b"other", &a));
}

// SIWQ

const NOW: &str = "2026-10-27T10:01:00Z";

fn siwq_fields(address: &str) -> SiwqFields {
    SiwqFields {
        scheme: Some("https".into()),
        domain: "app.example.com".into(),
        address: address.into(),
        statement: Some("Sign in to the example app.".into()),
        uri: "https://app.example.com/login".into(),
        chain_id: CHAIN_ID.into(),
        nonce: "a1b2c3d4e5".into(),
        issued_at: "2026-10-27T10:00:00Z".into(),
        expiration_time: Some("2026-10-27T10:10:00Z".into()),
        ..SiwqFields::default()
    }
}

fn siwq_verify(
    message: &str,
    sig: &SiwqSignature,
    pq: Option<&[u8]>,
    edit: impl FnOnce(&mut VerifySiwqArgs<'_>),
) -> Result<SiwqFields> {
    let mut args = VerifySiwqArgs::new(message, sig, "app.example.com", "a1b2c3d4e5", pq);
    args.now_ms = parse_timestamp_ms(NOW);
    edit(&mut args);
    verify_siwq(&args)
}

#[test]
fn siwq_checks() {
    let k = keys();
    let msg = create_siwq_message(&siwq_fields(&k.address)).unwrap();
    let sig = sign_siwq(&msg, &k.classical, Some(&k.pq), false).unwrap();
    let pq = Some(k.pq.public_key.as_slice());
    assert!(siwq_verify(&msg, &sig, pq, |_| {}).is_ok());

    let code = |r: Result<SiwqFields>| r.unwrap_err().code();
    assert_eq!(
        code(siwq_verify(&msg, &sig, pq, |a| a.domain = "evil.example.com")),
        "SIWQ_DOMAIN_MISMATCH"
    );
    assert_eq!(
        code(siwq_verify(&msg, &sig, pq, |a| a.nonce = "zzzzzzzzzz")),
        "SIWQ_NONCE_MISMATCH"
    );
    assert_eq!(
        code(siwq_verify(&msg, &sig, pq, |a| a.chain_id = Some("qorechain-vladi"))),
        "SIWQ_CHAIN_MISMATCH"
    );
    assert_eq!(
        code(siwq_verify(&msg, &sig, pq, |a| a.now_ms =
            parse_timestamp_ms("2026-10-27T10:10:00Z"))),
        "SIWQ_EXPIRED"
    );
    assert_eq!(
        code(siwq_verify(&msg, &sig, pq, |a| a.now_ms =
            parse_timestamp_ms("2026-10-27T09:58:59Z"))),
        "SIWQ_NOT_YET_VALID"
    );
    // Within the default 60 s skew.
    assert!(siwq_verify(&msg, &sig, pq, |a| a.now_ms =
        parse_timestamp_ms("2026-10-27T09:59:00Z"))
    .is_ok());
    assert_eq!(
        code(siwq_verify(&msg, &sig, pq, |a| {
            a.now_ms = parse_timestamp_ms("2026-10-27T09:59:00Z");
            a.clock_skew_seconds = 0;
        })),
        "SIWQ_NOT_YET_VALID"
    );

    // PQ requirement.
    assert_eq!(
        code(siwq_verify(&msg, &sig, None, |_| {})),
        "KEY_NOT_REGISTERED"
    );
    let classical_only = sign_siwq(&msg, &k.classical, None, false).unwrap();
    assert_eq!(classical_only.signature_type, SiwqSignatureType::Secp256k1);
    assert_eq!(
        code(siwq_verify(&msg, &classical_only, pq, |_| {})),
        "PQ_LAYER_MISSING"
    );
    assert!(siwq_verify(&msg, &classical_only, None, |a| a.require_pq = false).is_ok());

    // Wrong PQ key and tampered signatures.
    let other = derive_hd_pq_key(MNEMONIC, &default_hd_path(0, 118), "").unwrap();
    assert_eq!(
        code(siwq_verify(&msg, &sig, Some(&other.public_key), |_| {})),
        "PQ_SIGNATURE_INVALID"
    );
    let mut bad = sig.clone();
    bad.pq.as_mut().unwrap().signature = "!!".into();
    assert_eq!(
        code(siwq_verify(&msg, &bad, pq, |_| {})),
        "PQ_SIGNATURE_INVALID"
    );
    let mut bad = sig.clone();
    bad.pq.as_mut().unwrap().algorithm_id = 2;
    assert_eq!(
        code(siwq_verify(&msg, &bad, pq, |_| {})),
        "UNSUPPORTED_ALGORITHM"
    );
    let mut bad = sig.clone();
    let other_sig = classical_sign(
        ClassicalKeyType::Secp256k1,
        &k.classical.private_key,
        b"other",
    )
    .unwrap();
    bad.classical.signature = base64::engine::general_purpose::STANDARD.encode(other_sig);
    assert_eq!(
        code(siwq_verify(&msg, &bad, pq, |_| {})),
        "CLASSICAL_SIGNATURE_INVALID"
    );

    // A signature over a different message.
    let msg2 = msg.replace("example app", "other app");
    assert_eq!(
        code(siwq_verify(&msg2, &sig, pq, |_| {})),
        "CLASSICAL_SIGNATURE_INVALID"
    );
}

#[test]
fn siwq_address_mismatch() {
    let k = keys();
    let eth = derive_classical_key(MNEMONIC, ClassicalKeyType::EthSecp256k1, 0).unwrap();
    let msg = create_siwq_message(&siwq_fields(&k.address)).unwrap();
    assert_eq!(
        sign_siwq(&msg, &eth, Some(&k.pq), false)
            .unwrap_err()
            .code(),
        "ADDRESS_MISMATCH"
    );

    // A valid signature by another account's key.
    let eth_addr = address_from_public_key(&eth.public_key, ClassicalKeyType::EthSecp256k1)
        .unwrap()
        .bech32;
    let eth_msg = create_siwq_message(&siwq_fields(&eth_addr)).unwrap();
    let eth_sig = sign_siwq(&eth_msg, &eth, None, false).unwrap();
    let mut swapped = sign_siwq(&msg, &k.classical, Some(&k.pq), false).unwrap();
    swapped.classical = eth_sig.classical.clone();
    let err = siwq_verify(&msg, &swapped, Some(&k.pq.public_key), |_| {}).unwrap_err();
    assert_eq!(err.code(), "ADDRESS_MISMATCH");

    // Right key, wrong declared key type.
    let mut wrong_type = sign_siwq(&msg, &k.classical, Some(&k.pq), false).unwrap();
    wrong_type.classical.key_type = ClassicalKeyType::EthSecp256k1;
    let err = siwq_verify(&msg, &wrong_type, Some(&k.pq.public_key), |_| {}).unwrap_err();
    assert_eq!(err.code(), "ADDRESS_MISMATCH");

    // eth_secp256k1 sign-in verifies (keccak digest).
    let eth_pq = derive_canonical_pq_key(MNEMONIC, &eth_addr).unwrap();
    let eth_sig = sign_siwq(&eth_msg, &eth, Some(&eth_pq), false).unwrap();
    assert!(siwq_verify(&eth_msg, &eth_sig, Some(&eth_pq.public_key), |_| {}).is_ok());
}

#[test]
fn siwq_canonical_text() {
    let k = keys();
    let msg = create_siwq_message(&siwq_fields(&k.address)).unwrap();
    for bad in [
        format!("{msg}\n"),
        msg.replace("Version: 1", "Version: 2"),
        msg.replace("Nonce: a1b2c3d4e5", "Nonce: short"),
        msg.replace("Issued At: 2026-10-27T10:00:00Z", "Issued At: yesterday"),
        msg.replace("URI: ", "URI:  "),
        msg.replace(" wants you", " wants  you"),
        msg.replacen("\n\n", "\n", 1),
        msg.replace("Expiration Time", "Expiry"),
    ] {
        assert_eq!(
            parse_siwq_message(&bad).unwrap_err().code(),
            "SIWQ_MALFORMED",
            "{bad:?}"
        );
    }
    let bad_addr = msg.replace(&k.address, "qor1notanaddress");
    assert_eq!(
        parse_siwq_message(&bad_addr).unwrap_err().code(),
        "INVALID_ADDRESS"
    );

    let mut f = siwq_fields(&k.address);
    f.domain = "app.example.com/x".into();
    assert_eq!(
        create_siwq_message(&f).unwrap_err().code(),
        "SIWQ_MALFORMED"
    );
    let mut f = siwq_fields(&k.address);
    f.address = parse_address(&k.address).unwrap().hex;
    assert_eq!(
        create_siwq_message(&f).unwrap_err().code(),
        "SIWQ_MALFORMED"
    );

    // Minimal message round-trips.
    let f = SiwqFields {
        domain: "localhost:3000".into(),
        address: k.address.clone(),
        uri: "urn:qoresign:test".into(),
        chain_id: CHAIN_ID.into(),
        nonce: "ABCDEFGH".into(),
        issued_at: "2026-10-27T10:00:00.123+02:00".into(),
        not_before: Some("2026-10-27T08:00:00Z".into()),
        request_id: Some("r-1".into()),
        resources: Some(vec![]),
        ..SiwqFields::default()
    };
    let text = create_siwq_message(&f).unwrap();
    let parsed = parse_siwq_message(&text).unwrap();
    assert_eq!(create_siwq_message(&parsed).unwrap(), text);
    assert_eq!(parsed.statement, None);
    assert_eq!(parsed.scheme, None);
}

#[test]
fn siwq_impossible_dates_fail_closed() {
    let k = keys();
    let mut f = siwq_fields(&k.address);
    f.expiration_time = Some("2026-02-30T10:00:00Z".into());
    let msg = create_siwq_message(&f).unwrap();
    let sig = sign_siwq(&msg, &k.classical, Some(&k.pq), false).unwrap();
    let err = siwq_verify(&msg, &sig, Some(&k.pq.public_key), |_| {}).unwrap_err();
    assert_eq!(err.code(), "SIWQ_EXPIRED");
}

#[test]
fn timestamps() {
    assert_eq!(parse_timestamp_ms("1970-01-01T00:00:00Z"), Some(0));
    assert_eq!(parse_timestamp_ms("1970-01-01T00:00:01.5Z"), Some(1500));
    assert_eq!(parse_timestamp_ms("1970-01-01T00:00:00.123456Z"), Some(123));
    assert_eq!(parse_timestamp_ms("1970-01-01T01:00:00+01:00"), Some(0));
    assert_eq!(parse_timestamp_ms("1969-12-31T23:00:00-01:00"), Some(0));
    assert_eq!(
        parse_timestamp_ms("2026-10-27T10:00:00Z"),
        Some(1_793_095_200_000)
    );
    assert_eq!(
        parse_timestamp_ms("2024-02-29T00:00:00Z"),
        Some(1_709_164_800_000)
    );
    assert_eq!(parse_timestamp_ms("1970-01-01T24:00:00Z"), Some(86_400_000));
    for bad in [
        "2023-02-29T00:00:00Z",
        "2026-13-01T00:00:00Z",
        "2026-10-27T10:60:00Z",
        "2026-10-27T10:00:00+24:00",
        "2026-10-27T10:00:00+01:60",
        "2026-10-27T10:00:00",
        "2026-10-27 10:00:00Z",
        "2026-10-27T10:00:00.Z",
    ] {
        assert_eq!(parse_timestamp_ms(bad), None, "{bad}");
    }
}

#[test]
fn lanes() {
    assert!(assert_hybrid_lane(Lane::Native).is_ok());
    assert_eq!(
        assert_hybrid_lane(Lane::Evm).unwrap_err().code(),
        "LANE_NOT_AVAILABLE"
    );
    assert_eq!(
        assert_hybrid_lane(Lane::Svm).unwrap_err().code(),
        "LANE_NOT_AVAILABLE"
    );
    for (lane, support) in LANE_SUPPORT {
        assert_eq!(lane.support(), support);
    }

    let d = decide_lane(&LaneRequest {
        is_qor_transfer: true,
        ..LaneRequest::default()
    });
    assert_eq!(
        (d.lane, d.leaves_hybrid_default, d.reason),
        (Lane::Native, false, LaneReason::DefaultNative)
    );
    let d = decide_lane(&LaneRequest {
        is_qor_transfer: true,
        explicit_lane: Some(Lane::Evm),
        dapp_required_lane: Some(Lane::Svm),
    });
    assert_eq!(
        (d.lane, d.leaves_hybrid_default, d.reason),
        (Lane::Svm, true, LaneReason::DappRequired)
    );
    let d = decide_lane(&LaneRequest {
        is_qor_transfer: true,
        explicit_lane: Some(Lane::Evm),
        dapp_required_lane: Some(Lane::Native),
    });
    assert_eq!((d.lane, d.reason), (Lane::Evm, LaneReason::UserOverride));

    let state = |lane, on, signed, urls: Option<&[&str]>| {
        evaluate_layer_state(&LayerStateInput {
            lane,
            on_qore_chain: on,
            signed_with_pq_layer: signed,
            committed_extension_type_urls: urls,
        })
    };
    assert_eq!(state(Lane::Evm, true, true, None), LayerState::Classical);
    assert_eq!(
        state(Lane::Native, false, true, None),
        LayerState::Classical
    );
    assert_eq!(
        state(Lane::Native, true, false, None),
        LayerState::Downgraded
    );
    assert_eq!(state(Lane::Native, true, true, None), LayerState::Pending);
    assert_eq!(
        state(Lane::Native, true, true, Some(&[PQC_HYBRID_TYPE_URL])),
        LayerState::Protected
    );
    assert_eq!(
        state(Lane::Native, true, true, Some(&["/other"])),
        LayerState::Downgraded
    );
}

#[test]
fn proto_edits() {
    let b = body();
    assert_eq!(strip_extension(&b, PQC_HYBRID_TYPE_URL).unwrap(), b);
    // Non-critical extension (field 2047) stays after the inserted option.
    let mut with_nc = b.clone();
    with_nc.extend_from_slice(&[0xfa, 0x7f, 0x00]);
    let any = AnyMessage {
        type_url: "/x".into(),
        value: vec![1],
    };
    let out = append_extension(&with_nc, &any).unwrap();
    assert!(out.ends_with(&[0xfa, 0x7f, 0x00]));
    assert_eq!(strip_extension(&out, "/x").unwrap(), with_nc);
    assert_eq!(decode_any(&encode_any(&any)).unwrap(), any);
    for bad in [
        &[0x0a, 0x05, 0x01][..],
        &[0x00, 0x01],
        &[0x0b],
        &[0x80],
        &[0x09, 0, 0],
    ] {
        assert_eq!(
            strip_extension(bad, PQC_HYBRID_TYPE_URL)
                .unwrap_err()
                .code(),
            "MALFORMED_PROTOBUF",
            "{bad:?}"
        );
    }
    let tx = TxRawParts {
        body_bytes: vec![1],
        auth_info_bytes: vec![2],
        signatures: vec![vec![], vec![3]],
    };
    assert_eq!(decode_tx_raw(&encode_tx_raw(&tx)).unwrap(), tx);
}

#[test]
fn error_codes() {
    assert_eq!(Error::SiwqExpired("x".into()).code(), "SIWQ_EXPIRED");
    assert_eq!(Error::KeyMismatch("x".into()).code(), "KEY_MISMATCH");
    assert_eq!(
        Error::NetworkUnavailable("x".into()).code(),
        "NETWORK_UNAVAILABLE"
    );
    assert_eq!(Error::SimulationFailed("m".into()).message(), "m");
    assert_eq!(Error::InvalidArgument("m".into()).to_string(), "m");
}
