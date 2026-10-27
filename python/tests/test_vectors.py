# SPDX-License-Identifier: Apache-2.0
#
# Checks the Python package against vectors/qoresign-v1.json.

import json
import re
from datetime import datetime
from pathlib import Path

import pytest

import qoresign as qs

PYTHON_DIR = Path(__file__).resolve().parents[1]
VECTORS = PYTHON_DIR.parent / "vectors" / "qoresign-v1.json"


def iso_ms(value):
    return int(datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp() * 1000)


def error_code(fn, *args, **kwargs):
    try:
        fn(*args, **kwargs)
    except qs.QoreSignError as e:
        return e.code
    return None


@pytest.fixture(scope="module")
def v():
    data = json.loads(VECTORS.read_text(encoding="utf-8"))
    assert data["format"] == "qoresign-vectors-v1"
    return data


@pytest.fixture(scope="module")
def ctx(v):
    mnemonic = v["mnemonic"]
    classical = qs.derive_classical_key(mnemonic, qs.ClassicalKeyType.SECP256K1)
    address = qs.address_from_public_key(classical.public_key, qs.ClassicalKeyType.SECP256K1).bech32
    pq = qs.derive_canonical_pq_key(mnemonic, address)
    return {
        "mnemonic": mnemonic,
        "chain_id": v["chainId"],
        "classical": classical,
        "address": address,
        "pq": pq,
    }


def test_package():
    pyproject = (PYTHON_DIR / "pyproject.toml").read_text(encoding="utf-8")
    assert qs.__version__ == re.search(r'^version = "([^"]+)"', pyproject, re.M).group(1)
    for name in qs.__all__:
        assert hasattr(qs, name), name
    assert qs.ALGORITHM_ML_DSA_87 == 1


def test_accounts(v, ctx):
    mnemonic = ctx["mnemonic"]
    for name, key_type in [
        ("secp256k1", qs.ClassicalKeyType.SECP256K1),
        ("eth_secp256k1", qs.ClassicalKeyType.ETH_SECP256K1),
    ]:
        a = v["accounts"][name]
        assert qs.default_classical_path(key_type) == a["path"]
        key = qs.derive_classical_key(mnemonic, key_type)
        assert qs.derive_classical_key(mnemonic, key_type, path=a["path"]) == key
        assert key.key_type == key_type
        assert key.private_key.hex() == a["privateKey"]
        assert key.public_key.hex() == a["publicKey"]
        addr = qs.address_from_public_key(key.public_key, key_type)
        assert addr.bech32 == a["address"]
        assert addr.hex == a["hex"]
        assert len(addr.bytes) == 20
        assert qs.parse_address(a["hex"]) == addr
        assert qs.parse_address(a["address"]) == addr
        assert qs.address_from_bytes(addr.bytes) == addr
        assert qs.classical_key_type_for(key.public_key, addr.bech32) == key_type
        assert qs.classical_key_from_private(key.private_key, key_type) == key
    assert ctx["address"] == v["accounts"]["secp256k1"]["address"]
    assert ctx["address"].startswith(qs.ACCOUNT_PREFIX + "1")


def test_pq_keys(v, ctx):
    mnemonic = ctx["mnemonic"]
    for item in v["canonical"]:
        key = qs.derive_canonical_pq_key(mnemonic, item["address"])
        assert key.algorithm_id == qs.ALGORITHM_ML_DSA_87
        assert len(key.public_key) == qs.ML_DSA_87_PUBLIC_KEY_LENGTH
        assert len(key.secret_key) == qs.ML_DSA_87_SECRET_KEY_LENGTH
        assert key.public_key.hex() == item["publicKey"]
    assert ctx["pq"].public_key.hex() == v["canonical"][0]["publicKey"]

    hd = v["hd"]
    for item in hd:
        key = qs.derive_hd_pq_key(mnemonic, item["path"])
        assert key.public_key.hex() == item["publicKey"], item["path"]
    assert qs.default_hd_path() == hd[0]["path"]
    assert qs.default_hd_path(index=1) == hd[1]["path"]
    assert qs.default_hd_path(coin_type=60) == hd[2]["path"]

    codes = [error_code(qs.derive_hd_pq_key, mnemonic, path) for path in v["hdRejected"]]
    assert codes == ["HD_NON_HARDENED", "HD_INVALID_PATH", "HD_INVALID_PATH"]


def test_hybrid_tx(v, ctx):
    t = v["hybridTx"]
    chain_id, classical, pq = ctx["chain_id"], ctx["classical"], ctx["pq"]
    account_number = t["accountNumber"]
    body = bytes.fromhex(t["bodyBytes"])
    auth = bytes.fromhex(t["authInfoBytes"])
    assert len(t["cases"]) == 2
    for c in t["cases"]:
        version = qs.SignBytesVersion.V1 if c["signBytesVersion"] == "v1" else qs.SignBytesVersion.V2
        sign_bytes = qs.hybrid_sign_bytes(chain_id, body, auth, version=version)
        assert sign_bytes.hex() == c["signBytes"]

        options = qs.SignOptions(sign_bytes_version=version)
        signed = qs.sign_hybrid(chain_id, account_number, body, auth, classical, pq_key=pq, options=options)
        assert len(signed.pq_signature) == qs.ML_DSA_87_SIGNATURE_LENGTH
        assert signed.pq_signature.hex() == c["pqSignature"]
        assert signed.body_bytes.hex() == c["signedBodyBytes"]
        assert signed.classical_signature.hex() == c["classicalSignature"]
        assert signed.tx_bytes.hex() == c["txBytes"]
        assert signed.auth_info_bytes == auth

        layer = qs.sign_pq_layer(chain_id, body, auth, pq, options=options)
        assert layer.body_bytes == signed.body_bytes
        assert layer.pq_signature == signed.pq_signature

        result = qs.verify_hybrid_tx(
            bytes.fromhex(c["txBytes"]),
            chain_id,
            account_number,
            classical.public_key,
            pq_public_key=pq.public_key,
            version=qs.VerifyVersion.EITHER,
        )
        assert result.valid
        assert result.classical
        assert result.pq.valid
        assert result.pq.sign_bytes_version == version

        layer_result = qs.verify_pq_layer(
            chain_id, signed.body_bytes, auth, pq.public_key, version=qs.VerifyVersion.EITHER
        )
        assert layer_result.valid
        assert layer_result.sign_bytes_version == version


def test_hybrid_tx_negative(v, ctx):
    t = v["hybridTx"]
    chain_id, classical, pq = ctx["chain_id"], ctx["classical"], ctx["pq"]
    account_number = t["accountNumber"]
    body = bytes.fromhex(t["bodyBytes"])
    auth = bytes.fromhex(t["authInfoBytes"])
    tx_bytes = bytes.fromhex(t["cases"][0]["txBytes"])

    # Wrong account number: the classical signature fails.
    wrong_account = qs.verify_hybrid_tx(
        tx_bytes,
        chain_id,
        account_number + 1,
        classical.public_key,
        pq_public_key=pq.public_key,
        version=qs.VerifyVersion.EITHER,
    )
    assert not wrong_account.valid
    assert not wrong_account.classical

    # Another account's ML-DSA-87 key: the PQ layer fails.
    other = bytes.fromhex(v["canonical"][1]["publicKey"])
    wrong_key = qs.verify_hybrid_tx(tx_bytes, chain_id, account_number, classical.public_key, pq_public_key=other)
    assert not wrong_key.valid
    assert wrong_key.pq.reason == qs.PqLayerFailure.INVALID_SIGNATURE

    # Classical check only when no PQ key is given.
    classical_only = qs.verify_hybrid_tx(tx_bytes, chain_id, account_number, classical.public_key)
    assert classical_only.valid
    assert classical_only.pq is None

    # An unsigned body has no layer.
    missing = qs.verify_pq_layer(chain_id, body, auth, pq.public_key)
    assert not missing.valid
    assert missing.reason == qs.PqLayerFailure.MISSING

    assert error_code(qs.sign_hybrid, chain_id, 7, body, auth, classical) == "INVALID_ARGUMENT"
    assert (
        error_code(qs.sign_hybrid, chain_id, 7, body, auth, classical, pq_key=pq, mode=qs.SigningMode.PQ_ONLY)
        == "LANE_NOT_AVAILABLE"
    )
    assert error_code(qs.derive_classical_key, "abandon  abandon", qs.ClassicalKeyType.SECP256K1) == "INVALID_MNEMONIC"
    assert error_code(qs.parse_address, "cosmos1xyz") == "INVALID_ADDRESS"
    assert error_code(qs.pq_key_from_seed, bytes(31)) == "BAD_KEY_LENGTH"

    # A public key that does not match the private key is refused.
    mismatched = qs.ClassicalKey(
        key_type=classical.key_type, private_key=classical.private_key, public_key=bytes(33)
    )
    assert error_code(qs.sign_hybrid, chain_id, 7, body, auth, mismatched, pq_key=pq) == "INVALID_ARGUMENT"

    with pytest.raises(qs.QoreSignError) as info:
        qs.derive_classical_key("not a phrase", qs.ClassicalKeyType.SECP256K1)
    assert isinstance(info.value, qs.QoreSignError.Failure)
    assert info.value.code == "INVALID_MNEMONIC"
    assert info.value.detail


def test_registration(v, ctx):
    chain_id, classical, pq, address = ctx["chain_id"], ctx["classical"], ctx["pq"], ctx["address"]
    p = v["proofOfPossession"]
    assert p["account"] == address
    message = qs.proof_of_possession_message(chain_id, address, pq.public_key)
    assert message.decode("utf-8") == p["message"]
    proof = qs.sign_proof_of_possession(chain_id, address, pq)
    assert proof.hex() == p["signature"]
    assert qs.verify_proof_of_possession(chain_id, address, pq.public_key, proof)
    assert not qs.verify_proof_of_possession("qorechain-vladi", address, pq.public_key, proof)

    r = v["registerMessage"]
    msg = qs.build_register_pq_key_message(chain_id, address, pq, classical.public_key)
    assert msg.type_url == r["typeUrl"]
    assert msg.type_url == qs.MSG_REGISTER_PQC_KEY_V2_TYPE_URL
    assert msg.value.hex() == r["value"]

    assert not qs.is_degenerate_pq_public_key(pq.public_key)
    degenerate = pq.public_key[:32] + bytes(len(pq.public_key) - 32)
    assert qs.is_degenerate_pq_public_key(degenerate)
    eth = qs.derive_classical_key(ctx["mnemonic"], qs.ClassicalKeyType.ETH_SECP256K1)
    assert (
        error_code(qs.build_register_pq_key_message, chain_id, address, pq, eth.public_key) == "ADDRESS_MISMATCH"
    )


def test_siwq(v, ctx):
    chain_id, classical, pq, address = ctx["chain_id"], ctx["classical"], ctx["pq"], ctx["address"]
    q = v["siwq"]
    f = q["fields"]
    fields = qs.SiwqFields(
        domain=f["domain"],
        address=f["address"],
        uri=f["uri"],
        chain_id=f["chainId"],
        nonce=f["nonce"],
        issued_at=f["issuedAt"],
        scheme=f.get("scheme"),
        statement=f.get("statement"),
        expiration_time=f.get("expirationTime"),
        resources=f.get("resources"),
    )
    message = qs.create_siwq_message(fields)
    assert message == q["message"]

    parsed = qs.parse_siwq_message(message)
    assert parsed.version == "1"
    assert qs.create_siwq_message(parsed) == message
    assert qs.adr36_sign_bytes(address, message.encode("utf-8")).hex() == q["adr36SignBytes"]
    assert qs.siwq_pq_sign_bytes(message).hex() == q["pqSignBytes"]

    signature = qs.sign_siwq(message, classical, pq_key=pq)
    assert json.loads(qs.siwq_signature_to_json(signature)) == q["signature"]
    from_vector = qs.siwq_signature_from_json(json.dumps(q["signature"]))
    assert from_vector == signature
    assert from_vector.signature_type == qs.SiwqSignatureType.ML_DSA87_HYBRID

    now_ms = iso_ms(q["verifyAt"])
    verified = qs.verify_siwq(
        message,
        from_vector,
        "app.example.com",
        "a1b2c3d4e5",
        pq_public_key=pq.public_key,
        chain_id=chain_id,
        now_ms=now_ms,
    )
    assert verified == parsed

    def verify_code(signature, pq_public_key, now_ms, domain="app.example.com", nonce="a1b2c3d4e5", **kw):
        return error_code(
            qs.verify_siwq, message, signature, domain, nonce, pq_public_key=pq_public_key, now_ms=now_ms, **kw
        )

    assert verify_code(from_vector, pq.public_key, now_ms, domain="evil.example.com") == "SIWQ_DOMAIN_MISMATCH"
    assert verify_code(from_vector, pq.public_key, now_ms, nonce="zzzzzzzzzz") == "SIWQ_NONCE_MISMATCH"
    assert verify_code(from_vector, pq.public_key, now_ms + 3_600_000) == "SIWQ_EXPIRED"
    assert verify_code(from_vector, None, now_ms) == "KEY_NOT_REGISTERED"
    classical_only = qs.SiwqSignature(signature_type=qs.SiwqSignatureType.SECP256K1, classical=from_vector.classical)
    assert verify_code(classical_only, pq.public_key, now_ms) == "PQ_LAYER_MISSING"
    assert error_code(qs.parse_siwq_message, "hello") == "SIWQ_MALFORMED"
    assert error_code(qs.siwq_signature_from_json, "{}") == "SIWQ_MALFORMED"


def test_message(v, ctx):
    chain_id, classical, pq, address = ctx["chain_id"], ctx["classical"], ctx["pq"], ctx["address"]
    m = v["message"]
    assert m["signer"] == address
    assert len(m["cases"]) == 2
    for c in m["cases"]:
        data = bytes.fromhex(c["data"])
        if "text" in c:
            assert c["text"].encode("utf-8") == data
        assert qs.adr36_sign_bytes(address, data).hex() == c["adr36SignBytes"]
        assert qs.message_pq_sign_bytes(chain_id, data).hex() == c["pqSignBytes"]

        signature = qs.sign_message(chain_id, address, data, classical, pq_key=pq)
        assert json.loads(qs.message_signature_to_json(signature)) == c["signature"]
        from_vector = qs.message_signature_from_json(json.dumps(c["signature"]))
        assert from_vector == signature
        assert from_vector.signature_type == qs.MessageSignatureType.ML_DSA87_HYBRID
        assert qs.verify_message(chain_id, address, data, from_vector, pq_public_key=pq.public_key) is None

        def verify_code(signature, pq_public_key, chain=chain_id, payload=data, require_pq=True):
            return error_code(
                qs.verify_message,
                chain,
                address,
                payload,
                signature,
                pq_public_key=pq_public_key,
                require_pq=require_pq,
            )

        assert verify_code(from_vector, pq.public_key, chain="qorechain-vladi") == "PQ_SIGNATURE_INVALID"
        assert verify_code(from_vector, pq.public_key, chain="bad chain") == "INVALID_ARGUMENT"
        assert verify_code(from_vector, pq.public_key, payload=b"x") == "CLASSICAL_SIGNATURE_INVALID"
        assert verify_code(from_vector, None) == "KEY_NOT_REGISTERED"
        classical_only = qs.MessageSignature(
            signature_type=qs.MessageSignatureType.SECP256K1, classical=from_vector.classical
        )
        assert verify_code(classical_only, pq.public_key) == "PQ_LAYER_MISSING"
        assert verify_code(classical_only, None, require_pq=False) is None
        unsupported = qs.MessageSignature(
            signature_type=qs.MessageSignatureType.ML_DSA87_HYBRID,
            classical=from_vector.classical,
            pq=qs.MessagePqSignature(algorithm_id=2, signature=from_vector.pq.signature),
        )
        assert verify_code(unsupported, pq.public_key) == "UNSUPPORTED_ALGORITHM"

    eth = qs.derive_classical_key(ctx["mnemonic"], qs.ClassicalKeyType.ETH_SECP256K1)
    assert error_code(qs.sign_message, chain_id, address, b"x", eth) == "ADDRESS_MISMATCH"
    assert error_code(qs.message_signature_from_json, "{}") == "INVALID_ARGUMENT"


def test_lanes():
    assert qs.lane_support(qs.Lane.NATIVE) == qs.LaneSupport.HYBRID
    assert qs.lane_support(qs.Lane.EVM) == qs.LaneSupport.QUANTUM_READY
    assert qs.lane_support(qs.Lane.SVM) == qs.LaneSupport.UNAVAILABLE
    assert qs.assert_hybrid_lane(qs.Lane.NATIVE) is None
    assert error_code(qs.assert_hybrid_lane, qs.Lane.EVM) == "LANE_NOT_AVAILABLE"
    assert error_code(qs.assert_hybrid_lane, qs.Lane.SVM) == "LANE_NOT_AVAILABLE"

    d = qs.decide_lane(qs.LaneRequest(is_qor_transfer=True))
    assert d.lane == qs.Lane.NATIVE
    assert not d.leaves_hybrid_default
    assert d.reason == qs.LaneReason.DEFAULT_NATIVE
    override = qs.decide_lane(qs.LaneRequest(is_qor_transfer=True, explicit_lane=qs.Lane.EVM))
    assert override.reason == qs.LaneReason.USER_OVERRIDE
    assert override.leaves_hybrid_default

    def state(**kw):
        return qs.evaluate_layer_state(qs.LayerStateInput(**kw))

    assert state(lane=qs.Lane.NATIVE, on_qore_chain=True, signed_with_pq_layer=True) == qs.LayerState.PENDING
    assert (
        state(
            lane=qs.Lane.NATIVE,
            on_qore_chain=True,
            signed_with_pq_layer=True,
            committed_extension_type_urls=[qs.PQC_HYBRID_TYPE_URL],
        )
        == qs.LayerState.PROTECTED
    )
    assert (
        state(lane=qs.Lane.NATIVE, on_qore_chain=True, signed_with_pq_layer=True, committed_extension_type_urls=[])
        == qs.LayerState.DOWNGRADED
    )
    assert state(lane=qs.Lane.EVM, on_qore_chain=True, signed_with_pq_layer=False) == qs.LayerState.CLASSICAL


def test_argument_types(ctx):
    # The bindings check argument types before calling into the library.
    with pytest.raises(TypeError):
        qs.derive_classical_key(b"bytes, not str", qs.ClassicalKeyType.SECP256K1)
    with pytest.raises((TypeError, ValueError)):
        qs.sign_hybrid("qorechain-diana", -1, b"", b"", ctx["classical"], pq_key=ctx["pq"])
