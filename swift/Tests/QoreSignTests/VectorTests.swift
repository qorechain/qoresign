// SPDX-License-Identifier: Apache-2.0
//
// Checks the Swift package against vectors/qoresign-v1.json.

import Foundation
import XCTest

@testable import QoreSign

private func loadVectors() throws -> [String: Any] {
    let root = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // QoreSignTests
        .deletingLastPathComponent() // Tests
        .deletingLastPathComponent() // swift
        .deletingLastPathComponent() // repository root
    let data = try Data(contentsOf: root.appendingPathComponent("vectors/qoresign-v1.json"))
    return try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
}

private func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

private func unhex(_ s: String) -> Data {
    var out = Data(capacity: s.count / 2)
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        out.append(UInt8(s[i..<j], radix: 16)!)
        i = j
    }
    return out
}

private func errorCode(_ body: () throws -> Void) -> String? {
    do {
        try body()
        return nil
    } catch let e as QoreSignError {
        return e.code
    } catch {
        return "unexpected \(error)"
    }
}

final class VectorTests: XCTestCase {
    var v: [String: Any] = [:]
    var mnemonic = ""
    var chainId = ""
    var classical: ClassicalKey!
    var pq: PqKeyPair!
    var address = ""

    override func setUpWithError() throws {
        v = try loadVectors()
        XCTAssertEqual(v["format"] as? String, "qoresign-vectors-v1")
        mnemonic = v["mnemonic"] as! String
        chainId = v["chainId"] as! String
        classical = try deriveClassicalKey(mnemonic: mnemonic, keyType: .secp256k1)
        address = try addressFromPublicKey(publicKey: classical.publicKey, keyType: .secp256k1).bech32
        pq = try deriveCanonicalPqKey(mnemonic: mnemonic, address: address)
    }

    func testAccounts() throws {
        let accounts = v["accounts"] as! [String: [String: String]]
        for (name, keyType) in [("secp256k1", ClassicalKeyType.secp256k1), ("eth_secp256k1", .ethSecp256k1)] {
            let a = accounts[name]!
            XCTAssertEqual(defaultClassicalPath(keyType: keyType), a["path"])
            let key = try deriveClassicalKey(mnemonic: mnemonic, keyType: keyType)
            XCTAssertEqual(try deriveClassicalKey(mnemonic: mnemonic, keyType: keyType, path: a["path"]), key)
            XCTAssertEqual(hex(key.privateKey), a["privateKey"])
            XCTAssertEqual(hex(key.publicKey), a["publicKey"])
            let addr = try addressFromPublicKey(publicKey: key.publicKey, keyType: keyType)
            XCTAssertEqual(addr.bech32, a["address"])
            XCTAssertEqual(addr.hex, a["hex"])
            XCTAssertEqual(try parseAddress(address: a["hex"]!), addr)
            XCTAssertEqual(try parseAddress(address: a["address"]!), addr)
            XCTAssertEqual(try classicalKeyTypeFor(publicKey: key.publicKey, address: addr.bech32), keyType)
            XCTAssertEqual(try classicalKeyFromPrivate(privateKey: key.privateKey, keyType: keyType), key)
        }
    }

    func testPqKeys() throws {
        for item in v["canonical"] as! [[String: String]] {
            let key = try deriveCanonicalPqKey(mnemonic: mnemonic, address: item["address"]!)
            XCTAssertEqual(key.publicKey.count, QoreSignConstants.mlDsa87PublicKeyLength)
            XCTAssertEqual(key.secretKey.count, QoreSignConstants.mlDsa87SecretKeyLength)
            XCTAssertEqual(hex(key.publicKey), item["publicKey"])
        }
        XCTAssertEqual(hex(pq.publicKey), (v["canonical"] as! [[String: String]])[0]["publicKey"])

        let hd = v["hd"] as! [[String: String]]
        for item in hd {
            let key = try deriveHdPqKey(mnemonic: mnemonic, path: item["path"]!)
            XCTAssertEqual(hex(key.publicKey), item["publicKey"], item["path"]!)
        }
        XCTAssertEqual(defaultHdPath(), hd[0]["path"])
        XCTAssertEqual(defaultHdPath(index: 1), hd[1]["path"])
        XCTAssertEqual(defaultHdPath(coinType: 60), hd[2]["path"])

        let codes = (v["hdRejected"] as! [String]).map { path in
            errorCode { _ = try deriveHdPqKey(mnemonic: mnemonic, path: path) }
        }
        XCTAssertEqual(codes, ["HD_NON_HARDENED", "HD_INVALID_PATH", "HD_INVALID_PATH"])
    }

    func testHybridTx() throws {
        let t = v["hybridTx"] as! [String: Any]
        let accountNumber = UInt64(t["accountNumber"] as! Int)
        let body = unhex(t["bodyBytes"] as! String)
        let auth = unhex(t["authInfoBytes"] as! String)
        let cases = t["cases"] as! [[String: String]]
        XCTAssertEqual(cases.count, 2)
        for c in cases {
            let isV1 = c["signBytesVersion"] == "v1"
            let version: SignBytesVersion = isV1 ? .v1 : .v2
            let signBytes = try hybridSignBytes(chainId: chainId, bodyBytes: body, authInfoBytes: auth, version: version)
            XCTAssertEqual(hex(signBytes), c["signBytes"])

            let options = SignOptions(signBytesVersion: version)
            let signed = try signHybrid(
                chainId: chainId, accountNumber: accountNumber, bodyBytes: body, authInfoBytes: auth,
                classicalKey: classical, pqKey: pq, options: options)
            XCTAssertEqual(signed.pqSignature?.count, QoreSignConstants.mlDsa87SignatureLength)
            XCTAssertEqual(hex(signed.pqSignature!), c["pqSignature"])
            XCTAssertEqual(hex(signed.bodyBytes), c["signedBodyBytes"])
            XCTAssertEqual(hex(signed.classicalSignature), c["classicalSignature"])
            XCTAssertEqual(hex(signed.txBytes), c["txBytes"])

            let layer = try signPqLayer(chainId: chainId, bodyBytes: body, authInfoBytes: auth, pqKey: pq, options: options)
            XCTAssertEqual(layer.bodyBytes, signed.bodyBytes)

            let result = try verifyHybridTx(
                txBytes: unhex(c["txBytes"]!), chainId: chainId, accountNumber: accountNumber,
                classicalPublicKey: classical.publicKey, pqPublicKey: pq.publicKey, version: .either)
            XCTAssertTrue(result.valid)
            XCTAssertTrue(result.classical)
            XCTAssertEqual(result.pq?.signBytesVersion, version)
        }
    }

    func testHybridTxNegative() throws {
        let t = v["hybridTx"] as! [String: Any]
        let accountNumber = UInt64(t["accountNumber"] as! Int)
        let body = unhex(t["bodyBytes"] as! String)
        let auth = unhex(t["authInfoBytes"] as! String)
        let txBytes = unhex((t["cases"] as! [[String: String]])[0]["txBytes"]!)

        // Wrong account number: the classical signature fails.
        let wrongAccount = try verifyHybridTx(
            txBytes: txBytes, chainId: chainId, accountNumber: accountNumber + 1,
            classicalPublicKey: classical.publicKey, pqPublicKey: pq.publicKey, version: .either)
        XCTAssertFalse(wrongAccount.valid)
        XCTAssertFalse(wrongAccount.classical)

        // Another account's ML-DSA-87 key: the PQ layer fails.
        let other = (v["canonical"] as! [[String: String]])[1]
        let wrongKey = try verifyHybridTx(
            txBytes: txBytes, chainId: chainId, accountNumber: accountNumber,
            classicalPublicKey: classical.publicKey, pqPublicKey: unhex(other["publicKey"]!))
        XCTAssertFalse(wrongKey.valid)
        XCTAssertEqual(wrongKey.pq?.reason, .invalidSignature)

        // An unsigned body has no layer.
        let missing = try verifyPqLayer(chainId: chainId, bodyBytes: body, authInfoBytes: auth, pqPublicKey: pq.publicKey)
        XCTAssertEqual(missing.reason, .missing)

        XCTAssertEqual(errorCode {
            _ = try signHybrid(chainId: chainId, accountNumber: 7, bodyBytes: body, authInfoBytes: auth, classicalKey: self.classical)
        }, "INVALID_ARGUMENT")
        XCTAssertEqual(errorCode {
            _ = try signHybrid(chainId: chainId, accountNumber: 7, bodyBytes: body, authInfoBytes: auth,
                               classicalKey: self.classical, pqKey: self.pq, mode: .pqOnly)
        }, "LANE_NOT_AVAILABLE")
        XCTAssertEqual(errorCode { _ = try deriveClassicalKey(mnemonic: "abandon  abandon", keyType: .secp256k1) }, "INVALID_MNEMONIC")
        XCTAssertEqual(errorCode { _ = try parseAddress(address: "cosmos1xyz") }, "INVALID_ADDRESS")
        XCTAssertEqual(errorCode { _ = try pqKeyFromSeed(seed: Data(count: 31)) }, "BAD_KEY_LENGTH")
    }

    func testRegistration() throws {
        let p = v["proofOfPossession"] as! [String: String]
        XCTAssertEqual(p["account"], address)
        let message = try proofOfPossessionMessage(chainId: chainId, account: address, publicKey: pq.publicKey)
        XCTAssertEqual(String(data: message, encoding: .utf8), p["message"])
        let proof = try signProofOfPossession(chainId: chainId, account: address, pqKey: pq)
        XCTAssertEqual(hex(proof), p["signature"])
        XCTAssertTrue(try verifyProofOfPossession(chainId: chainId, account: address, publicKey: pq.publicKey, proof: proof))
        XCTAssertFalse(try verifyProofOfPossession(chainId: "qorechain-vladi", account: address, publicKey: pq.publicKey, proof: proof))

        let r = v["registerMessage"] as! [String: String]
        let msg = try buildRegisterPqKeyMessage(chainId: chainId, account: address, pqKey: pq, classicalPublicKey: classical.publicKey)
        XCTAssertEqual(msg.typeUrl, r["typeUrl"])
        XCTAssertEqual(msg.typeUrl, QoreSignConstants.msgRegisterPqcKeyV2TypeUrl)
        XCTAssertEqual(hex(msg.value), r["value"])

        XCTAssertFalse(isDegeneratePqPublicKey(publicKey: pq.publicKey))
        var degenerate = pq.publicKey
        degenerate.replaceSubrange(32..<degenerate.count, with: Data(count: degenerate.count - 32))
        XCTAssertTrue(isDegeneratePqPublicKey(publicKey: degenerate))
        let eth = try deriveClassicalKey(mnemonic: mnemonic, keyType: .ethSecp256k1)
        XCTAssertEqual(errorCode {
            _ = try buildRegisterPqKeyMessage(chainId: self.chainId, account: self.address, pqKey: self.pq, classicalPublicKey: eth.publicKey)
        }, "ADDRESS_MISMATCH")
    }

    func testSiwq() throws {
        let q = v["siwq"] as! [String: Any]
        let f = q["fields"] as! [String: Any]
        let fields = SiwqFields(
            domain: f["domain"] as! String, address: f["address"] as! String, uri: f["uri"] as! String,
            chainId: f["chainId"] as! String, nonce: f["nonce"] as! String, issuedAt: f["issuedAt"] as! String,
            scheme: f["scheme"] as? String, statement: f["statement"] as? String,
            expirationTime: f["expirationTime"] as? String, resources: f["resources"] as? [String])
        let message = try createSiwqMessage(fields: fields)
        XCTAssertEqual(message, q["message"] as? String)

        let parsed = try parseSiwqMessage(message: message)
        XCTAssertEqual(parsed.version, "1")
        XCTAssertEqual(try createSiwqMessage(fields: parsed), message)
        XCTAssertEqual(hex(adr36SignBytes(signer: address, data: Data(message.utf8))), q["adr36SignBytes"] as? String)
        XCTAssertEqual(hex(siwqPqSignBytes(message: message)), q["pqSignBytes"] as? String)

        let signature = try signSiwq(message: message, classicalKey: classical, pqKey: pq)
        let expected = q["signature"] as! [String: Any]
        let json = try JSONSerialization.jsonObject(with: Data(try siwqSignatureToJson(signature: signature).utf8))
        XCTAssertEqual(json as? NSDictionary, expected as NSDictionary)
        let vectorJson = String(data: try JSONSerialization.data(withJSONObject: expected), encoding: .utf8)!
        let fromVector = try siwqSignatureFromJson(json: vectorJson)
        XCTAssertEqual(fromVector, signature)
        XCTAssertEqual(fromVector.signatureType, .mlDsa87Hybrid)

        let verifyAt = try XCTUnwrap(ISO8601DateFormatter().date(from: q["verifyAt"] as! String))
        let nowMs = Int64(verifyAt.timeIntervalSince1970 * 1000)
        let verified = try verifySiwq(
            message: message, signature: fromVector, domain: "app.example.com", nonce: "a1b2c3d4e5",
            pqPublicKey: pq.publicKey, chainId: chainId, nowMs: nowMs)
        XCTAssertEqual(verified, parsed)

        func verifyCode(domain: String = "app.example.com", nonce: String = "a1b2c3d4e5",
                        nowMs: Int64, pqPublicKey: Data?, signature: SiwqSignature) -> String? {
            errorCode {
                _ = try verifySiwq(message: message, signature: signature, domain: domain, nonce: nonce,
                                   pqPublicKey: pqPublicKey, nowMs: nowMs)
            }
        }
        XCTAssertEqual(verifyCode(domain: "evil.example.com", nowMs: nowMs, pqPublicKey: pq.publicKey, signature: fromVector), "SIWQ_DOMAIN_MISMATCH")
        XCTAssertEqual(verifyCode(nonce: "zzzzzzzzzz", nowMs: nowMs, pqPublicKey: pq.publicKey, signature: fromVector), "SIWQ_NONCE_MISMATCH")
        XCTAssertEqual(verifyCode(nowMs: nowMs + 3_600_000, pqPublicKey: pq.publicKey, signature: fromVector), "SIWQ_EXPIRED")
        XCTAssertEqual(verifyCode(nowMs: nowMs, pqPublicKey: nil, signature: fromVector), "KEY_NOT_REGISTERED")
        let classicalOnly = SiwqSignature(signatureType: .secp256k1, classical: fromVector.classical)
        XCTAssertEqual(verifyCode(nowMs: nowMs, pqPublicKey: pq.publicKey, signature: classicalOnly), "PQ_LAYER_MISSING")
        XCTAssertEqual(errorCode { _ = try parseSiwqMessage(message: "hello") }, "SIWQ_MALFORMED")
    }

    func testLanes() throws {
        XCTAssertEqual(laneSupport(lane: .native), .hybrid)
        XCTAssertEqual(laneSupport(lane: .evm), .quantumReady)
        XCTAssertEqual(laneSupport(lane: .svm), .unavailable)
        XCTAssertNoThrow(try assertHybridLane(lane: .native))
        XCTAssertEqual(errorCode { try assertHybridLane(lane: .evm) }, "LANE_NOT_AVAILABLE")
        XCTAssertEqual(errorCode { try assertHybridLane(lane: .svm) }, "LANE_NOT_AVAILABLE")

        let d = decideLane(request: LaneRequest(isQorTransfer: true))
        XCTAssertEqual(d.lane, .native)
        XCTAssertFalse(d.leavesHybridDefault)
        XCTAssertEqual(d.reason, .defaultNative)
        XCTAssertEqual(decideLane(request: LaneRequest(isQorTransfer: true, explicitLane: .evm)).reason, .userOverride)

        XCTAssertEqual(evaluateLayerState(input: LayerStateInput(lane: .native, onQoreChain: true, signedWithPqLayer: true)), .pending)
        XCTAssertEqual(evaluateLayerState(input: LayerStateInput(
            lane: .native, onQoreChain: true, signedWithPqLayer: true,
            committedExtensionTypeUrls: [QoreSignConstants.pqcHybridTypeUrl])), .protected)
        XCTAssertEqual(evaluateLayerState(input: LayerStateInput(
            lane: .native, onQoreChain: true, signedWithPqLayer: true, committedExtensionTypeUrls: [])), .downgraded)
        XCTAssertEqual(evaluateLayerState(input: LayerStateInput(lane: .evm, onQoreChain: true, signedWithPqLayer: false)), .classical)
    }
}
