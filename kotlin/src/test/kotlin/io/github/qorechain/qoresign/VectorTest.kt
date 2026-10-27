// SPDX-License-Identifier: Apache-2.0
//
// Checks the Kotlin package against vectors/qoresign-v1.json.

package io.github.qorechain.qoresign

import java.io.File
import java.time.Instant
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

private val vectors: JsonObject = Json.parseToJsonElement(
    File(System.getProperty("qoresign.vectors") ?: "../vectors/qoresign-v1.json").readText(),
).jsonObject

private fun JsonElement.str(key: String): String = jsonObject.getValue(key).jsonPrimitive.content

private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

private fun String.unhex(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

private fun errorCode(block: () -> Unit): String? =
    try {
        block()
        null
    } catch (e: QoreSignException) {
        e.code
    }

class VectorTest {
    private val mnemonic = vectors.str("mnemonic")
    private val chainId = vectors.str("chainId")
    private val classical = deriveClassicalKey(mnemonic, ClassicalKeyType.SECP256K1)
    private val address = addressFromPublicKey(classical.publicKey, ClassicalKeyType.SECP256K1).bech32
    private val pq = deriveCanonicalPqKey(mnemonic, address)

    @Test
    fun format() {
        assertEquals("qoresign-vectors-v1", vectors.str("format"))
    }

    @Test
    fun accounts() {
        val accounts = vectors.getValue("accounts")
        for ((name, keyType) in listOf("secp256k1" to ClassicalKeyType.SECP256K1, "eth_secp256k1" to ClassicalKeyType.ETH_SECP256K1)) {
            val a = accounts.jsonObject.getValue(name)
            assertEquals(a.str("path"), defaultClassicalPath(keyType))
            val key = deriveClassicalKey(mnemonic, keyType)
            val byPath = deriveClassicalKey(mnemonic, keyType, path = a.str("path"))
            assertArrayEquals(key.privateKey, byPath.privateKey)
            assertEquals(a.str("privateKey"), key.privateKey.hex())
            assertEquals(a.str("publicKey"), key.publicKey.hex())
            val addr = addressFromPublicKey(key.publicKey, keyType)
            assertEquals(a.str("address"), addr.bech32)
            assertEquals(a.str("hex"), addr.hex)
            assertEquals(addr.bech32, parseAddress(a.str("hex")).bech32)
            assertEquals(addr.hex, parseAddress(a.str("address")).hex)
            assertEquals(keyType, classicalKeyTypeFor(key.publicKey, addr.bech32))
            assertArrayEquals(key.publicKey, classicalKeyFromPrivate(key.privateKey, keyType).publicKey)
        }
    }

    @Test
    fun pqKeys() {
        val canonical = vectors.getValue("canonical").jsonArray
        for (item in canonical) {
            val key = deriveCanonicalPqKey(mnemonic, item.str("address"))
            assertEquals(QoreSignConstants.ML_DSA_87_PUBLIC_KEY_LENGTH, key.publicKey.size)
            assertEquals(QoreSignConstants.ML_DSA_87_SECRET_KEY_LENGTH, key.secretKey.size)
            assertEquals(item.str("publicKey"), key.publicKey.hex())
        }
        assertEquals(canonical[0].str("publicKey"), pq.publicKey.hex())

        val hd = vectors.getValue("hd").jsonArray
        for (item in hd) {
            assertEquals(item.str("publicKey"), deriveHdPqKey(mnemonic, item.str("path")).publicKey.hex(), item.str("path"))
        }
        assertEquals(hd[0].str("path"), defaultHdPath())
        assertEquals(hd[1].str("path"), defaultHdPath(index = 1u))
        assertEquals(hd[2].str("path"), defaultHdPath(coinType = 60u))

        val codes = vectors.getValue("hdRejected").jsonArray.map { p ->
            errorCode { deriveHdPqKey(mnemonic, p.jsonPrimitive.content) }
        }
        assertEquals(listOf("HD_NON_HARDENED", "HD_INVALID_PATH", "HD_INVALID_PATH"), codes)
    }

    @Test
    fun hybridTx() {
        val t = vectors.getValue("hybridTx")
        val accountNumber = t.jsonObject.getValue("accountNumber").jsonPrimitive.int.toULong()
        val body = t.str("bodyBytes").unhex()
        val auth = t.str("authInfoBytes").unhex()
        val cases = t.jsonObject.getValue("cases").jsonArray
        assertEquals(2, cases.size)
        for (c in cases) {
            val version = if (c.str("signBytesVersion") == "v1") SignBytesVersion.V1 else SignBytesVersion.V2
            assertEquals(c.str("signBytes"), hybridSignBytes(chainId, body, auth, version).hex())

            val options = SignOptions(signBytesVersion = version)
            val signed = signHybrid(chainId, accountNumber, body, auth, classical, pqKey = pq, options = options)
            val pqSignature = signed.pqSignature!!
            assertEquals(QoreSignConstants.ML_DSA_87_SIGNATURE_LENGTH, pqSignature.size)
            assertEquals(c.str("pqSignature"), pqSignature.hex())
            assertEquals(c.str("signedBodyBytes"), signed.bodyBytes.hex())
            assertEquals(c.str("classicalSignature"), signed.classicalSignature.hex())
            assertEquals(c.str("txBytes"), signed.txBytes.hex())

            val layer = signPqLayer(chainId, body, auth, pq, options)
            assertArrayEquals(signed.bodyBytes, layer.bodyBytes)

            val result = verifyHybridTx(
                c.str("txBytes").unhex(), chainId, accountNumber, classical.publicKey,
                pqPublicKey = pq.publicKey, version = VerifyVersion.EITHER,
            )
            assertTrue(result.valid)
            assertTrue(result.classical)
            assertEquals(version, result.pq?.signBytesVersion)
        }
    }

    @Test
    fun hybridTxNegative() {
        val t = vectors.getValue("hybridTx")
        val accountNumber = t.jsonObject.getValue("accountNumber").jsonPrimitive.int.toULong()
        val body = t.str("bodyBytes").unhex()
        val auth = t.str("authInfoBytes").unhex()
        val txBytes = t.jsonObject.getValue("cases").jsonArray[0].str("txBytes").unhex()

        val wrongAccount = verifyHybridTx(txBytes, chainId, accountNumber + 1u, classical.publicKey, pq.publicKey, version = VerifyVersion.EITHER)
        assertFalse(wrongAccount.valid)
        assertFalse(wrongAccount.classical)

        val other = vectors.getValue("canonical").jsonArray[1].str("publicKey").unhex()
        val wrongKey = verifyHybridTx(txBytes, chainId, accountNumber, classical.publicKey, other)
        assertFalse(wrongKey.valid)
        assertEquals(PqLayerFailure.INVALID_SIGNATURE, wrongKey.pq?.reason)

        assertEquals(PqLayerFailure.MISSING, verifyPqLayer(chainId, body, auth, pq.publicKey).reason)

        assertEquals("INVALID_ARGUMENT", errorCode { signHybrid(chainId, 7u, body, auth, classical) })
        assertEquals("LANE_NOT_AVAILABLE", errorCode { signHybrid(chainId, 7u, body, auth, classical, pq, SigningMode.PQ_ONLY) })
        assertEquals("INVALID_MNEMONIC", errorCode { deriveClassicalKey("abandon  abandon", ClassicalKeyType.SECP256K1) })
        assertEquals("INVALID_ADDRESS", errorCode { parseAddress("cosmos1xyz") })
        assertEquals("BAD_KEY_LENGTH", errorCode { pqKeyFromSeed(ByteArray(31)) })
    }

    @Test
    fun registration() {
        val p = vectors.getValue("proofOfPossession")
        assertEquals(address, p.str("account"))
        assertEquals(p.str("message"), proofOfPossessionMessage(chainId, address, pq.publicKey).decodeToString())
        val proof = signProofOfPossession(chainId, address, pq)
        assertEquals(p.str("signature"), proof.hex())
        assertTrue(verifyProofOfPossession(chainId, address, pq.publicKey, proof))
        assertFalse(verifyProofOfPossession("qorechain-vladi", address, pq.publicKey, proof))

        val r = vectors.getValue("registerMessage")
        val msg = buildRegisterPqKeyMessage(chainId, address, pq, classical.publicKey)
        assertEquals(r.str("typeUrl"), msg.typeUrl)
        assertEquals(QoreSignConstants.MSG_REGISTER_PQC_KEY_V2_TYPE_URL, msg.typeUrl)
        assertEquals(r.str("value"), msg.value.hex())

        assertFalse(isDegeneratePqPublicKey(pq.publicKey))
        val degenerate = pq.publicKey.copyOf().also { it.fill(0, 32, it.size) }
        assertTrue(isDegeneratePqPublicKey(degenerate))
        val eth = deriveClassicalKey(mnemonic, ClassicalKeyType.ETH_SECP256K1)
        assertEquals("ADDRESS_MISMATCH", errorCode { buildRegisterPqKeyMessage(chainId, address, pq, eth.publicKey) })
    }

    @Test
    fun siwq() {
        val q = vectors.getValue("siwq")
        val f = q.jsonObject.getValue("fields")
        val fields = SiwqFields(
            domain = f.str("domain"),
            address = f.str("address"),
            uri = f.str("uri"),
            chainId = f.str("chainId"),
            nonce = f.str("nonce"),
            issuedAt = f.str("issuedAt"),
            scheme = f.str("scheme"),
            statement = f.str("statement"),
            expirationTime = f.str("expirationTime"),
            resources = f.jsonObject.getValue("resources").jsonArray.map { it.jsonPrimitive.content },
        )
        val message = createSiwqMessage(fields)
        assertEquals(q.str("message"), message)

        val parsed = parseSiwqMessage(message)
        assertEquals("1", parsed.version)
        assertEquals(message, createSiwqMessage(parsed))
        assertEquals(q.str("adr36SignBytes"), adr36SignBytes(address, message.encodeToByteArray()).hex())
        assertEquals(q.str("pqSignBytes"), siwqPqSignBytes(message).hex())

        val signature = signSiwq(message, classical, pq)
        val expected = q.jsonObject.getValue("signature")
        assertEquals(expected, Json.parseToJsonElement(siwqSignatureToJson(signature)))
        val fromVector = siwqSignatureFromJson(expected.toString())
        assertEquals(signature, fromVector)
        assertEquals(SiwqSignatureType.ML_DSA87_HYBRID, fromVector.signatureType)

        val nowMs = Instant.parse(q.str("verifyAt")).toEpochMilli()
        val verified = verifySiwq(message, fromVector, "app.example.com", "a1b2c3d4e5", pq.publicKey, chainId, nowMs = nowMs)
        assertEquals(parsed, verified)

        fun code(
            domain: String = "app.example.com",
            nonce: String = "a1b2c3d4e5",
            now: Long = nowMs,
            key: ByteArray? = pq.publicKey,
            sig: SiwqSignature = fromVector,
        ) = errorCode { verifySiwq(message, sig, domain, nonce, key, nowMs = now) }
        assertEquals("SIWQ_DOMAIN_MISMATCH", code(domain = "evil.example.com"))
        assertEquals("SIWQ_NONCE_MISMATCH", code(nonce = "zzzzzzzzzz"))
        assertEquals("SIWQ_EXPIRED", code(now = nowMs + 3_600_000))
        assertEquals("KEY_NOT_REGISTERED", code(key = null))
        assertEquals("PQ_LAYER_MISSING", code(sig = SiwqSignature(SiwqSignatureType.SECP256K1, fromVector.classical)))
        assertEquals("SIWQ_MALFORMED", errorCode { parseSiwqMessage("hello") })
    }

    @Test
    fun lanes() {
        assertEquals(LaneSupport.HYBRID, laneSupport(Lane.NATIVE))
        assertEquals(LaneSupport.QUANTUM_READY, laneSupport(Lane.EVM))
        assertEquals(LaneSupport.UNAVAILABLE, laneSupport(Lane.SVM))
        assertNull(errorCode { assertHybridLane(Lane.NATIVE) })
        assertEquals("LANE_NOT_AVAILABLE", errorCode { assertHybridLane(Lane.EVM) })
        assertEquals("LANE_NOT_AVAILABLE", errorCode { assertHybridLane(Lane.SVM) })

        val d = decideLane(LaneRequest(isQorTransfer = true))
        assertEquals(LaneDecision(Lane.NATIVE, false, LaneReason.DEFAULT_NATIVE), d)
        assertEquals(LaneReason.DAPP_REQUIRED, decideLane(LaneRequest(true, dappRequiredLane = Lane.EVM)).reason)

        assertEquals(LayerState.PENDING, evaluateLayerState(LayerStateInput(Lane.NATIVE, true, true)))
        assertEquals(
            LayerState.PROTECTED,
            evaluateLayerState(LayerStateInput(Lane.NATIVE, true, true, listOf(QoreSignConstants.PQC_HYBRID_TYPE_URL))),
        )
        assertEquals(LayerState.DOWNGRADED, evaluateLayerState(LayerStateInput(Lane.NATIVE, true, true, emptyList())))
        assertEquals(LayerState.CLASSICAL, evaluateLayerState(LayerStateInput(Lane.EVM, true, false)))
    }
}
