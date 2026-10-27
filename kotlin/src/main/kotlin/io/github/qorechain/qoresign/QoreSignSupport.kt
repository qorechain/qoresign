// SPDX-License-Identifier: Apache-2.0
//
// Small additions over the generated bindings in qoresign_ffi.kt.

package io.github.qorechain.qoresign

/** Stable code shared by every QoreSign implementation, e.g. `INVALID_MNEMONIC`. */
val QoreSignException.code: String
    get() = when (this) {
        is QoreSignException.Failure -> code
    }

/** Human-readable message without the code. */
val QoreSignException.detail: String
    get() = when (this) {
        is QoreSignException.Failure -> detail
    }

/** Constants of the QoreSign format, identical across implementations. */
object QoreSignConstants {
    /** Bech32 prefix of QoreChain accounts. */
    const val ACCOUNT_PREFIX = "qor"

    /** Algorithm id of ML-DSA-87 in `qorechain.pqc.v1`. */
    const val ALGORITHM_ML_DSA_87: UInt = 1u

    /** ML-DSA-87 sizes (FIPS 204, Table 2). */
    const val ML_DSA_87_PUBLIC_KEY_LENGTH = 2592
    const val ML_DSA_87_SECRET_KEY_LENGTH = 4896
    const val ML_DSA_87_SIGNATURE_LENGTH = 4627
    const val ML_DSA_87_SEED_LENGTH = 32

    /** Type URL of the PQC extension option on a transaction body. */
    const val PQC_HYBRID_TYPE_URL = "/qorechain.pqc.v1.PQCHybridSignature"

    /** Type URL of the key registration message. */
    const val MSG_REGISTER_PQC_KEY_V2_TYPE_URL = "/qorechain.pqc.v1.MsgRegisterPQCKeyV2"
}
