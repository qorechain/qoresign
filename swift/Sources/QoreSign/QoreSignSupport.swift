// SPDX-License-Identifier: Apache-2.0
//
// Small additions over the generated bindings in QoreSign.swift.

import Foundation

extension QoreSignError {
    /// Stable code shared by every QoreSign implementation, e.g. `INVALID_MNEMONIC`.
    public var code: String {
        switch self {
        case let .Failure(code, _): return code
        }
    }

    /// Human-readable message.
    public var message: String {
        switch self {
        case let .Failure(_, detail): return detail
        }
    }
}

/// Constants of the QoreSign format, identical across implementations.
public enum QoreSignConstants {
    /// Bech32 prefix of QoreChain accounts.
    public static let accountPrefix = "qor"
    /// Algorithm id of ML-DSA-87 in `qorechain.pqc.v1`.
    public static let algorithmMlDsa87: UInt32 = 1
    /// ML-DSA-87 sizes (FIPS 204, Table 2).
    public static let mlDsa87PublicKeyLength = 2592
    public static let mlDsa87SecretKeyLength = 4896
    public static let mlDsa87SignatureLength = 4627
    public static let mlDsa87SeedLength = 32
    /// Type URL of the PQC extension option on a transaction body.
    public static let pqcHybridTypeUrl = "/qorechain.pqc.v1.PQCHybridSignature"
    /// Type URL of the key registration message.
    public static let msgRegisterPqcKeyV2TypeUrl = "/qorechain.pqc.v1.MsgRegisterPQCKeyV2"
}
