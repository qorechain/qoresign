# SPDX-License-Identifier: Apache-2.0
"""Hybrid secp256k1 + ML-DSA-87 (FIPS 204) signing for QoreChain.

Bindings over the Rust implementation (crates/qoresign) through UniFFI. The
output is byte-identical to the TypeScript, Rust, Go, Swift and Kotlin
packages; all of them are checked against vectors/qoresign-v1.json.

Every failure raises ``QoreSignError.Failure`` with ``code`` (stable across
implementations, for example ``INVALID_MNEMONIC``) and ``detail``.
"""

from importlib import metadata as _metadata

from ._ffi import qoresign_ffi as _ffi
from ._ffi.qoresign_ffi import *  # noqa: F401,F403

try:
    __version__ = _metadata.version("qorechain-qoresign")
except _metadata.PackageNotFoundError:  # pragma: no cover
    __version__ = "0+unknown"

# Constants of the QoreSign format, identical across implementations.

#: Bech32 prefix of QoreChain accounts.
ACCOUNT_PREFIX = "qor"
#: Algorithm id of ML-DSA-87 in ``qorechain.pqc.v1``.
ALGORITHM_ML_DSA_87 = 1
#: ML-DSA-87 sizes in bytes (FIPS 204, Table 2).
ML_DSA_87_PUBLIC_KEY_LENGTH = 2592
ML_DSA_87_SECRET_KEY_LENGTH = 4896
ML_DSA_87_SIGNATURE_LENGTH = 4627
ML_DSA_87_SEED_LENGTH = 32
#: Type URL of the PQC extension option on a transaction body.
PQC_HYBRID_TYPE_URL = "/qorechain.pqc.v1.PQCHybridSignature"
#: Type URL of the key registration message.
MSG_REGISTER_PQC_KEY_V2_TYPE_URL = "/qorechain.pqc.v1.MsgRegisterPQCKeyV2"

__all__ = [
    "ACCOUNT_PREFIX",
    "ALGORITHM_ML_DSA_87",
    "ML_DSA_87_PUBLIC_KEY_LENGTH",
    "ML_DSA_87_SECRET_KEY_LENGTH",
    "ML_DSA_87_SIGNATURE_LENGTH",
    "ML_DSA_87_SEED_LENGTH",
    "PQC_HYBRID_TYPE_URL",
    "MSG_REGISTER_PQC_KEY_V2_TYPE_URL",
]
__all__ += _ffi.__all__
