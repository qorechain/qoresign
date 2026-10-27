# EVM wallets: quantum-ready mode

Ethereum transactions have no field where a second signature could travel, and the network applies its PQC setting chain-wide rather than per lane. So a transaction sent on QoreChain's EVM lane is signed with secp256k1 only, and QoreSign does not offer a hybrid EVM signature (`assertHybridLane("evm")` throws `LANE_NOT_AVAILABLE`).

Instead, the network admits an EVM transaction only if its sender has a registered ML-DSA-87 key and a live **EVM authorization window** that covers it. The window is opened from the native lane by a hybrid-signed transaction, so the post-quantum key authorizes EVM activity ahead of time ("quantum-ready mode"). Both public networks enforce this (protocol feature `evm-pqc-authorisation-window`, readable with `fetchProtocolFeatures` in the QoreChain SDK or at `/qorechain/pqc/v1/protocol_features`).

Steps for an EVM account:

1. Register an ML-DSA-87 key for the account on the native lane (`buildRegisterPqKeyMessage`). For an `eth_secp256k1` account the same 20 address bytes have a `qor1` form; use it as `sender`.
2. Open a window with a hybrid-signed native-lane transaction: an expiry height, a maximum number of EVM transactions, a maximum value and, optionally, the contracts it may call. The QoreChain SDK has composers for the window messages.
3. Send EVM transactions from any EIP-1193 wallet while the window is open. Outside a window, or beyond its limits, the network refuses them, so the secp256k1 key alone cannot move value on the EVM lane.

When the network adds per-lane PQC for the EVM lane, QoreSign will add a hybrid EVM mode in a new minor version.

MetaMask and other EIP-1193 wallets cannot add an ML-DSA-87 signature to `eth_sendTransaction`; for them the window, opened from a wallet that holds the ML-DSA-87 key, is the available path.
