# Contributing to QoreSign

Thanks for your interest. Issues, pull requests and discussion are welcome.

## Layout

| Path | Contents |
|---|---|
| `packages/ts` | TypeScript package `@qorechain/qoresign` (the reference implementation) |
| `crates/qoresign` | Rust crate `qorechain-qoresign` |
| `crates/qoresign-ffi` | bindings layer used by the Swift, Kotlin and Python packages (not published) |
| `go` | Go module `github.com/qorechain/qoresign/go` |
| `swift`, `Package.swift` | Swift package `QoreSign` |
| `kotlin` | Kotlin/JVM library `io.github.qorechain:qoresign` |
| `python` | Python package `qorechain-qoresign` (import `qoresign`) |
| `spec` | wire formats |
| `vectors` | test vectors shared by every implementation |
| `docs`, `examples` | guides and runnable examples |

## Build and test

```bash
pnpm install && pnpm build && pnpm lint && pnpm typecheck && pnpm test   # TypeScript
cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test   # Rust
(cd go && gofmt -l . && go vet ./... && go test ./...)                      # Go
pip install -r python/requirements-dev.txt && scripts/build-python-wheels.sh \
  && pip install --no-index --find-links python/dist qorechain-qoresign \
  && pytest python/tests                                                     # Python (in a venv)
```

Swift, Kotlin and Python: see `swift/README.md`, `kotlin/README.md` and `python/README.md`.

Integration tests against the `qorechain-diana` testnet run only with `QORE_LIVE_TEST=1` and `QORE_TEST_MNEMONIC` set to a funded testnet account.

## Changing a wire format

The TypeScript package is the reference. If a change affects bytes on the wire, update the relevant file in `spec/`, regenerate the vectors into a **new** versioned file (`pnpm build && pnpm vectors`), and make every implementation pass it in the same pull request.

## Pull requests

- Keep changes focused; add tests for behaviour changes.
- Add a changeset (`pnpm changeset`) when a published package changes.
- Match the existing code style; formatting and linting run in CI.

## Code of Conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).

## Security

Do not open public issues for vulnerabilities; see [SECURITY.md](SECURITY.md).
