# hx-libs

The Hotline protocol pieces that don't belong to any one program, as one
Cargo workspace. [GtkHx](https://github.com/mishan/gtkhx) and
[hxd-ng](https://github.com/mishan/hxd-ng) pull them in as git
dependencies.

## Crates

| Crate | What it is |
|---|---|
| `hxproto` | The classic Hotline wire format, including the tracker protocol, for servers and clients alike. |
| `hxfiles-xfer` | The file-transfer codec. |
| `hxhfs` | HFS metadata and resource-fork sidecars. |
| `hxcrypto` | The crypto behind HOPE, the secure login: HMAC and the legacy hashes, Blowfish OFB-64, ChaCha20-Poly1305 and its keys. |
| `hxhope` | HOPE itself, with no I/O of its own: the handshake as a client or a server plays it, and the cipher and compression it agrees, as a codec between a connection and its socket. |
| `hxsession` | A client session over the classic control connection: handshake, login, agreement, replies matched to requests, the keep-alive, and the server's pushes as events. It does no I/O of its own, so the same session runs over a TCP socket, a WebSocket to a relay, or a test's script. |
| `hl-identity` | Hotline-ng's identity objects: keys, device certificates, user cards, attestations, login proofs, registrar records, signed and sealed messages, server key handovers and friendship objects, in deterministic CBOR with domain-separated Ed25519, and no transport. Its specifications are hxd-ng's, and its test vectors, in `crates/hl-identity/vectors/`, are what other implementations check against. hl-delegation builds on it to give agents narrow, revocable authority (its specification is in `crates/hl-delegation/docs/`). |

## Features and targets

- `hxproto`'s emoji shortcode tables sit behind its default `emoji`
  feature, so a build that doesn't need them can leave them out
  (`default-features = false`). `tools/gen_emoji_table.py` generates
  them.
- `hxsession`'s `hope` feature, off by default, lets a session log in
  with HOPE; its bytes then go through the transport `hxhope` agreed. A
  client that does not log in with HOPE leaves the ciphers and
  compressors out.
- HOPE's Zstandard compression, a C library, sits behind `hxhope`'s
  `zstd` feature (and `hxsession`'s), off unless a consumer turns it on.
- `hxproto`, `hxfiles-xfer`, `hxcrypto`, `hxhope` and `hxsession` also
  build for `wasm32-unknown-unknown`, for a browser client.

## Building and testing

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p hxsession --features hxsession/hope
cargo test -p hxhope -p hxsession --features hxsession/zstd
```

CI also runs clippy with `hxsession/hope` and with `hxsession/zstd`, and
builds the wasm32 crates (`.github/workflows/ci.yml`). `hxsession`'s
`rig` feature runs `tests/rig.rs` against GtkHx's Docker rig of real
servers, which CI does not have.

## License

GPL-2.0-or-later (`LICENSE`), except `hl-identity` and `hl-delegation`,
which are licensed under either of MIT or Apache-2.0 at your option (each
crate's `LICENSE-MIT` and `LICENSE-APACHE`), so any implementation can use
them.
