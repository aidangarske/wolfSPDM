# Project Structure

## Top-level layout

| Path | Purpose |
|------|---------|
| `src/` | Core protocol, crypto glue, transcript, secured messaging, and session logic |
| `wolfspdm/` | Public headers (`spdm.h`, `spdm_types.h`, `spdm_error.h`) |
| `examples/` | Demo client and emulator integration script |
| `test/` | Unit tests and emulator smoke test |
| `docs/` | Project documentation (including attestation notes) |
| `.github/workflows/` | CI workflows |

## Core source modules

| File | Responsibility |
|------|----------------|
| `src/spdm_context.c` | Context init/free lifecycle and state setup |
| `src/spdm_msg.c` | SPDM message construction and parsing |
| `src/spdm_crypto.c` | Cryptographic helper operations |
| `src/spdm_kdf.c` | HKDF-based key derivation |
| `src/spdm_transcript.c` | Transcript management (TH computations) |
| `src/spdm_secured.c` | Secured message protection (AES-256-GCM) |
| `src/spdm_session.c` | Handshake/session flow and higher-level operations |
| `src/spdm_internal.h` | Internal types, constants, and internal APIs |

## Public API surface

| Header | Content |
|--------|---------|
| `wolfspdm/spdm.h` | Main public API and feature macros |
| `wolfspdm/spdm_types.h` | SPDM protocol constants and algorithm identifiers |
| `wolfspdm/spdm_error.h` | Error code enum and error-string helper |

## Build/test assets

| File | Purpose |
|------|---------|
| `configure.ac` | Autotools configure logic and options |
| `Makefile.am` | Library, test, and example build targets |
| `examples/spdm_demo.c` | CLI demo for session/measurement/challenge/heartbeat/key update |
| `examples/spdm_test.sh` | 18-case emulator integration driver |
| `test/unit_test.c` | Unit test coverage |
| `test/test_spdm.c` | SPDM smoke-test utility |
