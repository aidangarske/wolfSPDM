# Configuration and Macros

## Configure-time options

From `configure.ac`:

| Option | Default | Effect |
|--------|---------|--------|
| `--with-wolfssl=PATH` | system paths | Adds wolfSSL include/library search paths |
| `--enable-debug` | off | Defines `WOLFSPDM_DEBUG`, builds with `-g -O0` |
| `--enable-dynamic-mem` | off | Defines `WOLFSPDM_DYNAMIC_MEMORY` and enables `wolfSPDM_New` |
| `--disable-mldsa` | auto | Force ML-DSA off (default follows wolfSSL — see [[Post-Quantum ML-DSA]]) |
| `--disable-chunking` | on | Defines `WOLFSPDM_NO_CHUNK` — compile out CHUNK_GET (see [[Message Chunking]]) |

## Public feature macros

Defined in `wolfspdm/spdm.h` depending on build flags:

- `WOLFSPDM_HAS_MEASUREMENTS` *(not defined if `NO_WOLFSPDM_MEAS`)*
- `WOLFSPDM_HAS_CHALLENGE` *(not defined if `NO_WOLFSPDM_CHALLENGE`)*
- `WOLFSPDM_HAS_HEARTBEAT`
- `WOLFSPDM_HAS_KEY_UPDATE`
- `WOLFSPDM_HAVE_MLDSA` *(defined when ML-DSA is built in; follows wolfSSL's `WOLFSSL_HAVE_MLDSA`, suppress with `WOLFSPDM_NO_MLDSA`)*
- `WOLFSPDM_HAVE_CHUNK` *(defined when CHUNK_GET chunking is built in; suppress with `WOLFSPDM_NO_CHUNK`)* — tunables `WOLFSPDM_CHUNK_BUF_SIZE` (MTU, default 4096), `WOLFSPDM_CHUNK_MAX_CHUNKS` (default 64), and `WOLFSPDM_CHUNK_NO_SECURED` (drop the encrypted path). See [[Message Chunking]].

## Size and protocol constants

From `wolfspdm/spdm.h` and `wolfspdm/spdm_types.h`. The buffer/context defaults
grow when ML-DSA is built in so ML-DSA-65 payloads fit a single message
(all three buffer caps are overridable with `-D`):

| Constant | Classical | With ML-DSA |
|----------|-----------|-------------|
| `WOLFSPDM_CTX_STATIC_SIZE` | `32768` | `73728` |
| `WOLFSPDM_MAX_MSG_SIZE` | `4096` | `8192` |
| `WOLFSPDM_MAX_CERT_CHAIN` | `4096` | `24576` |
| `WOLFSPDM_MAX_TRANSCRIPT` | `4096` | `16384` |

Version constants:
- `SPDM_VERSION_12`, `SPDM_VERSION_13`, `SPDM_VERSION_14`

Measurement constants (when enabled):
- `SPDM_MEAS_OPERATION_ALL`
- `SPDM_MEAS_SUMMARY_HASH_NONE`, `_TCB`, `_ALL`

## Common compile-time feature toggles

These are used in source-level conditional compilation:

| Macro | Effect |
|-------|--------|
| `NO_WOLFSPDM_MEAS` | Removes measurement APIs and related fields/code |
| `NO_WOLFSPDM_MEAS_VERIFY` | Keeps retrieval path but disables measurement signature verification |
| `NO_WOLFSPDM_CHALLENGE` | Removes challenge-attestation API/code |
| `WOLFSPDM_LEAN` | Excludes selected convenience secured-message helpers |

## Notes

- `wolfspdm/options.h` is auto-generated from `config.h` during build/install.
- API availability should be detected using feature macros rather than hard-coded assumptions.
