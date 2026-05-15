# Configuration and Macros

## Configure-time options

From `configure.ac`:

| Option | Default | Effect |
|--------|---------|--------|
| `--with-wolfssl=PATH` | system paths | Adds wolfSSL include/library search paths |
| `--enable-debug` | off | Defines `WOLFSPDM_DEBUG`, builds with `-g -O0` |
| `--enable-dynamic-mem` | off | Defines `WOLFSPDM_DYNAMIC_MEMORY` and enables `wolfSPDM_New` |

## Public feature macros

Defined in `wolfspdm/spdm.h` depending on build flags:

- `WOLFSPDM_HAS_MEASUREMENTS` *(not defined if `NO_WOLFSPDM_MEAS`)*
- `WOLFSPDM_HAS_CHALLENGE` *(not defined if `NO_WOLFSPDM_CHALLENGE`)*
- `WOLFSPDM_HAS_HEARTBEAT`
- `WOLFSPDM_HAS_KEY_UPDATE`

## Size and protocol constants

From `wolfspdm/spdm.h` and `wolfspdm/spdm_types.h`:

- `WOLFSPDM_CTX_STATIC_SIZE` = `32768`
- `WOLFSPDM_MAX_MSG_SIZE` = `4096`
- `WOLFSPDM_MAX_CERT_CHAIN` = `4096`
- `WOLFSPDM_MAX_TRANSCRIPT` = `4096`

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
