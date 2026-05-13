# wolfSPDM

wolfSPDM is a lightweight C library implementing [SPDM 1.2 / 1.3 / 1.4](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.4.0.pdf) and [Secured Messages over MCTP (DSP0277)](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.2.0.pdf) using [wolfSSL](https://www.wolfssl.com/) as the crypto backend. It is a standalone, requester-only stack designed for embedded use, tested end-to-end against the DMTF [spdm-emu](https://github.com/DMTF/spdm-emu) emulator.

## Main Features

- **Standard SPDM 1.2 / 1.3 / 1.4 requester** per DMTF DSP0274 and DSP0277
- **Algorithm Set B fixed:** ECDSA P-384, ECDHE P-384, SHA-384, AES-256-GCM, HKDF-SHA384
- **Zero-malloc by default:** static memory, ~32 KB context, ideal for constrained/embedded environments
- **Optional `--enable-dynamic-mem`** for heap-allocated contexts on small-stack platforms
- **Full session lifecycle:** key exchange, finish, encrypted messaging, heartbeat keep-alive, key update
- **Device attestation:** signed / unsigned `GET_MEASUREMENTS`, sessionless `CHALLENGE_AUTH`, certificate-chain validation against trusted root CAs
- **Compatible with DMTF spdm-emu** for interoperability testing (18-test matrix across 1.2 / 1.3 / 1.4)
- **Path to FIPS 140-3** via wolfCrypt FIPS Certificate #4718 (sole crypto dependency)

## Supported Operations (RFC / DSP0274)

| Operation | DSP0274 | wolfSPDM API |
|---|---|---|
| Session establishment | Sec. 10.7 | `wolfSPDM_Connect`, `wolfSPDM_KeyExchange`, `wolfSPDM_Finish` |
| Encrypted application data | DSP0277 | `wolfSPDM_SecuredExchange`, `wolfSPDM_SendData`, `wolfSPDM_ReceiveData` |
| Measurements (signed/unsigned) | Sec. 10.11 | `wolfSPDM_GetMeasurements`, `wolfSPDM_GetMeasurementBlock` |
| Challenge authentication (sessionless) | Sec. 10.8 | `wolfSPDM_Challenge` |
| Session keep-alive | Sec. 10.10 | `wolfSPDM_Heartbeat` |
| Session key rotation | Sec. 10.9 | `wolfSPDM_KeyUpdate` |
| Trust anchor | Sec. 10.6 | `wolfSPDM_SetTrustedCAs` |

## Prerequisites (wolfSSL)

wolfSPDM requires [wolfSSL](https://www.wolfssl.com/) configured with ECC P-384, SHA-384, AES-GCM, and HKDF:

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-ecc --enable-sha384 \
            --enable-aesgcm --enable-hkdf --enable-sp
make
sudo make install
sudo ldconfig
```

`--enable-sp` enables Single Precision math with optimized ECC P-384, required for SPDM Algorithm Set B on ARM64 and other constrained targets. `--enable-all` works as a superset.

## Build

```bash
./autogen.sh
./configure
make
make check
```

### Configure Options

| Option | Description |
|---|---|
| `--enable-debug` | Debug output with `-g -O0` (default: `-O2`) |
| `--enable-dynamic-mem` | Use heap allocation for `WOLFSPDM_CTX` (default: static) |
| `--with-wolfssl=PATH` | wolfSSL installation path |

### Memory Modes

**Static (default):** zero heap allocation. The caller provides a buffer (`WOLFSPDM_CTX_STATIC_SIZE` bytes, ~32 KB) and wolfSPDM operates entirely within it. Ideal for embedded and constrained environments where malloc is unavailable or undesirable.

```c
#include <wolfspdm/spdm.h>

byte spdmBuf[WOLFSPDM_CTX_STATIC_SIZE];
WOLFSPDM_CTX* ctx = (WOLFSPDM_CTX*)spdmBuf;
wolfSPDM_InitStatic(ctx, sizeof(spdmBuf));
/* ... use ctx ... */
wolfSPDM_Free(ctx);
```

**Dynamic (`--enable-dynamic-mem`):** context is heap-allocated via `wolfSPDM_New()`. Useful on platforms with small stacks where a ~32 KB local variable is impractical.

```c
#include <wolfspdm/spdm.h>

WOLFSPDM_CTX* ctx = wolfSPDM_New();
/* ... use ctx ... */
wolfSPDM_Free(ctx);  /* frees heap memory */
```

## Quick Start

`examples/spdm_demo` is a CLI driver that exercises each SPDM operation against `spdm-emu` over TCP/MCTP:

```bash
# Build the DMTF spdm-emu emulator
git clone --recursive https://github.com/DMTF/spdm-emu.git
cd spdm-emu && mkdir build && cd build
cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls ..
make copy_sample_key && make

# Run the 18-test integration matrix from this repo
export SPDM_EMU_PATH=../spdm-emu/build/bin
./examples/spdm_test.sh
```

The driver starts/stops `spdm_responder_emu` per test and runs six scenarios — Session, Signed Measurements, Unsigned Measurements, Challenge, Heartbeat, Key Update — across SPDM 1.2, 1.3, and 1.4 (18 tests total).

## API Reference

| Function | Description |
|---|---|
| `wolfSPDM_InitStatic()` | Initialize context in caller-provided buffer (static mode) |
| `wolfSPDM_New()` | Allocate and initialize context on heap (dynamic mode) |
| `wolfSPDM_Init()` | Initialize a pre-allocated context |
| `wolfSPDM_Free()` | Free context (releases resources; frees heap only if dynamic) |
| `wolfSPDM_GetCtxSize()` | Return `sizeof(WOLFSPDM_CTX)` at runtime |
| `wolfSPDM_SetIO()` | Set transport I/O callback |
| `wolfSPDM_SetDebug()` | Enable/disable debug output |
| `wolfSPDM_SetMaxVersion()` | Runtime cap on the highest SPDM version to negotiate |
| `wolfSPDM_Connect()` | Full SPDM handshake (`GET_VERSION` -> `FINISH`) |
| `wolfSPDM_IsConnected()` | Check session status |
| `wolfSPDM_Disconnect()` | End session |
| `wolfSPDM_SecuredExchange()` | Combined encrypted send/receive |
| `wolfSPDM_SendData()` / `wolfSPDM_ReceiveData()` | Application data over an established session |
| `wolfSPDM_SetTrustedCAs()` | Load the trusted root CA certificate for chain validation |
| `wolfSPDM_GetMeasurements()` | Retrieve device measurements with optional signature verification |
| `wolfSPDM_GetMeasurementCount()` / `wolfSPDM_GetMeasurementBlock()` | Access individual measurement block data |
| `wolfSPDM_Challenge()` | Sessionless device attestation via `CHALLENGE` / `CHALLENGE_AUTH` |
| `wolfSPDM_Heartbeat()` | Session keep-alive (`HEARTBEAT` / `HEARTBEAT_ACK`) |
| `wolfSPDM_KeyUpdate()` | Rotate session encryption keys (`KEY_UPDATE` / `KEY_UPDATE_ACK`) |
| `wolfSPDM_GetSessionId()` | Combined req/rsp session ID; available from `KEY_EXCHANGE_RSP` onward so I/O callbacks can distinguish the encrypted `FINISH` record from plaintext handshake messages |
| `wolfSPDM_GetNegotiatedVersion()` | Negotiated SPDM version (e.g. 0x12, 0x13, 0x14). The old spelling `wolfSPDM_GetVersion_Negotiated` is kept as an exported ABI-compat alias |
| `wolfSPDM_GetLastPeerError()` | Last `SPDM_ERROR` code received from the responder, for retry/backoff logic |

## CI / Testing

Runs on every push and PR:

- **Build + Test**: Ubuntu 22.04 / 24.04, debug and release, static-mem and `--enable-dynamic-mem`
- **Multi-compiler**: GCC 11-13 and Clang 14-17 with `-Wall -Wextra -Werror`
- **Compiler Warnings**: strict `-Wpedantic -Werror -Wconversion -Wshadow`
- **Static Analysis**: cppcheck and Clang Static Analyzer (`scan-build`)
- **CodeQL Security**: weekly + per-PR analysis
- **Memory Check**: Valgrind `--leak-check=full` (static and dynamic mem)
- **SPDM Emulator Integration**: 18-test matrix (6 scenarios x SPDM 1.2 / 1.3 / 1.4) across ubuntu-22.04 x64, ubuntu-24.04 x64, and ubuntu-24.04-arm aarch64
- **Skoll review**: wolfSSL deep-review pipeline, pre-merge security and code review

## Relationship to wolfTPM's SPDM

wolfTPM ships its own SPDM implementation in `src/spdm/` for hardware-backed responders (Nuvoton NPCT75x, NSING NS350) with PSK / TCG-binding extensions. **wolfSPDM is a separate implementation** focused on the standard DSP0274 / DSP0277 requester for embedded use with `spdm-emu` and any standards-compliant peer. The two share heritage but solve different problems:

| | wolfSPDM | wolfTPM `src/spdm/` |
|---|---|---|
| Role | Requester only | Requester + responder |
| Scope | Pure standard SPDM 1.2 / 1.3 / 1.4 | Same, plus PSK / TCG / Nuvoton / Nations vendor bindings |
| Target | Embedded / spdm-emu / generic SPDM peer | TPM hardware (Nuvoton, NS350) |
| Footprint | ~32 KB context, zero-malloc | Larger; includes TPM stack |

Either library can be used standalone; they aren't link-time compatible.

## License

wolfSPDM is free software licensed under the [GPLv3](https://www.gnu.org/licenses/gpl-3.0.html).

Copyright (C) 2006-2026 wolfSSL Inc.

## Support

> **Note:** wolfSPDM is currently maintained by wolfSSL developers but is not yet classified as an officially supported product. It was designed from the ground up to meet the same quality standards as the rest of the wolfSSL suite with future adoption in mind. We are eager to transition this to a fully supported product as demand grows; if your organization requires official support, has specific feature requirements, or just has general questions or guidance with the product, please reach out.

For commercial licensing, professional support contracts, or to discuss moving wolfSPDM into your production environment, contact [wolfSSL](https://www.wolfssl.com/contact/).
