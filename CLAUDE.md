# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

wolfSPDM is a lightweight SPDM 1.2/1.3/1.4 requester (initiator) implementation using wolfCrypt for cryptographic operations. It provides authenticated and encrypted communication with SPDM responders per DMTF DSP0274/DSP0277 specifications, tested against the DMTF spdm-emu emulator.

**Key characteristics:**
- Standard SPDM 1.2 / 1.3 / 1.4 negotiation
- Algorithm Set B only: ECDSA P-384, ECDHE P-384, SHA-384, AES-256-GCM, HKDF-SHA384
- Zero-malloc by default (static memory ~28KB context), optional `--enable-dynamic-mem` for heap allocation
- Requester-only - pair with any SPDM responder (e.g. spdm-emu)

## Build Commands

```bash
./autogen.sh                              # Generate configure script
./configure --with-wolfssl=/usr/local     # Configure (adjust wolfSSL path as needed)
make                                      # Build library
make check                                # Run unit tests
sudo make install                         # Install library
```

**Configure options:**
- `--enable-debug` - Debug output with -g -O0 (default: -O2)
- `--enable-dynamic-mem` - Use heap allocation for WOLFSPDM_CTX (default: static/zero-malloc)
- `--with-wolfssl=PATH` - wolfSSL installation path

## Testing

**Unit tests:**
```bash
make check                    # Runs test/unit_test
./test/unit_test              # Run directly
```

**Integration test (requires DMTF spdm-emu):**
```bash
export SPDM_EMU_PATH=../spdm-emu/build/bin
./examples/spdm_test.sh       # Runs 18 tests (6 scenarios x SPDM 1.2/1.3/1.4)
```

The script starts/stops `spdm_responder_emu` per test and runs session
establishment, signed measurements, unsigned measurements, challenge
authentication, heartbeat, and key update.

## Architecture

### Source Organization
```
src/                      # Core implementation
  spdm_context.c          # Context lifecycle (New/Init/Free)
  spdm_msg.c              # Message building/parsing
  spdm_crypto.c           # ECC operations
  spdm_kdf.c              # HKDF key derivation
  spdm_transcript.c       # Transcript buffer for TH1/TH2
  spdm_secured.c          # AES-256-GCM encryption/decryption
  spdm_session.c          # Session management
  spdm_internal.h         # Internal declarations

wolfspdm/                 # Public API headers
  spdm.h                  # Main API
  spdm_types.h            # Protocol constants
  spdm_error.h            # Error codes

examples/
  spdm_demo.c             # CLI demo: --emu/--meas/--challenge/--heartbeat/--key-update
  spdm_test.sh            # Integration test driver (runs 18 tests against spdm-emu)

test/
  unit_test.c             # Unit tests
  test_spdm.c             # Smoke test (single session against emu)
```

### Protocol State Machine
```
INIT -> VERSION -> CAPS -> ALGO -> DIGESTS -> CERT -> KEY_EX -> FINISH -> CONNECTED -> MEASURED
```

### Key Patterns

**Return codes:** 0 = success, negative = error (see `spdm_error.h`)

**Buffer pattern:** Output size is input capacity and output actual size:
```c
int func(..., byte* buf, word32* bufSz);
```

**Transport abstraction:** I/O callback handles all transport:
```c
typedef int (*WOLFSPDM_IO_CB)(WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz,
    void* userCtx);
```

**Memory:** Zero-malloc by default (static context via `wolfSPDM_InitStatic()`). With `--enable-dynamic-mem`, uses XMALLOC/XFREE macros (wolfCrypt convention) for heap allocation via `wolfSPDM_New()`. Fixed-size internal buffers (4KB max message/cert/transcript).

### Cryptographic Constants
- Hash: 48 bytes (SHA-384)
- ECC key: 48 bytes, point: 96 bytes, signature: 96 bytes (P-384)
- AEAD: 32-byte key, 12-byte IV, 16-byte tag (AES-256-GCM)

## Dependencies

wolfSSL/wolfCrypt configured with: `--enable-wolftpm --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf --enable-sp`

**Build order:** wolfSSL (install) -> wolfSPDM (build). `WOLFSPDM_CTX_STATIC_SIZE` depends on wolfSSL internal struct sizes (`ecc_key`, `wc_Sha384`, `WC_RNG`), so wolfSPDM must be rebuilt whenever wolfSSL config changes.
