# wolfSPDM

Lightweight SPDM 1.2+ requester-only stack implementation using wolfSSL/wolfCrypt

## Overview

- SPDM 1.2 requester implementation
- Algorithm Set B (FIPS 140-3 Level 3): ECDSA/ECDHE P-384, SHA-384, AES-256-GCM, HKDF-SHA384
- **Zero-malloc by default** — fully static memory, ideal for constrained/embedded environments
- Optional `--enable-dynamic-mem` for heap-allocated contexts (useful for small-stack platforms)
- Hardware SPDM via wolfTPM + Nuvoton TPM
- Full transcript tracking for TH1/TH2 computation
- Compatible with DMTF spdm-emu for interoperability testing
- **FIPS 140-3** (Certificate #4718) via wolfCrypt FIPS
- **DO-178C DAL A** via wolfCrypt DO-178 with wolfTPM

wolfSPDM supports hardware-backed SPDM through wolfTPM with Nuvoton TPM
integration, and requires no external dependencies beyond wolfSSL/wolfCrypt.

## Prerequisites

wolfSSL with the required crypto algorithms:

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure --enable-wolftpm --enable-all
or
./configure --enable-wolftpm --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf
make
sudo make install
sudo ldconfig
```

## Building

```bash
./autogen.sh
./configure
make
```

### Configure Options

| Option | Description |
|---|---|
| `--enable-debug` | Debug output with `-g -O0` (default: `-O2`) |
| `--enable-nuvoton` | Enable Nuvoton TPM support |
| `--enable-dynamic-mem` | Use heap allocation for WOLFSPDM_CTX (default: static) |
| `--with-wolfssl=PATH` | wolfSSL installation path |

### Memory Modes

**Static (default):** Zero heap allocation. The caller provides a buffer
(`WOLFSPDM_CTX_STATIC_SIZE` bytes, ~22 KB) and wolfSPDM operates entirely
within it. This is ideal for embedded and constrained environments where
malloc is unavailable or undesirable.

```c
#include <wolfspdm/spdm.h>

byte spdmBuf[WOLFSPDM_CTX_STATIC_SIZE];
WOLFSPDM_CTX* ctx = (WOLFSPDM_CTX*)spdmBuf;
wolfSPDM_InitStatic(ctx, sizeof(spdmBuf));
/* ... use ctx ... */
wolfSPDM_Free(ctx);
```

**Dynamic (`--enable-dynamic-mem`):** Context is heap-allocated via
`wolfSPDM_New()`. Useful on platforms with small stacks where a ~22 KB
local variable is impractical.

```c
#include <wolfspdm/spdm.h>

WOLFSPDM_CTX* ctx = wolfSPDM_New();
/* ... use ctx ... */
wolfSPDM_Free(ctx);  /* frees heap memory */
```

## Testing with spdm-emu Emulator

```bash
# Build emulator
git clone https://github.com/DMTF/spdm-emu.git
cd spdm-emu && mkdir build && cd build
cmake -DARCH=x64 -DTOOLCHAIN=GCC -DTARGET=Release -DCRYPTO=mbedtls ..
make copy_sample_key && make

# Build wolfSPDM
cd wolfSPDM
./configure
make

# Build wolfTPM
cd wolfTPM
./configure --enable-spdm --enable-swtpm --with-wolfspdm=path/to/wolfspdm
make

# Terminal 1: Start responder with Algorithm Set B
cd spdm-emu
./bin/spdm_responder_emu --ver 1.2 \
    --hash SHA_384 --asym ECDSA_P384 \
    --dhe SECP_384_R1 --aead AES_256_GCM

# Terminal 2: Run wolfTPM example
cd wolfTPM
./examples/spdm/spdm_demo --emu
```

## Testing with Nuvoton NPCT75x

```bash
# Build wolfSPDM
cd wolfSPDM
./configure --enable-nuvoton
make

# Build wolfTPM
cd wolfTPM
./configure --enable-spdm --enable-nuvoton --with-wolfspdm=path/to/wolfspdm
make

# Run test suite
./examples/spdm/spdm_test.sh
```

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
| `wolfSPDM_Connect()` | Full SPDM handshake |
| `wolfSPDM_IsConnected()` | Check session status |
| `wolfSPDM_Disconnect()` | End session |
| `wolfSPDM_EncryptMessage()` | Encrypt outgoing message |
| `wolfSPDM_DecryptMessage()` | Decrypt incoming message |
| `wolfSPDM_SecuredExchange()` | Combined send/receive |

## License

GPLv3 — see LICENSE file. Copyright (C) 2006-2025 wolfSSL Inc.
