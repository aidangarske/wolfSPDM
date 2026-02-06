# wolfSPDM

Lightweight SPDM 1.2+ requester-only stack implenation using wolfSSL/wolfCrypt

## Overview

- SPDM 1.2 requester implementation
- Algorithm Set B (FIPS 140-3 Level 3): ECDSA/ECDHE P-384, SHA-384, AES-256-GCM, HKDF-SHA384
- Hardware SPDM via wolfTPM + Nuvoton TPM
- Full transcript tracking for TH1/TH2 computation
- Compatible with DMTF libspdm emulator for interoperability testing
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

## Testing with swpdm-emu Emulator

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

# Terminal 1: Start responder
cd spdm-emu
./bin/spdm_responder_emu --trans TCP

# Terminal 2: Run wolfTPM example tests you want
cd wolfTPM
./examples/spdm/spdm_demo --help
```

## Testing with Nuvoton NC75x

```bash
# Build wolfSPDM
cd wolfSPDM
./configure --enable-nuvoton
make

# Build wolfTPM
cd wolfTPM
./configure --enable-spdm --enable-nuvoton --with-wolfspdm=path/to/wolfspdm
make

# Terminal 2: Run wolfTPM example tests you want
./examples/spdm/spdm_demo --help
```

## API Reference

| Function | Description |
|---|---|
| `wolfSPDM_New()` | Allocate new context |
| `wolfSPDM_Init()` | Initialize context |
| `wolfSPDM_Free()` | Free context |
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
