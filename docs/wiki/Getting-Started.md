# Getting Started

## Prerequisites

wolfSPDM depends on wolfSSL/wolfCrypt with SPDM-required algorithms enabled.

Minimum validated wolfSSL version: **v5.8.0-stable**.

Example wolfSSL build:

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

## Build wolfSPDM

```bash
./autogen.sh
./configure --with-wolfssl=/usr/local
make
make check
```

### Configure options

| Option | Description |
|--------|-------------|
| `--with-wolfssl=PATH` | Path to wolfSSL headers/libs |
| `--enable-debug` | Enables debug build flags and `WOLFSPDM_DEBUG` |
| `--enable-dynamic-mem` | Enables heap-allocated context APIs (`wolfSPDM_New`) |

## Memory modes

### Static mode (default)

Zero-malloc operation with caller-managed context memory:

```c
byte spdmBuf[WOLFSPDM_CTX_STATIC_SIZE];
WOLFSPDM_CTX* ctx = (WOLFSPDM_CTX*)spdmBuf;
wolfSPDM_InitStatic(ctx, sizeof(spdmBuf));
```

`WOLFSPDM_CTX_STATIC_SIZE` is 32768 bytes.

### Dynamic mode (optional)

Enable with `--enable-dynamic-mem`, then:

```c
WOLFSPDM_CTX* ctx = wolfSPDM_New();
```

## Minimal connection flow

1. Initialize context (`wolfSPDM_Init` or `wolfSPDM_InitStatic`)
2. Register transport callback with `wolfSPDM_SetIO`
3. Optionally set trust root with `wolfSPDM_SetTrustedCAs`
4. Establish session with `wolfSPDM_Connect`
5. Exchange secured data using `wolfSPDM_SecuredExchange` (or send/receive helpers)
6. End session with `wolfSPDM_Disconnect`
7. Cleanup via `wolfSPDM_Free`

## Transport callback contract

All transport is caller-owned through:

```c
typedef int (*WOLFSPDM_IO_CB)(WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz,
    void* userCtx);
```

The callback sends raw SPDM/SPDM-secured records and returns the responder message.
