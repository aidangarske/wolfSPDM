# wolfSPDM Attestation (GET_MEASUREMENTS)

## Overview

wolfSPDM supports SPDM 1.2, 1.3, and 1.4 device attestation via
GET_MEASUREMENTS with optional cryptographic signature verification. This
enables a requester to retrieve firmware/hardware measurement blocks from
any SPDM-capable device and verify their authenticity.

Version-specific notes:
- **SPDM 1.3 and 1.4** add a 32-byte RequesterContext field in
  GET_MEASUREMENTS requests, which wolfSPDM populates automatically and
  echo-verifies in the response.
- The 18-test integration matrix exercises both signed and unsigned
  GET_MEASUREMENTS against the DMTF spdm-emu under each negotiated
  version (1.2 / 1.3 / 1.4).

The same protocol is used by:
- **GPUs** - NVIDIA uses SPDM over MCTP for GPU attestation
- **NICs** - BMC/iLO verify network cards
- **SSDs** - NVMe SPDM over DOE (Solidigm D7 series, etc.)
- **CXL memory devices**
- **Any PCIe device with CMA** (Component Measurement and Authentication)

## API Reference

### wolfSPDM_GetMeasurements

```c
int wolfSPDM_GetMeasurements(WOLFSPDM_CTX* ctx, byte measOperation,
    int requestSignature);
```

Retrieves measurements from the SPDM responder.

**Parameters:**
- `measOperation` - `SPDM_MEAS_OPERATION_ALL` (0xFF) for all measurements,
  or a specific 1-based index
- `requestSignature` - 1 to request signed measurements, 0 for unsigned

**Return values:**
- `WOLFSPDM_SUCCESS` - Measurements retrieved and signature **verified**
- `WOLFSPDM_E_MEAS_NOT_VERIFIED` - Measurements retrieved but not verified
  (unsigned request, or `NO_WOLFSPDM_MEAS_VERIFY` compiled out)
- `WOLFSPDM_E_MEAS_SIG_FAIL` - Signature verification **failed**

### wolfSPDM_GetMeasurementCount / wolfSPDM_GetMeasurementBlock

```c
int wolfSPDM_GetMeasurementCount(WOLFSPDM_CTX* ctx);
int wolfSPDM_GetMeasurementBlock(WOLFSPDM_CTX* ctx, int blockIdx,
    byte* measIndex, byte* measType, byte* value, word32* valueSz);
```

Access individual measurement blocks after retrieval.

### wolfSPDM_SendData / wolfSPDM_ReceiveData

```c
int wolfSPDM_SendData(WOLFSPDM_CTX* ctx, const byte* data, word32 dataSz);
int wolfSPDM_ReceiveData(WOLFSPDM_CTX* ctx, byte* data, word32* dataSz);
```

Send/receive application data over an established SPDM session.

## Build Configurations

| Configuration | Flag | Effect |
|---|---|---|
| Full (default) | - | Measurement retrieval + signature verification |
| No verification | `-DNO_WOLFSPDM_MEAS_VERIFY` | Retrieval only, no sig verify |
| No measurements | `-DNO_WOLFSPDM_MEAS` | Zero measurement code/RAM |

## Signature Verification

When `requestSignature=1` and verification is compiled in:

1. wolfSPDM sends GET_MEASUREMENTS with a 32-byte nonce
2. Responder returns measurements + ECDSA P-384 signature
3. wolfSPDM computes the L1/L2 transcript hash:
   - L1 = GET_MEASUREMENTS request (complete message)
   - L2 = MEASUREMENTS response (everything before the Signature field)
   - Per DSP0274: M = combined_spdm_prefix || zero_pad || context_str || Hash(L1||L2)
   - SignedData = Hash(M)
4. Verifies the signature using the responder's public key (extracted
   from the certificate chain during `wolfSPDM_Connect()`)

The nonce prevents replay attacks - each measurement request uses a fresh
random nonce that is included in the signed response.

## Testing with spdm-emu

Build and install [spdm-emu](https://github.com/DMTF/spdm-emu):

```bash
git clone https://github.com/DMTF/spdm-emu.git
cd spdm-emu && mkdir build && cd build
cmake .. && make
```

Run the automated test script in this repo:

```bash
# Runs 18 tests: session, signed/unsigned measurements, challenge,
# heartbeat, key update, each across SPDM 1.2 / 1.3 / 1.4.
export SPDM_EMU_PATH=../spdm-emu/build/bin
./examples/spdm_test.sh
```

The script automatically finds `spdm_responder_emu` via `SPDM_EMU_PATH` (or
`../spdm-emu/build/bin/`), starts/stops it per test, and verifies all the
test cases.

Expected output with `--meas`:
```
=== SPDM GET_MEASUREMENTS ===
Measurements retrieved and signature VERIFIED
Measurement blocks: 8
  [1] type=0x00 size=48: <hex digest>
  [2] type=0x01 size=48: <hex digest>
  ...
```

With `--meas --no-sig`:
```
=== SPDM GET_MEASUREMENTS ===
Measurements retrieved (not signature-verified)
Measurement blocks: 8
  ...
```

## Standalone Demo

`examples/spdm_demo` exercises the measurement flow against spdm-emu:

| Flag | Description |
|---|---|
| `--meas` | Establish session + retrieve all measurements with signature verification |
| `--no-sig` | Skip signature verification (use with `--meas`) |

## Security Notes

- **Signed + verified measurements** provide cryptographic proof that
  firmware/hardware state came from the authenticated responder
- **Replay protection** via fresh 32-byte nonce per request
- **Certificate chain validation** (chain-of-trust to root CA, expiry,
  revocation) is NOT yet implemented - signature is verified against the
  leaf certificate from session establishment. Full chain validation is
  a follow-up item
- **Parser security**: All fields from the untrusted responder are
  bounds-checked before use. Malformed responses return
  `WOLFSPDM_E_MEASUREMENT`
