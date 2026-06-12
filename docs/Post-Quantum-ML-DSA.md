# Post-Quantum ML-DSA

SPDM 1.4 (DMTF DSP0274 1.4.0) adds post-quantum cryptography: **ML-DSA**
(FIPS 204) for signatures and **ML-KEM** (FIPS 203) for key exchange. wolfSPDM
implements the requester side of **ML-DSA signature verification**, dual-stacked
alongside the classical ECDSA P-384 profile.

All three parameter sets work over the wire: ML-DSA-87's larger responses are
reassembled with **SPDM 1.2 message chunking** ([[Message Chunking]]). ML-KEM
**key exchange** is also implemented ([[Post-Quantum ML-KEM]]); combining the two
gives a **fully post-quantum SPDM handshake** (ML-KEM key exchange + ML-DSA
authentication, no classical asymmetric crypto).

## How negotiation works

In `NEGOTIATE_ALGORITHMS`, wolfSPDM advertises ECDSA P-384 in `BaseAsymAlgo`
**and** ML-DSA-44 / ML-DSA-65 / ML-DSA-87 in the SPDM 1.4 `PqcAsymAlgo` field
(8-byte field at offset 16). Per DSP0274 1.4, the responder selects exactly one
signature algorithm across `BaseAsymSel` and `PqcAsymSel` (offset 20 in
`ALGORITHMS`). wolfSPDM records the choice, pins the certificate's parameter set
to it, and verifies `KEY_EXCHANGE_RSP`, `CHALLENGE_AUTH`, and signed
`MEASUREMENTS` with whichever family was negotiated.

| PqcAsymSel bit | Algorithm | SigLen | Public key |
|----------------|-----------|--------|------------|
| `0x01` | ML-DSA-44 | 2420 B | 1312 B |
| `0x02` | ML-DSA-65 | 3309 B | 1952 B |
| `0x04` | ML-DSA-87 | 4627 B | 2592 B |

## Signing construction (DSP0274 1.4 §15.5)

ML-DSA uses **Algorithm 2 (pure `ML-DSA.Sign`)**, not the pre-hash variant:

- `M = combined_spdm_prefix || message_hash`
  - `combined_spdm_prefix` = `"dmtf-spdm-v1.4.*"` ×4, zero-pad, `spdm_context`
    (100 bytes)
  - `message_hash` = SHA-384 of the data to be signed (the negotiated
    `BaseHashSel`)
- ML-DSA `ctx` parameter = `spdm_context` (the `"responder-<context> signing"`
  string)

wolfSPDM verifies with `wc_MlDsaKey_VerifyCtx(key, sig, sigLen, ctx, ctxLen, M,
mLen, &res)`. Public keys are imported from the leaf certificate with
`wc_MlDsaKey_PublicKeyDecode`, pinned to the negotiated parameter set.

## Building

ML-DSA follows the linked wolfSSL automatically: it is enabled when wolfSSL
reports `WOLFSSL_HAVE_MLDSA` and provides the `wc_MlDsaKey` context API (wolfSSL
master or a release that ships it; build wolfSSL with `--enable-mldsa`). The
capability is detected at configure time — wolfSPDM does not gate on a wolfSSL
version number, since master and the matching stable can report the same
`LIBWOLFSSL_VERSION_HEX`.

```sh
# wolfSSL with ML-DSA
./configure --enable-ecc --enable-sha384 --enable-aesgcm --enable-hkdf \
            --enable-sp --enable-mldsa --prefix=$HOME/wolfssl-install
make && make install

# wolfSPDM (ML-DSA auto-enabled; --enable-mldsa asserts it, --disable-mldsa off)
./configure --with-wolfssl=$HOME/wolfssl-install
make && make check
```

The configure summary prints `ML-DSA: enabled|disabled`.

## Memory note

PQC signatures, public keys, and certificate chains are multi-kilobyte, so the
buffer and static-context sizes grow when ML-DSA is built in (see
[[Configuration and Macros]]). The signature-bearing responses also use larger
on-stack receive buffers in ML-DSA builds — `wolfSPDM_GetMeasurements` uses
`WOLFSPDM_MAX_MSG_SIZE` (8 KB) and `wolfSPDM_KeyExchange` /
`wolfSPDM_Challenge` use `WOLFSPDM_SIG_RSP_BUF` (~5.3 KB) — so size embedded
thread/task stacks accordingly. ML-DSA-44 and ML-DSA-65 responses fit a single
SPDM message at the common DataTransferSize (spdm-emu uses 4608 B). ML-DSA-87
responses (sig 4627 B) exceed that, so the responder splits them and wolfSPDM
reassembles via CHUNK_GET — see [[Message Chunking]] for the engine and its
compile-time knobs.

## References

- DMTF DSP0274 1.4.0 — SPDM Specification (§15 SPDMsign, §15.5 ML-DSA, Tables 19/20)
- NIST FIPS 204 — ML-DSA; FIPS 203 — ML-KEM
- wolfSSL `wc_mldsa.h` — `wc_MlDsaKey_*` API
