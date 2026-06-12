# Supported Operations

wolfSPDM implements requester-side SPDM operations for session establishment, secure data exchange, attestation, and session maintenance.

## Operation coverage

| Operation | SPDM area | wolfSPDM API |
|----------|-----------|--------------|
| Version negotiation | GET_VERSION | `wolfSPDM_GetVersion` |
| Capability negotiation | GET_CAPABILITIES | `wolfSPDM_GetCapabilities` |
| Algorithm negotiation | NEGOTIATE_ALGORITHMS | `wolfSPDM_NegotiateAlgorithms` |
| Certificate digest retrieval | GET_DIGESTS | `wolfSPDM_GetDigests` |
| Certificate chain retrieval | GET_CERTIFICATE | `wolfSPDM_GetCertificate` |
| Session key exchange | KEY_EXCHANGE | `wolfSPDM_KeyExchange` |
| Session finalization | FINISH | `wolfSPDM_Finish` |
| One-shot full connect | Full handshake | `wolfSPDM_Connect` |
| Secured app exchange | Secured messages | `wolfSPDM_SecuredExchange` |
| App send/receive helpers | Secured messages | `wolfSPDM_SendData`, `wolfSPDM_ReceiveData` |
| Measurements (signed/unsigned) | GET_MEASUREMENTS | `wolfSPDM_GetMeasurements` |
| Measurement block access | Measurement parsing | `wolfSPDM_GetMeasurementCount`, `wolfSPDM_GetMeasurementBlock` |
| Sessionless challenge auth | CHALLENGE / CHALLENGE_AUTH | `wolfSPDM_Challenge` |
| Keep-alive | HEARTBEAT | `wolfSPDM_Heartbeat` |
| Session key rotation | KEY_UPDATE | `wolfSPDM_KeyUpdate` |

## Supported protocol versions

- SPDM 1.2 (`0x12`)
- SPDM 1.3 (`0x13`)
- SPDM 1.4 (`0x14`)

Maximum negotiated version can be capped with `wolfSPDM_SetMaxVersion`.

## Fixed cryptographic profile (Algorithm Set B)

- Hash: SHA-384
- Asymmetric signature: ECDSA P-384
- Key exchange: ECDHE secp384r1
- AEAD: AES-256-GCM
- Key schedule: SPDM key schedule + HKDF-SHA384

## Post-quantum cryptography (SPDM 1.4, optional)

When built against a wolfSSL with the matching support, wolfSPDM adds two
independent post-quantum capabilities, each dual-stacked with the classical
profile so the responder selects one:

- **Signatures (ML-DSA, FIPS 204):** advertises **ML-DSA-44 / 65 / 87** in the
  1.4 `PqcAsymAlgo` field alongside ECDSA P-384; verifies whichever was
  negotiated. See [[Post-Quantum ML-DSA]].
- **Key exchange (ML-KEM, FIPS 203):** advertises **ML-KEM-512 / 768 / 1024**
  as a `KEMAlg` struct alongside the ECDHE group; sends the encapsulation key and
  decapsulates the responder's ciphertext. Standalone (not hybrid). See
  [[Post-Quantum ML-KEM]].

Enabling both yields a **fully post-quantum SPDM handshake** (ML-KEM key
exchange + ML-DSA authentication). Large responses (e.g. an ML-DSA-87 signature,
or ML-DSA + the ML-KEM ciphertext, exceeding the negotiated `DataTransferSize`)
are reassembled with **SPDM 1.2 message chunking** (`CHUNK_GET`); see
[[Message Chunking]].

## Notable implementation scope

- Requester-only implementation (no responder role)
- Designed for standards-based SPDM peers and DMTF spdm-emu
- Trust anchor support via `wolfSPDM_SetTrustedCAs` (single DER CA cert buffer)
