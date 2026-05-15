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
- DHE: secp384r1
- AEAD: AES-256-GCM
- Key schedule: SPDM key schedule + HKDF-SHA384

## Notable implementation scope

- Requester-only implementation (no responder role)
- Designed for standards-based SPDM peers and DMTF spdm-emu
- Trust anchor support via `wolfSPDM_SetTrustedCAs` (single DER CA cert buffer)
