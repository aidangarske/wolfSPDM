# wolfSPDM Documentation

Welcome to the wolfSPDM wiki. This documentation covers wolfSPDM, a lightweight requester-only SPDM implementation for embedded systems and constrained environments.

## What is wolfSPDM?

wolfSPDM is a C library implementing:
- **SPDM 1.2 / 1.3 / 1.4** ([DMTF DSP0274](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.4.0.pdf))
- **Secured Messages over MCTP** ([DMTF DSP0277](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.2.0.pdf))

It uses [wolfSSL / wolfCrypt](https://www.wolfssl.com/) as its crypto backend and is tested end-to-end against the DMTF [spdm-emu](https://github.com/DMTF/spdm-emu) responder emulator.

## Key Features

| Feature | Description |
|---------|-------------|
| Requester-only SPDM stack | Purpose-built initiator implementation |
| SPDM 1.2/1.3/1.4 | Standards-based negotiation and session setup |
| Fixed Algorithm Set B | ECDSA P-384, ECDHE P-384, SHA-384, AES-256-GCM, HKDF-SHA384 |
| Post-quantum signatures (1.4) | Optional ML-DSA-44/65/87 (FIPS 204), dual-stacked with ECDSA P-384 |
| Post-quantum key exchange (1.4) | Optional ML-KEM-512/768/1024 (FIPS 203), advertised alongside ECDHE P-384 |
| Fully post-quantum handshake | ML-KEM key exchange + ML-DSA authentication, no classical asymmetric crypto |
| Message chunking | SPDM 1.2 CHUNK_GET reassembly over a fixed MTU buffer (zero-alloc) |
| Zero-malloc by default | Static context (`WOLFSPDM_CTX_STATIC_SIZE`, 32 KB; ~72 KB with ML-DSA) |
| Optional dynamic context | `--enable-dynamic-mem` enables `wolfSPDM_New()` |
| Attestation operations | Signed/unsigned `GET_MEASUREMENTS`, sessionless `CHALLENGE_AUTH` |
| Session operations | `HEARTBEAT`, `KEY_UPDATE`, secured app data transfer |
| CI + security coverage | Multi-compiler, static analysis, CodeQL, Valgrind, spdm-emu integration |

## Documentation

| Page | Description |
|------|-------------|
| [[Getting Started]] | Dependencies, build, install, and first connection flow |
| [[Supported Operations]] | Supported SPDM flows and operation/API mapping |
| [[Post-Quantum ML-DSA]] | SPDM 1.4 ML-DSA (FIPS 204) post-quantum signatures |
| [[Post-Quantum ML-KEM]] | SPDM 1.4 ML-KEM (FIPS 203) post-quantum key exchange + fully post-quantum handshake |
| [[Message Chunking]] | SPDM 1.2 CHUNK_GET reassembly of large responses |
| [[API Reference]] | Public API grouped by lifecycle and purpose |
| [[Configuration and Macros]] | Configure flags and compile-time feature controls |
| [[Testing and CI]] | Unit tests, emulator tests, and CI workflow coverage |
| [[Project Structure]] | Repository layout and module responsibilities |
| [[Attestation Notes]] | Measurement and challenge attestation details |

## Protocol Session Flow

The primary session establishment sequence is:

`GET_VERSION -> GET_CAPABILITIES -> NEGOTIATE_ALGORITHMS -> GET_DIGESTS -> GET_CERTIFICATE -> KEY_EXCHANGE -> FINISH`

After `FINISH`, secured messaging and maintenance operations are available.

## Quick Links

- [GitHub Repository](https://github.com/aidangarske/wolfSPDM)
- [README](https://github.com/aidangarske/wolfSPDM/blob/main/README.md)
- [DMTF DSP0274 (SPDM)](https://www.dmtf.org/sites/default/files/standards/documents/DSP0274_1.4.0.pdf)
- [DMTF DSP0277 (Secured Messages)](https://www.dmtf.org/sites/default/files/standards/documents/DSP0277_1.2.0.pdf)
- [wolfSSL Website](https://www.wolfssl.com/)

## License

wolfSPDM is free software licensed under GPLv3.
For commercial licensing and support, contact [wolfSSL](https://www.wolfssl.com/contact/).
