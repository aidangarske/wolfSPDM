# Message Chunking (CHUNK_GET)

SPDM 1.2 added a *Large SPDM message transfer mechanism* (DSP0274 Sec. 10.27):
when a response is larger than the requester's `DataTransferSize`, the responder
returns `ERROR(LargeResponse)` and the requester fetches the message in pieces
with `CHUNK_GET` / `CHUNK_RESPONSE`, then reassembles it. wolfSPDM implements the
requester (CHUNK_GET) side.

This is what lets ML-DSA-87 work over the wire: its KEY_EXCHANGE_RSP /
CHALLENGE_AUTH / signed MEASUREMENTS (~4.7–4.8 KB) exceed the common
DataTransferSize (spdm-emu advertises 4608 B), so the responder chunks them.

## How it works

- In GET_CAPABILITIES wolfSPDM advertises `CHUNK_CAP` and a `DataTransferSize`
  equal to the **MTU** (`WOLFSPDM_CHUNK_BUF_SIZE`). The responder splits any
  response larger than that.
- Reassembly is **transparent**: it hooks the two transport functions
  (`wolfSPDM_SendReceive` for cleartext KEY_EXCHANGE / CHALLENGE, and
  `wolfSPDM_SecuredExchange` for the encrypted GET_MEASUREMENTS), so every parser
  sees a complete logical message and the transcript/hash stay correct. The chunk
  transport messages themselves are not hashed.
- **Zero dynamic allocation**: a single fixed `WOLFSPDM_CHUNK_BUF_SIZE` buffer in
  the context holds one CHUNK_RESPONSE; the reassembled message lands in the
  caller's existing message buffer.

The `ChunkSeqNo` field is `u16` for SPDM < 1.4 and `u32` for ≥ 1.4; wolfSPDM
emits the version-appropriate form. The first chunk (`ChunkSeqNo == 0`) carries
`LargeMessageSize`, which is bounds-checked against the output buffer.

## Compile-time configuration

| Macro / option | Default | Effect |
|----------------|---------|--------|
| `--disable-chunking` / `WOLFSPDM_NO_CHUNK` | enabled | Compile the engine out entirely (no `CHUNK_CAP` advertised) |
| `WOLFSPDM_CHUNK_BUF_SIZE` | `4096` | MTU = advertised DataTransferSize = transport buffer size. Lower it for constrained devices (smaller buffer, more round-trips) |
| `WOLFSPDM_CHUNK_NO_SECURED` | — | Keep cleartext chunking but compile out the encrypted (in-session MEASUREMENTS) path |
| `WOLFSPDM_CHUNK_MAX_CHUNKS` | `64` | Reassembly loop guard (max chunks per message) |

The configure summary prints `Chunking: enabled|disabled`.

## References

- DMTF DSP0274 1.4.0 — Sec. 10.27 (Large SPDM message transfer), Tables 68 / 101–105
- `ERROR(LargeResponse)` = error code `0x0F`; `CHUNK_GET` = `0x86`,
  `CHUNK_RESPONSE` = `0x06`; `CHUNK_CAP` = `0x00020000`
