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

`WOLFSPDM_CHUNK_BUF_SIZE` has a hard floor of 64 (it must hold a CHUNK_RESPONSE
header plus payload).

## Memory and interop notes

- **Advertised DataTransferSize drops to the MTU.** With chunking enabled,
  GET_CAPABILITIES advertises `DataTransferSize = WOLFSPDM_CHUNK_BUF_SIZE` (4096
  by default) rather than `WOLFSPDM_MAX_MSG_SIZE`. This is the intended
  constrained-device tradeoff — the responder chunks anything larger. A
  responder that does **not** implement `CHUNK_CAP` must then keep every single
  response within that MTU; raise `WOLFSPDM_CHUNK_BUF_SIZE` if you need a larger
  single-message limit while still reassembling anything above it. Raising it
  also enlarges the in-context `chunkBuf`, so bump `WOLFSPDM_CTX_STATIC_SIZE`
  to match (a `_Static_assert` in `spdm_context.c` enforces this at compile
  time — in ML-DSA builds the context already sits ~1 KB under the default cap).
- **Secured path stack.** In-session reassembly (GET_MEASUREMENTS) encrypts each
  CHUNK_GET and decrypts each CHUNK_RESPONSE. Nested under
  `wolfSPDM_SecuredExchange`'s frame plus the AEAD scratch buffers, peak stack
  approaches ~30 KB in ML-DSA builds during a chunked GET_MEASUREMENTS (it
  scales with `WOLFSPDM_MAX_MSG_SIZE` and `WOLFSPDM_CHUNK_BUF_SIZE`). Lower the
  MTU or use `WOLFSPDM_CHUNK_NO_SECURED` on stack-constrained targets.
- **Untrusted input.** Every CHUNK_RESPONSE byte is responder-controlled; the
  reassembler validates `ChunkSize` with overflow-safe (subtraction) bounds,
  echoes of `Handle`/`ChunkSeqNo`, and the per-message and total length before
  any copy.

## Why CHUNK_GET only (no CHUNK_SEND)

The mechanism has two directions, controlled by different endpoints:

- `CHUNK_GET` pulls a large **response** the responder chose to split. The
  requester has no control over a responder's reply size (an ML-DSA-87 signature
  is 4627 B regardless), so it must be able to reassemble one. wolfSPDM
  implements this.
- `CHUNK_SEND` pushes a large **request** in pieces. This is requester-initiated:
  the requester decides to chunk its own outbound request; a responder cannot
  force it.

Every request wolfSPDM builds (GET_VERSION through GET_MEASUREMENTS,
KEY_EXCHANGE, FINISH) is small and fixed, well under any responder's
`DataTransferSize`, so `CHUNK_SEND` is never needed — it is not applicable to
this library's traffic rather than missing. `CHUNK_CAP` advertises support for
the large-message mechanism; it does not obligate an endpoint to chunk requests
it never sends, so a requester that only emits small requests is fully
conformant supporting `CHUNK_GET` alone. `CHUNK_SEND` / `CHUNK_SEND_ACK` are
defined in `spdm_types.h` for completeness but intentionally unimplemented.

## References

- DMTF DSP0274 1.4.0 — Sec. 10.27 (Large SPDM message transfer), Tables 68 / 101–105
- `ERROR(LargeResponse)` = error code `0x0F`; `CHUNK_GET` = `0x86`,
  `CHUNK_RESPONSE` = `0x06`; `CHUNK_CAP` = `0x00020000`
