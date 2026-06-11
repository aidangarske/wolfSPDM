/* spdm_chunk.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSPDM.
 *
 * wolfSPDM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfSPDM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#include "spdm_internal.h"

#ifdef WOLFSPDM_HAVE_CHUNK

/* DSP0274 Sec. 10.27.2: CHUNK_GET request.
 *   header: Param1 = Reserved, Param2 = Handle
 *   ChunkSeqNo: u16 for SPDM < 1.4, u32 for >= 1.4 */
int wolfSPDM_BuildChunkGet(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    byte handle, word32 seqNo)
{
    word32 need = (ctx != NULL && ctx->spdmVersion >= SPDM_VERSION_14) ? 8 : 6;

    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, need);

    buf[0] = ctx->spdmVersion;
    buf[1] = SPDM_CHUNK_GET;
    buf[2] = 0x00;          /* Param1 reserved */
    buf[3] = handle;        /* Param2 = Handle */
    if (ctx->spdmVersion >= SPDM_VERSION_14) {
        SPDM_Set32LE(&buf[4], seqNo);
    }
    else {
        SPDM_Set16LE(&buf[4], (word16)seqNo);
    }
    *bufSz = need;
    return WOLFSPDM_SUCCESS;
}

/* Cleartext transport for one CHUNK_GET -> CHUNK_RESPONSE into ctx->chunkBuf.
 * Uses the bare callback so the SendReceive chunk hook does not re-enter. */
static int wolfSPDM_ChunkXferCleartext(WOLFSPDM_CTX* ctx,
    const byte* tx, word32 txSz, word32* rxSz)
{
    *rxSz = (word32)sizeof(ctx->chunkBuf);
    return wolfSPDM_SendReceiveRaw(ctx, tx, txSz, ctx->chunkBuf, rxSz);
}

#ifndef WOLFSPDM_CHUNK_NO_SECURED
/* Secured (in-session) transport: encrypt CHUNK_GET, send, decrypt the
 * CHUNK_RESPONSE into ctx->chunkBuf. The on-stack encrypted buffers scale with
 * the MTU knob WOLFSPDM_CHUNK_BUF_SIZE. */
static int wolfSPDM_ChunkXferSecured(WOLFSPDM_CTX* ctx,
    const byte* tx, word32 txSz, word32* rxSz)
{
    byte enc[64];                                /* CHUNK_GET is <= 8 B + AEAD */
    byte encRx[WOLFSPDM_CHUNK_BUF_SIZE + 64];    /* encrypted CHUNK_RESPONSE */
    word32 encSz = sizeof(enc);
    word32 encRxSz = sizeof(encRx);
    int rc = wolfSPDM_EncryptInternal(ctx, tx, txSz, enc, &encSz);

    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_SendReceiveRaw(ctx, enc, encSz, encRx, &encRxSz);
    }
    if (rc == WOLFSPDM_SUCCESS) {
        *rxSz = (word32)sizeof(ctx->chunkBuf);
        rc = wolfSPDM_DecryptInternal(ctx, encRx, encRxSz, ctx->chunkBuf, rxSz);
    }
    return rc;
}
#endif /* !WOLFSPDM_CHUNK_NO_SECURED */

/* Reassemble a large response the responder split (DSP0274 Sec. 10.27.2).
 * The triggering ERROR(LargeResponse) carried the Handle; this drives the
 * CHUNK_GET loop, copying each chunk into the caller's outBuf until LastChunk.
 *
 * CHUNK_RESPONSE layout (data offsets are version-independent):
 *   [0..3]  header (Param1 = attributes, Param2 = Handle)
 *   [4..7]  ChunkSeqNo (u32 for 1.4; u16 + u16 reserved for < 1.4)
 *   [8..11] ChunkSize (u32)
 *   [12..15] LargeMessageSize (u32, only when ChunkSeqNo == 0)
 *   [12 or 16 ..] chunk bytes */
int wolfSPDM_ReassembleLargeResponse(WOLFSPDM_CTX* ctx, int secured,
    byte handle, byte* outBuf, word32 outBufSz, word32* outSz)
{
    byte txBuf[8];
    word32 txSz;
    word32 rxSz = 0;
    word32 seq = 0;
    word32 off = 0;
    word32 total = 0;
    word32 chunkSize;
    word32 dataOff;
    word32 seqEcho;
    word32 minSz;
    byte attrs;
    int last = 0;
    int rc;

    if (ctx == NULL || outBuf == NULL || outSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    while (!last) {
        if (seq >= WOLFSPDM_CHUNK_MAX_CHUNKS) {
            wolfSPDM_DebugPrint(ctx, "CHUNK: exceeded max chunks (%u)\n",
                (unsigned)WOLFSPDM_CHUNK_MAX_CHUNKS);
            return WOLFSPDM_E_CHUNK;
        }

        txSz = sizeof(txBuf);
        rc = wolfSPDM_BuildChunkGet(ctx, txBuf, &txSz, handle, seq);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

        if (secured) {
#ifndef WOLFSPDM_CHUNK_NO_SECURED
            rc = wolfSPDM_ChunkXferSecured(ctx, txBuf, txSz, &rxSz);
#else
            return WOLFSPDM_E_CHUNK;  /* secured chunking compiled out */
#endif
        }
        else {
            rc = wolfSPDM_ChunkXferCleartext(ctx, txBuf, txSz, &rxSz);
        }
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

        /* A mid-stream ERROR (e.g. the responder aborting the transfer) is a
         * valid 4-byte response; surface its code before the CHUNK_RESPONSE
         * length checks. */
        if (rxSz >= 4 && ctx->chunkBuf[1] == SPDM_ERROR) {
            ctx->lastPeerErrorCode = ctx->chunkBuf[2];
            wolfSPDM_DebugPrint(ctx, "CHUNK: responder ERROR 0x%02x\n",
                ctx->chunkBuf[2]);
            return WOLFSPDM_E_PEER_ERROR;
        }
        /* Minimum CHUNK_RESPONSE: header(4)+seq(4)+size(4); the first chunk
         * (seq 0) also carries LargeMessageSize, so require 4 more before
         * reading it. */
        minSz = (seq == 0) ? 16u : 12u;
        if (rxSz < minSz) {
            return WOLFSPDM_E_CHUNK;
        }
        if (ctx->chunkBuf[1] != SPDM_CHUNK_RESPONSE ||
            ctx->chunkBuf[3] != handle) {
            return WOLFSPDM_E_CHUNK;
        }
        attrs = ctx->chunkBuf[2];
        seqEcho = (ctx->spdmVersion >= SPDM_VERSION_14)
            ? SPDM_Get32LE(&ctx->chunkBuf[4])
            : (word32)SPDM_Get16LE(&ctx->chunkBuf[4]);
        if (seqEcho != seq) {
            return WOLFSPDM_E_CHUNK;
        }

        chunkSize = SPDM_Get32LE(&ctx->chunkBuf[8]);
        dataOff = 12;
        if (seq == 0) {
            total = SPDM_Get32LE(&ctx->chunkBuf[12]);
            dataOff = 16;
            if (total == 0 || total > outBufSz) {
                wolfSPDM_DebugPrint(ctx,
                    "CHUNK: LargeMessageSize %u exceeds buffer %u\n",
                    (unsigned)total, (unsigned)outBufSz);
                return WOLFSPDM_E_BUFFER_SMALL;
            }
        }

        /* chunkSize is fully responder-controlled. Validate with subtraction so
         * an oversized value cannot wrap an addition: dataOff <= rxSz (minSz)
         * and off <= total hold by construction, so the differences are safe. */
        if (chunkSize == 0 ||
            chunkSize > rxSz - dataOff ||
            chunkSize > total - off) {
            return WOLFSPDM_E_CHUNK;
        }
        XMEMCPY(outBuf + off, &ctx->chunkBuf[dataOff], chunkSize);
        off += chunkSize;

        last = (attrs & SPDM_CHUNK_LAST_CHUNK) != 0;
        seq++;
    }

    if (off != total) {
        return WOLFSPDM_E_CHUNK;
    }
    *outSz = total;
    wolfSPDM_DebugPrint(ctx, "CHUNK: reassembled %u bytes in %u chunk(s)\n",
        (unsigned)total, (unsigned)seq);
    return WOLFSPDM_SUCCESS;
}

#endif /* WOLFSPDM_HAVE_CHUNK */
