/* spdm_nuvoton.c
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

/* Nuvoton TPM SPDM Support
 *
 * This file implements Nuvoton-specific SPDM functionality:
 * - TCG SPDM Binding message framing (per TCG SPDM Binding Spec v1.0)
 * - Nuvoton vendor-defined commands (GET_PUBK, GIVE_PUB, GET_STS_, SPDMONLY)
 * - Nuvoton SPDM handshake flow
 *
 * Reference: Nuvoton SPDM Guidance Rev 1.11
 */

#include "spdm_internal.h"

#ifdef WOLFSPDM_NUVOTON

#include <wolfspdm/spdm_nuvoton.h>
#include <string.h>

/* ==========================================================================
 * Internal Byte-Order Helpers
 * ========================================================================== */

/* Store a 16-bit value in big-endian format */
static void SPDM_Set16BE(byte* buf, word16 val)
{
    buf[0] = (byte)(val >> 8);
    buf[1] = (byte)(val & 0xFF);
}

/* Read a 16-bit value from big-endian format */
static word16 SPDM_Get16BE(const byte* buf)
{
    return (word16)((buf[0] << 8) | buf[1]);
}

/* Store a 16-bit value in little-endian format */
static void SPDM_Set16LE(byte* buf, word16 val)
{
    buf[0] = (byte)(val & 0xFF);
    buf[1] = (byte)(val >> 8);
}

/* Read a 16-bit value from little-endian format */
static word16 SPDM_Get16LE(const byte* buf)
{
    return (word16)(buf[0] | (buf[1] << 8));
}

/* Store a 32-bit value in big-endian format */
static void SPDM_Set32BE(byte* buf, word32 val)
{
    buf[0] = (byte)(val >> 24);
    buf[1] = (byte)(val >> 16);
    buf[2] = (byte)(val >> 8);
    buf[3] = (byte)(val & 0xFF);
}

/* Read a 32-bit value from big-endian format */
static word32 SPDM_Get32BE(const byte* buf)
{
    return ((word32)buf[0] << 24) | ((word32)buf[1] << 16) |
           ((word32)buf[2] << 8) | (word32)buf[3];
}

/* Store a 64-bit value in little-endian format */
static void SPDM_Set64LE(byte* buf, word64 val)
{
    buf[0] = (byte)(val & 0xFF);
    buf[1] = (byte)((val >> 8) & 0xFF);
    buf[2] = (byte)((val >> 16) & 0xFF);
    buf[3] = (byte)((val >> 24) & 0xFF);
    buf[4] = (byte)((val >> 32) & 0xFF);
    buf[5] = (byte)((val >> 40) & 0xFF);
    buf[6] = (byte)((val >> 48) & 0xFF);
    buf[7] = (byte)((val >> 56) & 0xFF);
}

/* Read a 64-bit value from little-endian format */
static word64 SPDM_Get64LE(const byte* buf)
{
    return (word64)buf[0] | ((word64)buf[1] << 8) |
           ((word64)buf[2] << 16) | ((word64)buf[3] << 24) |
           ((word64)buf[4] << 32) | ((word64)buf[5] << 40) |
           ((word64)buf[6] << 48) | ((word64)buf[7] << 56);
}

/* ==========================================================================
 * TCG SPDM Binding Message Framing
 * ========================================================================== */

int wolfSPDM_BuildTcgClearMessage(
    WOLFSPDM_CTX* ctx,
    const byte* spdmPayload, word32 spdmPayloadSz,
    byte* outBuf, word32 outBufSz)
{
    word32 totalSz;

    if (ctx == NULL || spdmPayload == NULL || outBuf == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* TCG binding header (16 bytes per Nuvoton spec):
     * tag(2/BE) + size(4/BE) + connHandle(4/BE) + fips(2/BE) + reserved(4) */
    totalSz = WOLFSPDM_TCG_HEADER_SIZE + spdmPayloadSz;

    if (outBufSz < totalSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Tag (2 bytes BE) */
    SPDM_Set16BE(outBuf, WOLFSPDM_TCG_TAG_CLEAR);
    /* Size (4 bytes BE, total including header) */
    SPDM_Set32BE(outBuf + 2, totalSz);
    /* Connection Handle (4 bytes BE) */
    SPDM_Set32BE(outBuf + 6, ctx->connectionHandle);
    /* FIPS Service Indicator (2 bytes BE) */
    SPDM_Set16BE(outBuf + 10, ctx->fipsIndicator);
    /* Reserved (4 bytes, must be 0) */
    XMEMSET(outBuf + 12, 0, 4);
    /* SPDM Payload */
    XMEMCPY(outBuf + WOLFSPDM_TCG_HEADER_SIZE, spdmPayload, spdmPayloadSz);

    return (int)totalSz;
}

int wolfSPDM_ParseTcgClearMessage(
    const byte* inBuf, word32 inBufSz,
    byte* spdmPayload, word32* spdmPayloadSz,
    WOLFSPDM_TCG_CLEAR_HDR* hdr)
{
    word16 tag;
    word32 msgSize;
    word32 payloadSz;

    if (inBuf == NULL || spdmPayload == NULL || spdmPayloadSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (inBufSz < WOLFSPDM_TCG_HEADER_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Parse header */
    tag = SPDM_Get16BE(inBuf);
    if (tag != WOLFSPDM_TCG_TAG_CLEAR) {
        return WOLFSPDM_E_PEER_ERROR;
    }

    msgSize = SPDM_Get32BE(inBuf + 2);
    if (msgSize > inBufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    payloadSz = msgSize - WOLFSPDM_TCG_HEADER_SIZE;
    if (*spdmPayloadSz < payloadSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Fill header if requested */
    if (hdr != NULL) {
        hdr->tag = tag;
        hdr->size = msgSize;
        hdr->connectionHandle = SPDM_Get32BE(inBuf + 6);
        hdr->fipsIndicator = SPDM_Get16BE(inBuf + 10);
        hdr->reserved = SPDM_Get32BE(inBuf + 12);
    }

    /* Extract payload */
    XMEMCPY(spdmPayload, inBuf + WOLFSPDM_TCG_HEADER_SIZE, payloadSz);
    *spdmPayloadSz = payloadSz;

    return (int)payloadSz;
}

int wolfSPDM_BuildTcgSecuredMessage(
    WOLFSPDM_CTX* ctx,
    const byte* encPayload, word32 encPayloadSz,
    const byte* mac, word32 macSz,
    byte* outBuf, word32 outBufSz)
{
    word32 totalSz;
    word32 offset;
    word16 recordLen;

    if (ctx == NULL || encPayload == NULL || mac == NULL || outBuf == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Total: TCG header(16) + sessionId(4/LE) + seqNum(8/LE) +
     *        length(2/LE) + encPayload + MAC */
    totalSz = WOLFSPDM_TCG_HEADER_SIZE + WOLFSPDM_TCG_SECURED_HDR_SIZE +
              encPayloadSz + macSz;

    if (outBufSz < totalSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* TCG binding header (16 bytes, all BE) */
    SPDM_Set16BE(outBuf, WOLFSPDM_TCG_TAG_SECURED);
    SPDM_Set32BE(outBuf + 2, totalSz);
    SPDM_Set32BE(outBuf + 6, ctx->connectionHandle);
    SPDM_Set16BE(outBuf + 10, ctx->fipsIndicator);
    XMEMSET(outBuf + 12, 0, 4);

    offset = WOLFSPDM_TCG_HEADER_SIZE;

    /* Session ID (4 bytes LE per DSP0277):
     * ReqSessionId(2/LE) || RspSessionId(2/LE) */
    SPDM_Set16LE(outBuf + offset, ctx->reqSessionId);
    offset += 2;
    SPDM_Set16LE(outBuf + offset, ctx->rspSessionId);
    offset += 2;

    /* Sequence Number (8 bytes LE per DSP0277) */
    SPDM_Set64LE(outBuf + offset, ctx->reqSeqNum);
    offset += 8;

    /* Length (2 bytes LE per DSP0277) = encrypted data + MAC */
    recordLen = (word16)(encPayloadSz + macSz);
    SPDM_Set16LE(outBuf + offset, recordLen);
    offset += 2;

    /* Encrypted payload */
    XMEMCPY(outBuf + offset, encPayload, encPayloadSz);
    offset += encPayloadSz;

    /* MAC (AES-256-GCM tag) */
    XMEMCPY(outBuf + offset, mac, macSz);

    /* Note: Sequence number increment is handled by caller */

    return (int)totalSz;
}

int wolfSPDM_ParseTcgSecuredMessage(
    const byte* inBuf, word32 inBufSz,
    word32* sessionId, word64* seqNum,
    byte* encPayload, word32* encPayloadSz,
    byte* mac, word32* macSz,
    WOLFSPDM_TCG_SECURED_HDR* hdr)
{
    word16 tag;
    word32 msgSize;
    word32 offset;
    word16 recordLen;
    word32 payloadSz;

    if (inBuf == NULL || sessionId == NULL || seqNum == NULL ||
        encPayload == NULL || encPayloadSz == NULL ||
        mac == NULL || macSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (inBufSz < WOLFSPDM_TCG_HEADER_SIZE + WOLFSPDM_TCG_SECURED_HDR_SIZE +
                  WOLFSPDM_AEAD_TAG_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Parse TCG binding header (16 bytes, all BE) */
    tag = SPDM_Get16BE(inBuf);
    if (tag != WOLFSPDM_TCG_TAG_SECURED) {
        return WOLFSPDM_E_PEER_ERROR;
    }

    msgSize = SPDM_Get32BE(inBuf + 2);
    if (msgSize > inBufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Fill header if requested */
    if (hdr != NULL) {
        hdr->tag = tag;
        hdr->size = msgSize;
        hdr->connectionHandle = SPDM_Get32BE(inBuf + 6);
        hdr->fipsIndicator = SPDM_Get16BE(inBuf + 10);
        hdr->reserved = SPDM_Get32BE(inBuf + 12);
    }

    offset = WOLFSPDM_TCG_HEADER_SIZE;

    /* Session ID (4 bytes LE per DSP0277):
     * ReqSessionId(2/LE) || RspSessionId(2/LE) */
    {
        word16 reqSid = SPDM_Get16LE(inBuf + offset);
        word16 rspSid = SPDM_Get16LE(inBuf + offset + 2);
        *sessionId = ((word32)reqSid << 16) | rspSid;
    }
    offset += 4;

    /* Sequence Number (8 bytes LE per DSP0277) */
    *seqNum = SPDM_Get64LE(inBuf + offset);
    offset += 8;

    /* Length (2 bytes LE per DSP0277) = encrypted data + MAC */
    recordLen = SPDM_Get16LE(inBuf + offset);
    offset += 2;

    /* Validate record length */
    if (recordLen < WOLFSPDM_AEAD_TAG_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    if (offset + recordLen > inBufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Encrypted payload size = recordLen - MAC */
    payloadSz = recordLen - WOLFSPDM_AEAD_TAG_SIZE;
    if (*encPayloadSz < payloadSz || *macSz < WOLFSPDM_AEAD_TAG_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Encrypted payload */
    XMEMCPY(encPayload, inBuf + offset, payloadSz);
    *encPayloadSz = payloadSz;
    offset += payloadSz;

    /* MAC */
    XMEMCPY(mac, inBuf + offset, WOLFSPDM_AEAD_TAG_SIZE);
    *macSz = WOLFSPDM_AEAD_TAG_SIZE;

    return (int)payloadSz;
}

/* ==========================================================================
 * SPDM Vendor Defined Message Helpers
 * ========================================================================== */

/* SPDM message codes */
#define SPDM_VERSION_1_3              0x13
#define SPDM_VENDOR_DEFINED_REQUEST   0xFE
#define SPDM_VENDOR_DEFINED_RESPONSE  0x7E

int wolfSPDM_BuildVendorDefined(
    const char* vdCode,
    const byte* payload, word32 payloadSz,
    byte* outBuf, word32 outBufSz)
{
    word32 totalSz;
    word32 offset = 0;

    if (vdCode == NULL || outBuf == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* SPDM VENDOR_DEFINED_REQUEST format (per Nuvoton SPDM Guidance):
     * SPDMVersion(1) + reqRspCode(1) + param1(1) + param2(1) +
     * standardId(2/LE) + vendorIdLen(1) + reqLength(2/LE) +
     * vdCode(8) + payload */
    totalSz = 1 + 1 + 1 + 1 + 2 + 1 + 2 + WOLFSPDM_VDCODE_LEN + payloadSz;

    if (outBufSz < totalSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* SPDM Version (v1.3 = 0x13) */
    outBuf[offset++] = SPDM_VERSION_1_3;
    /* Request/Response Code */
    outBuf[offset++] = SPDM_VENDOR_DEFINED_REQUEST;
    /* Param1, Param2 */
    outBuf[offset++] = 0x00;
    outBuf[offset++] = 0x00;
    /* Standard ID (0x0001 = TCG, little-endian per Nuvoton spec) */
    SPDM_Set16LE(outBuf + offset, 0x0001);
    offset += 2;
    /* Vendor ID Length (0 for TCG) */
    outBuf[offset++] = 0x00;
    /* Request Length (vdCode + payload, little-endian per Nuvoton spec) */
    SPDM_Set16LE(outBuf + offset, (word16)(WOLFSPDM_VDCODE_LEN + payloadSz));
    offset += 2;
    /* VdCode (8-byte ASCII) */
    XMEMCPY(outBuf + offset, vdCode, WOLFSPDM_VDCODE_LEN);
    offset += WOLFSPDM_VDCODE_LEN;
    /* Payload */
    if (payload != NULL && payloadSz > 0) {
        XMEMCPY(outBuf + offset, payload, payloadSz);
        offset += payloadSz;
    }

    return (int)offset;
}

int wolfSPDM_ParseVendorDefined(
    const byte* inBuf, word32 inBufSz,
    char* vdCode,
    byte* payload, word32* payloadSz)
{
    word32 offset = 0;
    word16 reqLength;
    word32 dataLen;
    byte vendorIdLen;

    if (inBuf == NULL || vdCode == NULL || payload == NULL ||
        payloadSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Minimum: version(1) + code(1) + param1(1) + param2(1) + stdId(2/LE) +
     *          vidLen(1) + reqLen(2/LE) + vdCode(8) = 17 */
    if (inBufSz < 17) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Skip SPDM version */
    offset += 1;
    /* Skip request/response code + params */
    offset += 3;
    /* Skip standard ID (2 bytes LE) */
    offset += 2;
    /* Vendor ID length and vendor ID data */
    vendorIdLen = inBuf[offset];
    offset += 1 + vendorIdLen;

    if (offset + 2 > inBufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Request/Response Length (2 bytes LE per Nuvoton spec) */
    reqLength = SPDM_Get16LE(inBuf + offset);
    offset += 2;

    if (reqLength < WOLFSPDM_VDCODE_LEN) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    if (offset + reqLength > inBufSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* VdCode */
    XMEMCPY(vdCode, inBuf + offset, WOLFSPDM_VDCODE_LEN);
    vdCode[WOLFSPDM_VDCODE_LEN] = '\0';  /* Null-terminate */
    offset += WOLFSPDM_VDCODE_LEN;

    /* Payload */
    dataLen = reqLength - WOLFSPDM_VDCODE_LEN;
    if (*payloadSz < dataLen) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    if (dataLen > 0) {
        XMEMCPY(payload, inBuf + offset, dataLen);
    }
    *payloadSz = dataLen;

    return (int)dataLen;
}

/* ==========================================================================
 * Nuvoton-Specific SPDM Functions
 * ========================================================================== */

/* Helper: Send TCG clear message and receive response */
static int wolfSPDM_Nuvoton_SendClear(
    WOLFSPDM_CTX* ctx,
    const byte* spdmPayload, word32 spdmPayloadSz,
    byte* rxBuf, word32* rxSz)
{
    int rc;
    byte txBuf[WOLFSPDM_MAX_MSG_SIZE];
    int txSz;

    if (ctx == NULL || spdmPayload == NULL || rxBuf == NULL || rxSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }

    /* Build TCG clear message wrapper */
    txSz = wolfSPDM_BuildTcgClearMessage(ctx, spdmPayload, spdmPayloadSz,
        txBuf, sizeof(txBuf));
    if (txSz < 0) {
        return txSz;
    }

    wolfSPDM_DebugHex(ctx, "Nuvoton TX", txBuf, (word32)txSz);

    /* Send via IO callback and receive response */
    rc = ctx->ioCb(ctx, txBuf, (word32)txSz, rxBuf, rxSz, ctx->ioUserCtx);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "Nuvoton I/O failed: %d\n", rc);
        return WOLFSPDM_E_IO_FAIL;
    }

    wolfSPDM_DebugHex(ctx, "Nuvoton RX", rxBuf, *rxSz);

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Nuvoton_GetPubKey(
    WOLFSPDM_CTX* ctx,
    byte* pubKey, word32* pubKeySz)
{
    int rc;
    byte spdmMsg[256];
    int spdmMsgSz;
    byte rxBuf[512];
    word32 rxSz;
    byte spdmPayload[256];
    word32 spdmPayloadSz;
    byte rspPayload[256];
    word32 rspPayloadSz;
    char rspVdCode[WOLFSPDM_VDCODE_LEN + 1];
    WOLFSPDM_TCG_CLEAR_HDR tcgHdr;

    if (ctx == NULL || pubKey == NULL || pubKeySz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    wolfSPDM_DebugPrint(ctx, "Nuvoton: GET_PUBK\n");

    /* Build GET_PUBK vendor-defined request */
    spdmMsgSz = wolfSPDM_BuildVendorDefined(WOLFSPDM_VDCODE_GET_PUBK,
        NULL, 0, spdmMsg, sizeof(spdmMsg));
    if (spdmMsgSz < 0) {
        return spdmMsgSz;
    }

    /* Send via TCG clear message */
    rxSz = sizeof(rxBuf);
    rc = wolfSPDM_Nuvoton_SendClear(ctx, spdmMsg, (word32)spdmMsgSz,
        rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Parse TCG clear response and capture fipsIndicator from header */
    spdmPayloadSz = sizeof(spdmPayload);
    XMEMSET(&tcgHdr, 0, sizeof(tcgHdr));
    rc = wolfSPDM_ParseTcgClearMessage(rxBuf, rxSz, spdmPayload,
        &spdmPayloadSz, &tcgHdr);

    /* Capture fipsIndicator from response for use in subsequent messages */
    if (rc >= 0 && tcgHdr.fipsIndicator != 0) {
        ctx->fipsIndicator = tcgHdr.fipsIndicator;
        wolfSPDM_DebugPrint(ctx, "GET_PUBK: Captured FipsIndicator=0x%04x from response\n",
            ctx->fipsIndicator);
    }
    if (rc < 0) {
        wolfSPDM_DebugPrint(ctx, "GET_PUBK: ParseClearMessage failed %d\n", rc);
        return rc;
    }

    /* Check for SPDM ERROR response */
    if (spdmPayloadSz >= 4 && spdmPayload[1] == SPDM_ERROR) {
        wolfSPDM_DebugPrint(ctx, "GET_PUBK: SPDM ERROR 0x%02x 0x%02x\n",
            spdmPayload[2], spdmPayload[3]);
        return WOLFSPDM_E_PEER_ERROR;
    }

    /* Parse vendor-defined response */
    rspPayloadSz = sizeof(rspPayload);
    XMEMSET(rspVdCode, 0, sizeof(rspVdCode));
    rc = wolfSPDM_ParseVendorDefined(spdmPayload, spdmPayloadSz,
        rspVdCode, rspPayload, &rspPayloadSz);
    if (rc < 0) {
        wolfSPDM_DebugPrint(ctx, "GET_PUBK: ParseVendorDefined failed %d\n", rc);
        return rc;
    }

    /* Verify VdCode */
    if (XMEMCMP(rspVdCode, WOLFSPDM_VDCODE_GET_PUBK, WOLFSPDM_VDCODE_LEN) != 0) {
        wolfSPDM_DebugPrint(ctx, "GET_PUBK: Unexpected VdCode '%.8s'\n", rspVdCode);
        return WOLFSPDM_E_PEER_ERROR;
    }

    wolfSPDM_DebugPrint(ctx, "GET_PUBK: Got TPMT_PUBLIC (%u bytes)\n", rspPayloadSz);

    /* Copy public key to output */
    if (*pubKeySz < rspPayloadSz) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    XMEMCPY(pubKey, rspPayload, rspPayloadSz);
    *pubKeySz = rspPayloadSz;

    /* Store for KEY_EXCHANGE cert_chain_buffer_hash computation.
     * Per Nuvoton SPDM Guidance: cert_chain_buffer_hash = SHA-384(TPMT_PUBLIC) */
    if (rspPayloadSz <= sizeof(ctx->rspPubKey)) {
        XMEMCPY(ctx->rspPubKey, rspPayload, rspPayloadSz);
        ctx->rspPubKeyLen = rspPayloadSz;
        ctx->hasRspPubKey = 1;
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Nuvoton_GivePubKey(
    WOLFSPDM_CTX* ctx,
    const byte* pubKey, word32 pubKeySz)
{
    int rc;
    byte spdmMsg[256];
    int spdmMsgSz;
    byte encBuf[WOLFSPDM_MAX_MSG_SIZE];
    word32 encSz;
    byte rxBuf[512];
    word32 rxSz;
    byte decBuf[256];
    word32 decSz;

    if (ctx == NULL || pubKey == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state < WOLFSPDM_STATE_KEY_EX) {
        return WOLFSPDM_E_BAD_STATE;
    }

    wolfSPDM_DebugPrint(ctx, "Nuvoton: GIVE_PUB (%u bytes) - sending ENCRYPTED\n", pubKeySz);

    /* Build GIVE_PUB vendor-defined request */
    spdmMsgSz = wolfSPDM_BuildVendorDefined(WOLFSPDM_VDCODE_GIVE_PUB,
        pubKey, pubKeySz, spdmMsg, sizeof(spdmMsg));
    if (spdmMsgSz < 0) {
        return spdmMsgSz;
    }

    /* GIVE_PUB is sent as a SECURED (encrypted) message per Nuvoton spec Rev 1.11.
     * Section 4.2.4 shows GIVE_PUB_KEY uses tag 0x8201 (secured), not 0x8101 (clear).
     *
     * Note: GIVE_PUB is an application-phase vendor command, NOT part of the
     * SPDM handshake transcript. TH2 only includes handshake messages. */

    encSz = sizeof(encBuf);
    rc = wolfSPDM_EncryptMessage(ctx, spdmMsg, (word32)spdmMsgSz,
        encBuf, &encSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "GIVE_PUB: Encrypt failed %d\n", rc);
        return rc;
    }

    /* Send encrypted message */
    if (ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }

    rxSz = sizeof(rxBuf);
    rc = ctx->ioCb(ctx, encBuf, encSz, rxBuf, &rxSz, ctx->ioUserCtx);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "GIVE_PUB: I/O failed %d\n", rc);
        return WOLFSPDM_E_IO_FAIL;
    }

    /* Check if response is unencrypted SPDM message (likely an error).
     * SPDM messages start with version byte (0x10-0x1F).
     * Encrypted records start with session ID (first byte is low byte of reqSessionId). */
    if (rxSz >= 2 && rxBuf[0] >= 0x10 && rxBuf[0] <= 0x1F) {
        /* Unencrypted SPDM message - check if it's an error */
        if (rxBuf[1] == SPDM_ERROR) {
            wolfSPDM_DebugPrint(ctx, "GIVE_PUB: TPM returned unencrypted SPDM ERROR 0x%02x 0x%02x\n",
                (rxSz >= 3) ? rxBuf[2] : 0, (rxSz >= 4) ? rxBuf[3] : 0);
            return WOLFSPDM_E_PEER_ERROR;
        }
        wolfSPDM_DebugPrint(ctx, "GIVE_PUB: Unexpected unencrypted response code 0x%02x\n",
            rxBuf[1]);
        return WOLFSPDM_E_PEER_ERROR;
    }

    /* Decrypt response (encrypted record format) */
    decSz = sizeof(decBuf);
    rc = wolfSPDM_DecryptMessage(ctx, rxBuf, rxSz, decBuf, &decSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "GIVE_PUB: Decrypt failed %d\n", rc);
        return rc;
    }

    /* Check for SPDM ERROR response in decrypted payload */
    if (decSz >= 4 && decBuf[1] == SPDM_ERROR) {
        wolfSPDM_DebugPrint(ctx, "GIVE_PUB: SPDM ERROR 0x%02x 0x%02x\n",
            decBuf[2], decBuf[3]);
        return WOLFSPDM_E_PEER_ERROR;
    }

    wolfSPDM_DebugPrint(ctx, "GIVE_PUB: Success\n");

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Nuvoton_GetStatus(
    WOLFSPDM_CTX* ctx,
    WOLFSPDM_NUVOTON_STATUS* status)
{
    int rc;
    byte spdmMsg[256];
    int spdmMsgSz;
    byte rxBuf[256];
    word32 rxSz;
    byte spdmPayload[128];
    word32 spdmPayloadSz;
    byte rspPayload[64];
    word32 rspPayloadSz;
    char rspVdCode[WOLFSPDM_VDCODE_LEN + 1];
    byte statusType[4] = {0x00, 0x00, 0x00, 0x00}; /* All */

    if (ctx == NULL || status == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    XMEMSET(status, 0, sizeof(*status));

    wolfSPDM_DebugPrint(ctx, "Nuvoton: GET_STS_\n");

    /* Build GET_STS_ vendor-defined request */
    spdmMsgSz = wolfSPDM_BuildVendorDefined(WOLFSPDM_VDCODE_GET_STS,
        statusType, sizeof(statusType), spdmMsg, sizeof(spdmMsg));
    if (spdmMsgSz < 0) {
        return spdmMsgSz;
    }

    /* Send via TCG clear message */
    rxSz = sizeof(rxBuf);
    rc = wolfSPDM_Nuvoton_SendClear(ctx, spdmMsg, (word32)spdmMsgSz,
        rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Parse TCG clear response */
    spdmPayloadSz = sizeof(spdmPayload);
    rc = wolfSPDM_ParseTcgClearMessage(rxBuf, rxSz, spdmPayload,
        &spdmPayloadSz, NULL);
    if (rc < 0) {
        return rc;
    }

    /* Check for SPDM ERROR response */
    if (spdmPayloadSz >= 4 && spdmPayload[1] == SPDM_ERROR) {
        wolfSPDM_DebugPrint(ctx, "GET_STS_: SPDM ERROR 0x%02x 0x%02x\n",
            spdmPayload[2], spdmPayload[3]);
        return WOLFSPDM_E_PEER_ERROR;
    }

    /* Parse vendor-defined response */
    rspPayloadSz = sizeof(rspPayload);
    XMEMSET(rspVdCode, 0, sizeof(rspVdCode));
    rc = wolfSPDM_ParseVendorDefined(spdmPayload, spdmPayloadSz,
        rspVdCode, rspPayload, &rspPayloadSz);
    if (rc < 0) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "GET_STS_: VdCode='%.8s', %u bytes\n",
        rspVdCode, rspPayloadSz);

    /* Debug: dump raw response payload using hex dump function */
    wolfSPDM_DebugHex(ctx, "GET_STS_ payload", rspPayload, rspPayloadSz);

    /* Parse status fields per Nuvoton spec page 9:
     * Byte 0: SpecVersionMajor (0 for SPDM 1.x)
     * Byte 1: SpecVersionMinor (1 = SPDM 1.1, 3 = SPDM 1.3)
     * Byte 2: Reserved
     * Byte 3: SPDMOnly lock state (0 = unlocked, 1 = locked) */
    if (rspPayloadSz >= 4) {
        byte specMajor = rspPayload[0];
        byte specMinor = rspPayload[1];
        /* byte reserved = rspPayload[2]; */
        byte spdmOnly = rspPayload[3];

        status->specVersionMajor = specMajor;
        status->specVersionMinor = specMinor;
        status->spdmOnlyLocked = (spdmOnly != 0);
        status->spdmEnabled = 1; /* If GET_STS works, SPDM is enabled */

        /* Session active can't be determined from GET_STS alone -
         * if we're getting a response, SPDM is working */
        status->sessionActive = 0;

        wolfSPDM_DebugPrint(ctx, "GET_STS_: SpecVersion=%u.%u, SPDMOnly=%s\n",
            specMajor, specMinor, spdmOnly ? "LOCKED" : "unlocked");
    }
    else if (rspPayloadSz >= 1) {
        /* Minimal response - just SPDMOnly */
        status->spdmOnlyLocked = (rspPayload[0] != 0);
        status->spdmEnabled = 1;
        wolfSPDM_DebugPrint(ctx, "GET_STS_: SPDMOnly=%s (minimal response)\n",
            status->spdmOnlyLocked ? "LOCKED" : "unlocked");
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Nuvoton_SetOnlyMode(
    WOLFSPDM_CTX* ctx,
    int lock)
{
    int rc;
    byte spdmMsg[256];
    int spdmMsgSz;
    byte encBuf[WOLFSPDM_MAX_MSG_SIZE];
    word32 encSz;
    byte rxBuf[512];
    word32 rxSz;
    byte decBuf[256];
    word32 decSz;
    byte param[1];

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state != WOLFSPDM_STATE_CONNECTED) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    param[0] = lock ? WOLFSPDM_SPDMONLY_LOCK : WOLFSPDM_SPDMONLY_UNLOCK;

    wolfSPDM_DebugPrint(ctx, "Nuvoton: SPDMONLY %s\n",
        lock ? "LOCK" : "UNLOCK");

    /* Build SPDMONLY vendor-defined request */
    spdmMsgSz = wolfSPDM_BuildVendorDefined(WOLFSPDM_VDCODE_SPDMONLY,
        param, sizeof(param), spdmMsg, sizeof(spdmMsg));
    if (spdmMsgSz < 0) {
        return spdmMsgSz;
    }

    /* Encrypt the message */
    encSz = sizeof(encBuf);
    rc = wolfSPDM_EncryptMessage(ctx, spdmMsg, (word32)spdmMsgSz,
        encBuf, &encSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Send encrypted message */
    if (ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }

    rxSz = sizeof(rxBuf);
    rc = ctx->ioCb(ctx, encBuf, encSz, rxBuf, &rxSz, ctx->ioUserCtx);
    if (rc != 0) {
        return WOLFSPDM_E_IO_FAIL;
    }

    /* Decrypt response */
    decSz = sizeof(decBuf);
    rc = wolfSPDM_DecryptMessage(ctx, rxBuf, rxSz, decBuf, &decSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Check for SPDM ERROR response */
    if (decSz >= 4 && decBuf[1] == SPDM_ERROR) {
        wolfSPDM_DebugPrint(ctx, "SPDMONLY: SPDM ERROR 0x%02x 0x%02x\n",
            decBuf[2], decBuf[3]);
        return WOLFSPDM_E_PEER_ERROR;
    }

    wolfSPDM_DebugPrint(ctx, "SPDMONLY: Success\n");

    return WOLFSPDM_SUCCESS;
}

/* ==========================================================================
 * Nuvoton SPDM Connection Flow
 * ========================================================================== */

/* Nuvoton-specific connection flow:
 * GET_VERSION -> GET_PUB_KEY -> KEY_EXCHANGE -> GIVE_PUB_KEY -> FINISH
 *
 * Key differences from standard SPDM:
 * - No GET_CAPABILITIES or NEGOTIATE_ALGORITHMS (Algorithm Set B is fixed)
 * - Uses GET_PUBK vendor command instead of GET_CERTIFICATE
 * - Uses GIVE_PUB vendor command for mutual authentication
 * - All messages wrapped in TCG binding headers
 */
int wolfSPDM_ConnectNuvoton(WOLFSPDM_CTX* ctx)
{
    int rc;
    byte pubKey[256];
    word32 pubKeySz;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->initialized) {
        return WOLFSPDM_E_BAD_STATE;
    }

    if (ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }

    wolfSPDM_DebugPrint(ctx, "Nuvoton: Starting SPDM connection\n");

    /* Reset state for new connection */
    ctx->state = WOLFSPDM_STATE_INIT;
    wolfSPDM_TranscriptReset(ctx);

    /* Step 1: GET_VERSION / VERSION
     * Note: For Nuvoton, GET_VERSION uses TCG binding header
     * but the message parsing is the same as standard SPDM */
    wolfSPDM_DebugPrint(ctx, "Nuvoton Step 1: GET_VERSION\n");
    rc = wolfSPDM_GetVersion(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "GET_VERSION failed: %d\n", rc);
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }

    /* Step 2: GET_PUBK (Nuvoton vendor command)
     * Gets the TPM's SPDM-Identity public key (TPMT_PUBLIC format) */
    wolfSPDM_DebugPrint(ctx, "Nuvoton Step 2: GET_PUBK\n");
    pubKeySz = sizeof(pubKey);
    rc = wolfSPDM_Nuvoton_GetPubKey(ctx, pubKey, &pubKeySz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "GET_PUBK failed: %d\n", rc);
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }
    ctx->state = WOLFSPDM_STATE_CERT;

    /* Step 2.5: Compute Ct = SHA-384(TPMT_PUBLIC) and add to transcript
     * For Nuvoton, the cert_chain_buffer_hash is SHA-384(TPMT_PUBLIC)
     * instead of the standard certificate chain hash */
    if (ctx->hasRspPubKey && ctx->rspPubKeyLen > 0) {
        wc_Sha384 sha;

        wolfSPDM_DebugPrint(ctx, "Nuvoton: Computing Ct = SHA-384(TPMT_PUBLIC[%u])\n",
            ctx->rspPubKeyLen);

        rc = wc_InitSha384(&sha);
        if (rc != 0) {
            wolfSPDM_DebugPrint(ctx, "Nuvoton: SHA-384 init failed\n");
            ctx->state = WOLFSPDM_STATE_ERROR;
            return WOLFSPDM_E_CRYPTO_FAIL;
        }

        rc = wc_Sha384Update(&sha, ctx->rspPubKey, ctx->rspPubKeyLen);
        if (rc != 0) {
            wc_Sha384Free(&sha);
            wolfSPDM_DebugPrint(ctx, "Nuvoton: SHA-384 update failed\n");
            ctx->state = WOLFSPDM_STATE_ERROR;
            return WOLFSPDM_E_CRYPTO_FAIL;
        }

        rc = wc_Sha384Final(&sha, ctx->certChainHash);
        wc_Sha384Free(&sha);
        if (rc != 0) {
            wolfSPDM_DebugPrint(ctx, "Nuvoton: SHA-384 final failed\n");
            ctx->state = WOLFSPDM_STATE_ERROR;
            return WOLFSPDM_E_CRYPTO_FAIL;
        }

        wolfSPDM_DebugHex(ctx, "Ct (TPMT_PUBLIC hash)", ctx->certChainHash,
            WOLFSPDM_HASH_SIZE);

        /* Add Ct to transcript */
        rc = wolfSPDM_TranscriptAdd(ctx, ctx->certChainHash, WOLFSPDM_HASH_SIZE);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx, "Nuvoton: Failed to add Ct to transcript\n");
            ctx->state = WOLFSPDM_STATE_ERROR;
            return rc;
        }
    }
    else {
        wolfSPDM_DebugPrint(ctx, "Nuvoton: Warning - no responder public key for Ct\n");
    }

    /* Step 3: KEY_EXCHANGE */
    wolfSPDM_DebugPrint(ctx, "Nuvoton Step 3: KEY_EXCHANGE\n");
    rc = wolfSPDM_KeyExchange(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE failed: %d\n", rc);
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }

    /* Step 4: GIVE_PUB (Nuvoton vendor command) - sent as SECURED message
     * Gives the host's SPDM-Identity public key to the TPM.
     * Per Nuvoton spec Rev 1.11 section 4.2.4, GIVE_PUB uses tag 0x8201 (secured). */
    if (ctx->hasReqKeyPair && ctx->reqPubKeyTPMTLen > 0) {
        wolfSPDM_DebugPrint(ctx, "Nuvoton Step 4: GIVE_PUB\n");
        rc = wolfSPDM_Nuvoton_GivePubKey(ctx, ctx->reqPubKeyTPMT,
            ctx->reqPubKeyTPMTLen);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx, "GIVE_PUB failed: %d\n", rc);
            /* Don't fail - continue to FINISH for debug */
        }
        else {
            wolfSPDM_DebugPrint(ctx, "GIVE_PUB succeeded!\n");
        }
    }
    else {
        wolfSPDM_DebugPrint(ctx, "Nuvoton Step 4: GIVE_PUB (skipped, no host key)\n");
    }

    /* Step 5: FINISH (first encrypted message)
     * Completes the handshake with RequesterVerifyData */
    wolfSPDM_DebugPrint(ctx, "Nuvoton Step 5: FINISH\n");
    rc = wolfSPDM_Finish(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "FINISH failed: %d\n", rc);
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }

    ctx->state = WOLFSPDM_STATE_CONNECTED;
    wolfSPDM_DebugPrint(ctx, "Nuvoton: SPDM Session Established! "
        "SessionID=0x%08x\n", ctx->sessionId);

    return WOLFSPDM_SUCCESS;
}

#endif /* WOLFSPDM_NUVOTON */
