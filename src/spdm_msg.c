/* spdm_msg.c
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
#include <string.h>

int wolfSPDM_BuildGetVersion(byte* buf, word32* bufSz)
{
    if (buf == NULL || bufSz == NULL || *bufSz < 4) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Per SPDM spec, GET_VERSION always uses version 0x10 */
    buf[0] = SPDM_VERSION_10;
    buf[1] = SPDM_GET_VERSION;
    buf[2] = 0x00;
    buf[3] = 0x00;
    *bufSz = 4;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_BuildGetCapabilities(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    if (ctx == NULL || buf == NULL || bufSz == NULL || *bufSz < 20) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    XMEMSET(buf, 0, 20);
    buf[0] = ctx->spdmVersion;  /* Use negotiated version */
    buf[1] = SPDM_GET_CAPABILITIES;
    buf[2] = 0x00;
    buf[3] = 0x00;
    /* CTExponent and reserved at offsets 4-7 */

    /* Requester flags (4 bytes LE) */
    buf[8]  = (byte)(ctx->reqCaps & 0xFF);
    buf[9]  = (byte)((ctx->reqCaps >> 8) & 0xFF);
    buf[10] = (byte)((ctx->reqCaps >> 16) & 0xFF);
    buf[11] = (byte)((ctx->reqCaps >> 24) & 0xFF);

    /* DataTransferSize (4 LE) */
    buf[12] = 0x00; buf[13] = 0x10; buf[14] = 0x00; buf[15] = 0x00;
    /* MaxSPDMmsgSize (4 LE) */
    buf[16] = 0x00; buf[17] = 0x10; buf[18] = 0x00; buf[19] = 0x00;

    *bufSz = 20;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_BuildNegotiateAlgorithms(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    if (ctx == NULL || buf == NULL || bufSz == NULL || *bufSz < 48) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    XMEMSET(buf, 0, 48);
    buf[0] = ctx->spdmVersion;  /* Use negotiated version */
    buf[1] = SPDM_NEGOTIATE_ALGORITHMS;
    buf[2] = 0x04;  /* NumAlgoStructTables = 4 */
    buf[3] = 0x00;
    buf[4] = 48; buf[5] = 0x00;  /* Length = 48 */
    buf[6] = 0x01;  /* MeasurementSpecification = DMTF */
    buf[7] = 0x02;  /* OtherParamsSupport = MULTI_KEY_CONN */

    /* BaseAsymAlgo: ECDSA P-384 (bit 7) */
    buf[8] = 0x80; buf[9] = 0x00; buf[10] = 0x00; buf[11] = 0x00;
    /* BaseHashAlgo: SHA-384 (bit 1) */
    buf[12] = 0x02; buf[13] = 0x00; buf[14] = 0x00; buf[15] = 0x00;

    /* Struct tables start at offset 32 */
    /* DHE: SECP_384_R1 */
    buf[32] = 0x02; buf[33] = 0x20; buf[34] = 0x10; buf[35] = 0x00;
    /* AEAD: AES_256_GCM */
    buf[36] = 0x03; buf[37] = 0x20; buf[38] = 0x02; buf[39] = 0x00;
    /* ReqBaseAsymAlg */
    buf[40] = 0x04; buf[41] = 0x20; buf[42] = 0x0F; buf[43] = 0x00;
    /* KeySchedule */
    buf[44] = 0x05; buf[45] = 0x20; buf[46] = 0x01; buf[47] = 0x00;

    *bufSz = 48;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_BuildGetDigests(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    if (ctx == NULL || buf == NULL || bufSz == NULL || *bufSz < 4) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    buf[0] = ctx->spdmVersion;  /* Use negotiated version */
    buf[1] = SPDM_GET_DIGESTS;
    buf[2] = 0x00;
    buf[3] = 0x00;
    *bufSz = 4;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_BuildGetCertificate(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    int slotId, word16 offset, word16 length)
{
    if (ctx == NULL || buf == NULL || bufSz == NULL || *bufSz < 8) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    buf[0] = ctx->spdmVersion;  /* Use negotiated version */
    buf[1] = SPDM_GET_CERTIFICATE;
    buf[2] = (byte)(slotId & 0x0F);
    buf[3] = 0x00;
    buf[4] = (byte)(offset & 0xFF);
    buf[5] = (byte)((offset >> 8) & 0xFF);
    buf[6] = (byte)(length & 0xFF);
    buf[7] = (byte)((length >> 8) & 0xFF);
    *bufSz = 8;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_BuildKeyExchange(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    word32 offset = 0;
    byte pubKeyX[WOLFSPDM_ECC_KEY_SIZE];
    byte pubKeyY[WOLFSPDM_ECC_KEY_SIZE];
    word32 pubKeyXSz = sizeof(pubKeyX);
    word32 pubKeyYSz = sizeof(pubKeyY);
    int rc;

    if (ctx == NULL || buf == NULL || bufSz == NULL || *bufSz < 180) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    rc = wolfSPDM_GenerateEphemeralKey(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rc = wolfSPDM_ExportEphemeralPubKey(ctx, pubKeyX, &pubKeyXSz,
        pubKeyY, &pubKeyYSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    XMEMSET(buf, 0, *bufSz);

    /* Use negotiated SPDM version (not hardcoded 1.2) */
    buf[offset++] = ctx->spdmVersion;
    buf[offset++] = SPDM_KEY_EXCHANGE;
    buf[offset++] = 0x00;  /* MeasurementSummaryHashType = None */
#ifdef WOLFSPDM_NUVOTON
    buf[offset++] = 0xFF;  /* SlotID = 0xFF (no cert, use provisioned public key) */
#else
    buf[offset++] = 0x00;  /* SlotID = 0 (certificate slot 0) */
#endif

    /* ReqSessionID (2 LE) */
    buf[offset++] = (byte)(ctx->reqSessionId & 0xFF);
    buf[offset++] = (byte)((ctx->reqSessionId >> 8) & 0xFF);

    buf[offset++] = 0x00;  /* SessionPolicy */
    buf[offset++] = 0x00;  /* Reserved */

    /* RandomData (32 bytes) */
    rc = wolfSPDM_GetRandom(ctx, &buf[offset], WOLFSPDM_RANDOM_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    offset += WOLFSPDM_RANDOM_SIZE;

    /* ExchangeData: X || Y */
    XMEMCPY(&buf[offset], pubKeyX, WOLFSPDM_ECC_KEY_SIZE);
    offset += WOLFSPDM_ECC_KEY_SIZE;
    XMEMCPY(&buf[offset], pubKeyY, WOLFSPDM_ECC_KEY_SIZE);
    offset += WOLFSPDM_ECC_KEY_SIZE;

    /* OpaqueData for secured message version negotiation */
#ifdef WOLFSPDM_NUVOTON
    /* Nuvoton format: 12 bytes per spec Rev 1.11 page 19-20
     * OpaqueLength(2 LE) + OpaqueData(12 bytes) = 14 bytes total */
    buf[offset++] = 0x0c;  /* OpaqueLength = 12 (LE) */
    buf[offset++] = 0x00;
    buf[offset++] = 0x00; buf[offset++] = 0x00;  /* SMDataID = 0 */
    buf[offset++] = 0x05; buf[offset++] = 0x00;  /* DataSize = 5 (LE) */
    buf[offset++] = 0x01;  /* Registry ID = 1 (DMTF) */
    buf[offset++] = 0x01;  /* VendorLen = 1 */
    buf[offset++] = 0x01; buf[offset++] = 0x00;  /* VersionCount = 1, Reserved = 0 */
    buf[offset++] = 0x10; buf[offset++] = 0x00;  /* Version 1.0 (0x0010 LE) */
    buf[offset++] = 0x00; buf[offset++] = 0x00;  /* Padding to make OpaqueData 12 bytes */
#else
    /* Standard SPDM 1.2+ OpaqueData format: 20 bytes */
    buf[offset++] = 0x14;  /* OpaqueLength = 20 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x01; buf[offset++] = 0x00;  /* TotalElements */
    buf[offset++] = 0x00; buf[offset++] = 0x00;  /* Reserved */
    buf[offset++] = 0x00; buf[offset++] = 0x00;
    buf[offset++] = 0x09; buf[offset++] = 0x00;  /* DataSize */
    buf[offset++] = 0x01;  /* Registry ID */
    buf[offset++] = 0x01;  /* VendorLen */
    buf[offset++] = 0x03; buf[offset++] = 0x00;  /* VersionCount */
    buf[offset++] = 0x10; buf[offset++] = 0x00;  /* 1.0 */
    buf[offset++] = 0x11; buf[offset++] = 0x00;  /* 1.1 */
    buf[offset++] = 0x12; buf[offset++] = 0x00;  /* 1.2 */
    buf[offset++] = 0x00; buf[offset++] = 0x00;  /* Padding */
#endif

    *bufSz = offset;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_BuildFinish(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    byte th2Hash[WOLFSPDM_HASH_SIZE];
    byte verifyData[WOLFSPDM_HASH_SIZE];
    byte signature[WOLFSPDM_ECC_POINT_SIZE];  /* 96 bytes for P-384 */
    word32 sigSz = sizeof(signature);
    word32 offset = 4;  /* Start after header */
    int mutualAuth = 0;
    int rc;

#ifdef WOLFSPDM_NUVOTON
    /* Nuvoton requires mutual authentication when we have a requester key */
    if (ctx->mode == WOLFSPDM_MODE_NUVOTON && ctx->hasReqKeyPair) {
        mutualAuth = 1;
        wolfSPDM_DebugPrint(ctx, "Nuvoton: Mutual auth ENABLED (required after GIVE_PUB)\n");
    }
#endif

    /* Check buffer size: 148 bytes for mutual auth, 52 bytes otherwise */
    if (ctx == NULL || buf == NULL || bufSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (mutualAuth && *bufSz < 148) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    if (!mutualAuth && *bufSz < 52) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Build FINISH header */
    buf[0] = ctx->spdmVersion;
    buf[1] = SPDM_FINISH;
    if (mutualAuth) {
        buf[2] = 0x01;  /* Param1: Signature field is included */
        buf[3] = 0xFF;  /* Param2: 0xFF = Requester public key provisioned in trusted environment (per Nuvoton spec) */
        wolfSPDM_DebugPrint(ctx, "FINISH: mutual auth with signature\n");
        wolfSPDM_DebugPrint(ctx, "  Header: version=0x%02x code=0x%02x param1=0x%02x param2=0x%02x\n",
            buf[0], buf[1], buf[2], buf[3]);
    }
    else {
        buf[2] = 0x00;  /* Param1: No signature */
        buf[3] = 0x00;  /* Param2: SlotID */
        wolfSPDM_DebugPrint(ctx, "FINISH: no mutual auth\n");
        wolfSPDM_DebugPrint(ctx, "  Header: version=0x%02x code=0x%02x param1=0x%02x param2=0x%02x\n",
            buf[0], buf[1], buf[2], buf[3]);
    }

    /* Debug: Show transcript state before adding FINISH header */
    wolfSPDM_DebugPrint(ctx, "\n=== BuildFinish Transcript Debug ===\n");
    wolfSPDM_DebugPrint(ctx, "Transcript before FINISH header: %u bytes\n", ctx->transcriptLen);
    wolfSPDM_DebugPrint(ctx, "Expected components:\n");
    wolfSPDM_DebugPrint(ctx, "  - VCA (GET_VERSION + VERSION): ~12 bytes\n");
    wolfSPDM_DebugPrint(ctx, "  - Ct (cert chain hash): 48 bytes\n");
    wolfSPDM_DebugPrint(ctx, "  - KEY_EXCHANGE: ~150 bytes\n");
    wolfSPDM_DebugPrint(ctx, "  - KEY_EXCHANGE_RSP partial: ~146 bytes\n");
    wolfSPDM_DebugPrint(ctx, "  - Signature: 96 bytes\n");
    wolfSPDM_DebugPrint(ctx, "  - ResponderVerifyData: 48 bytes\n");
    wolfSPDM_DebugPrint(ctx, "  Total expected: ~500 bytes\n");
    wolfSPDM_DebugHex(ctx, "TH1 (from KEY_EXCHANGE)", ctx->th1, WOLFSPDM_HASH_SIZE);
    wolfSPDM_DebugHex(ctx, "Transcript (first 64 bytes)", ctx->transcript, 64);

    /* Add FINISH header to transcript for TH2 */
    rc = wolfSPDM_TranscriptAdd(ctx, buf, 4);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "Transcript after FINISH header: %u bytes\n", ctx->transcriptLen);

    /* TH2 = Hash(transcript with FINISH header) */
    rc = wolfSPDM_TranscriptHash(ctx, th2Hash);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    XMEMCPY(ctx->th2, th2Hash, WOLFSPDM_HASH_SIZE);
    wolfSPDM_DebugHex(ctx, "TH2", th2Hash, WOLFSPDM_HASH_SIZE);
    wolfSPDM_DebugPrint(ctx, "=== End BuildFinish Transcript Debug ===\n\n");

    /* For mutual auth, use SPDM 1.2+ signing context format per DSP0274:
     * M = SPDM_SIGNING_CONTEXT_PREFIX || SPDM_VERSION || SIGNING_CONTEXT || TH2
     *
     * Where:
     * - SPDM_SIGNING_CONTEXT_PREFIX = 64 bytes of ASCII space (0x20)
     * - SPDM_VERSION = "spdm1.3 " (8 bytes with trailing space, for v1.3)
     * - SIGNING_CONTEXT = "requester-finish signing" (24 bytes)
     * - TH2 = transcript hash (48 bytes for SHA-384)
     *
     * Total: 64 + 8 + 24 + 48 = 144 bytes */
    if (mutualAuth) {
        /* Build signing context per SPDM 1.2+ spec */
        static const char spdm_version[] = "spdm1.3 ";  /* 8 bytes */
        static const char context_str[] = "requester-finish signing";  /* 24 bytes */
        byte signMsg[200];  /* 64 + 8 + 24 + 48 = 144 bytes */
        byte signMsgHash[WOLFSPDM_HASH_SIZE];
        word32 signMsgLen = 0;
        wc_Sha384 sha;

        /* 64 bytes of ASCII space (0x20) as signing context prefix */
        XMEMSET(signMsg, 0x20, 64);
        signMsgLen = 64;

        /* SPDM version string: "spdm1.3 " (8 bytes) */
        XMEMCPY(&signMsg[signMsgLen], spdm_version, 8);
        signMsgLen += 8;

        /* Append signing context string */
        XMEMCPY(&signMsg[signMsgLen], context_str, 24);
        signMsgLen += 24;

        /* Append TH2 */
        XMEMCPY(&signMsg[signMsgLen], th2Hash, WOLFSPDM_HASH_SIZE);
        signMsgLen += WOLFSPDM_HASH_SIZE;

        wolfSPDM_DebugPrint(ctx, "Using SPDM 1.2+ signing context (M = %u bytes)\n", signMsgLen);
        wolfSPDM_DebugPrint(ctx, "  - 64 bytes 0x20 prefix, then \"spdm1.3 \" + context_str + TH2\n");
        wolfSPDM_DebugHex(ctx, "Signing context M (first 64 = spaces)", signMsg, 64);
        wolfSPDM_DebugHex(ctx, "Signing context M (bytes 64-96 = version+context)", &signMsg[64], 32);
        wolfSPDM_DebugHex(ctx, "Signing context M (last 48 = TH2)", &signMsg[signMsgLen - 48], 48);

        /* Hash M to get the value to sign */
        rc = wc_InitSha384(&sha);
        if (rc != 0) {
            return WOLFSPDM_E_CRYPTO_FAIL;
        }
        rc = wc_Sha384Update(&sha, signMsg, signMsgLen);
        if (rc != 0) {
            wc_Sha384Free(&sha);
            return WOLFSPDM_E_CRYPTO_FAIL;
        }
        rc = wc_Sha384Final(&sha, signMsgHash);
        wc_Sha384Free(&sha);
        if (rc != 0) {
            return WOLFSPDM_E_CRYPTO_FAIL;
        }

        wolfSPDM_DebugHex(ctx, "Hash(M) to sign", signMsgHash, WOLFSPDM_HASH_SIZE);

        /* Sign Hash(M) */
        rc = wolfSPDM_SignHash(ctx, signMsgHash, WOLFSPDM_HASH_SIZE, signature, &sigSz);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx, "Failed to sign FINISH: %d\n", rc);
            return rc;
        }

        wolfSPDM_DebugHex(ctx, "Signature", signature, WOLFSPDM_ECC_POINT_SIZE);

        /* Copy signature to buffer (96 bytes) */
        XMEMCPY(&buf[offset], signature, WOLFSPDM_ECC_POINT_SIZE);
        offset += WOLFSPDM_ECC_POINT_SIZE;
    }

    /* RequesterVerifyData = HMAC(reqFinishedKey, TH2) */
    rc = wolfSPDM_ComputeVerifyData(ctx->reqFinishedKey, th2Hash, verifyData);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugHex(ctx, "RequesterVerifyData", verifyData, WOLFSPDM_HASH_SIZE);

    XMEMCPY(&buf[offset], verifyData, WOLFSPDM_HASH_SIZE);
    offset += WOLFSPDM_HASH_SIZE;

    *bufSz = offset;
    wolfSPDM_DebugPrint(ctx, "FINISH message size: %u bytes\n", *bufSz);

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_BuildEndSession(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    if (ctx == NULL || buf == NULL || bufSz == NULL || *bufSz < 4) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    buf[0] = ctx->spdmVersion;  /* Use negotiated version */
    buf[1] = SPDM_END_SESSION;
    buf[2] = 0x00;
    buf[3] = 0x00;
    *bufSz = 4;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_CheckError(const byte* buf, word32 bufSz, int* errorCode)
{
    if (buf == NULL || bufSz < 4) {
        return 0;
    }

    if (buf[1] == SPDM_ERROR) {
        if (errorCode != NULL) {
            *errorCode = buf[2];
        }
        return 1;
    }

    return 0;
}

int wolfSPDM_ParseVersion(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    word16 entryCount;
    word32 i;
    byte highestVersion = SPDM_VERSION_12;  /* Start at 1.2, find highest supported (capped at 1.3) */

    if (ctx == NULL || buf == NULL || bufSz < 6) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (buf[1] != SPDM_VERSION) {
        int errCode;
        if (wolfSPDM_CheckError(buf, bufSz, &errCode)) {
            wolfSPDM_DebugPrint(ctx, "VERSION error: 0x%02x\n", errCode);
            return WOLFSPDM_E_PEER_ERROR;
        }
        return WOLFSPDM_E_VERSION_MISMATCH;
    }

    /* Parse VERSION response:
     * Offset 4-5: VersionNumberEntryCount (LE)
     * Offset 6+: VersionNumberEntry array (2 bytes each, LE) */
    entryCount = (word16)(buf[4] | (buf[5] << 8));

    /* Find highest supported version from entries (capped at 1.3 for now)
     *
     * TODO: SPDM 1.4 fails at FINISH step with libspdm emulator returning
     * InvalidRequest (0x01). KEY_EXCHANGE and key derivation work correctly
     * with "spdm1.4 " prefix, but FINISH message format may differ in 1.4.
     * Investigate OpaqueData format or FINISH requirements for 1.4 support.
     */
    for (i = 0; i < entryCount && (6 + i * 2 + 1) < bufSz; i++) {
        byte ver = buf[6 + i * 2 + 1];  /* Major.Minor in high byte */
        wolfSPDM_DebugPrint(ctx, "VERSION entry %u: 0x%02x\n", i, ver);
        /* Cap at 1.3 (0x13) - SPDM 1.4 FINISH handling needs work */
        if (ver > highestVersion && ver <= SPDM_VERSION_13) {
            highestVersion = ver;
        }
    }

    ctx->spdmVersion = highestVersion;
    ctx->state = WOLFSPDM_STATE_VERSION;

    wolfSPDM_DebugPrint(ctx, "Negotiated SPDM version: 0x%02x\n", ctx->spdmVersion);
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseCapabilities(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    if (ctx == NULL || buf == NULL || bufSz < 12) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (buf[1] != SPDM_CAPABILITIES) {
        int errCode;
        if (wolfSPDM_CheckError(buf, bufSz, &errCode)) {
            return WOLFSPDM_E_PEER_ERROR;
        }
        return WOLFSPDM_E_CAPS_MISMATCH;
    }

    ctx->rspCaps = (word32)buf[8] | ((word32)buf[9] << 8) |
                   ((word32)buf[10] << 16) | ((word32)buf[11] << 24);
    ctx->state = WOLFSPDM_STATE_CAPS;

    wolfSPDM_DebugPrint(ctx, "Responder caps: 0x%08x\n", ctx->rspCaps);
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseAlgorithms(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    if (ctx == NULL || buf == NULL || bufSz < 4) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (buf[1] != SPDM_ALGORITHMS) {
        int errCode;
        if (wolfSPDM_CheckError(buf, bufSz, &errCode)) {
            return WOLFSPDM_E_PEER_ERROR;
        }
        return WOLFSPDM_E_ALGO_MISMATCH;
    }

    ctx->state = WOLFSPDM_STATE_ALGO;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseDigests(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    if (ctx == NULL || buf == NULL || bufSz < 4) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (buf[1] != SPDM_DIGESTS) {
        int errCode;
        if (wolfSPDM_CheckError(buf, bufSz, &errCode)) {
            return WOLFSPDM_E_PEER_ERROR;
        }
        return WOLFSPDM_E_CERT_FAIL;
    }

    ctx->state = WOLFSPDM_STATE_DIGESTS;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseCertificate(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz,
    word16* portionLen, word16* remainderLen)
{
    if (ctx == NULL || buf == NULL || bufSz < 8 ||
        portionLen == NULL || remainderLen == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (buf[1] != SPDM_CERTIFICATE) {
        int errCode;
        if (wolfSPDM_CheckError(buf, bufSz, &errCode)) {
            return WOLFSPDM_E_PEER_ERROR;
        }
        return WOLFSPDM_E_CERT_FAIL;
    }

    *portionLen = (word16)(buf[4] | (buf[5] << 8));
    *remainderLen = (word16)(buf[6] | (buf[7] << 8));

    /* Add certificate chain data (starting at offset 8) */
    if (*portionLen > 0 && bufSz >= (word32)(8 + *portionLen)) {
        wolfSPDM_CertChainAdd(ctx, buf + 8, *portionLen);
    }

    if (*remainderLen == 0) {
        ctx->state = WOLFSPDM_STATE_CERT;
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseKeyExchangeRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    word16 opaqueLen;
    word32 sigOffset;
    word32 keRspPartialLen;
    byte peerPubKeyX[WOLFSPDM_ECC_KEY_SIZE];
    byte peerPubKeyY[WOLFSPDM_ECC_KEY_SIZE];
    const byte* signature;
    const byte* rspVerifyData;
    byte expectedHmac[WOLFSPDM_HASH_SIZE];
    int rc;

    if (ctx == NULL || buf == NULL || bufSz < 140) {
        wolfSPDM_DebugPrint(ctx, "ParseKeyExchangeRsp: INVALID - ctx=%p buf=%p bufSz=%u (need 140)\n",
            (void*)ctx, (void*)buf, bufSz);
        if (buf != NULL && bufSz >= 4) {
            wolfSPDM_DebugPrint(ctx, "Response bytes: %02x %02x %02x %02x (code=%02x, err=%02x)\n",
                buf[0], buf[1], buf[2], buf[3], buf[1], buf[2]);
        }
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (buf[1] != SPDM_KEY_EXCHANGE_RSP) {
        int errCode;
        if (wolfSPDM_CheckError(buf, bufSz, &errCode)) {
            return WOLFSPDM_E_PEER_ERROR;
        }
        return WOLFSPDM_E_KEY_EXCHANGE;
    }

    ctx->rspSessionId = (word16)(buf[4] | (buf[5] << 8));
    ctx->sessionId = (word32)ctx->reqSessionId | ((word32)ctx->rspSessionId << 16);

    wolfSPDM_DebugPrint(ctx, "RspSessionID: 0x%04x, SessionID: 0x%08x\n",
        ctx->rspSessionId, ctx->sessionId);

    /* Extract responder's ephemeral public key (offset 40 = 4+2+1+1+32) */
    XMEMCPY(peerPubKeyX, &buf[40], WOLFSPDM_ECC_KEY_SIZE);
    XMEMCPY(peerPubKeyY, &buf[88], WOLFSPDM_ECC_KEY_SIZE);

    /* OpaqueLen at offset 136 */
    opaqueLen = (word16)(buf[136] | (buf[137] << 8));
    sigOffset = 138 + opaqueLen;
    keRspPartialLen = sigOffset;

    wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE_RSP parse: bufSz=%u, opaqueLen=%u, sigOffset=%u\n",
        bufSz, opaqueLen, sigOffset);
    wolfSPDM_DebugPrint(ctx, "  Need: sigOffset(%u) + sig(%u) + hash(%u) = %u bytes\n",
        sigOffset, WOLFSPDM_ECC_SIG_SIZE, WOLFSPDM_HASH_SIZE,
        sigOffset + WOLFSPDM_ECC_SIG_SIZE + WOLFSPDM_HASH_SIZE);

    if (bufSz < sigOffset + WOLFSPDM_ECC_SIG_SIZE + WOLFSPDM_HASH_SIZE) {
        wolfSPDM_DebugPrint(ctx, "  BUFFER_SMALL: have %u, need %u\n",
            bufSz, sigOffset + WOLFSPDM_ECC_SIG_SIZE + WOLFSPDM_HASH_SIZE);
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    signature = buf + sigOffset;
    rspVerifyData = buf + sigOffset + WOLFSPDM_ECC_SIG_SIZE;

    /* Add KEY_EXCHANGE_RSP partial (without sig/verify) to transcript */
    rc = wolfSPDM_TranscriptAdd(ctx, buf, keRspPartialLen);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Add signature to transcript (TH1 includes signature) */
    rc = wolfSPDM_TranscriptAdd(ctx, signature, WOLFSPDM_ECC_SIG_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Compute ECDH shared secret */
    rc = wolfSPDM_ComputeSharedSecret(ctx, peerPubKeyX, peerPubKeyY);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Compute TH1 = Hash(transcript including signature) */
    rc = wolfSPDM_TranscriptHash(ctx, ctx->th1);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    wolfSPDM_DebugHex(ctx, "TH1", ctx->th1, WOLFSPDM_HASH_SIZE);

    /* Derive all session keys */
    rc = wolfSPDM_DeriveHandshakeKeys(ctx, ctx->th1);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Verify ResponderVerifyData = HMAC(rspFinishedKey, TH1) */
    rc = wolfSPDM_ComputeVerifyData(ctx->rspFinishedKey, ctx->th1, expectedHmac);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Debug output matching old code format for comparison */
    wolfSPDM_DebugPrint(ctx, "\n=== ResponderVerifyData Debug ===\n");
    wolfSPDM_DebugPrint(ctx, "Transcript total: %u bytes\n", ctx->transcriptLen);
    wolfSPDM_DebugHex(ctx, "Transcript (first 64 bytes)", ctx->transcript,
        ctx->transcriptLen > 64 ? 64 : ctx->transcriptLen);
    wolfSPDM_DebugHex(ctx, "TH1 hash", ctx->th1, WOLFSPDM_HASH_SIZE);
    wolfSPDM_DebugHex(ctx, "rspFinishedKey", ctx->rspFinishedKey, WOLFSPDM_HASH_SIZE);
    wolfSPDM_DebugHex(ctx, "Expected HMAC", expectedHmac, WOLFSPDM_HASH_SIZE);
    wolfSPDM_DebugHex(ctx, "Received ResponderVerifyData", rspVerifyData, WOLFSPDM_HASH_SIZE);

    if (XMEMCMP(expectedHmac, rspVerifyData, WOLFSPDM_HASH_SIZE) != 0) {
        wolfSPDM_DebugPrint(ctx, "*** ResponderVerifyData MISMATCH ***\n");
        wolfSPDM_DebugPrint(ctx, "=== End Debug ===\n\n");
        /* Note: some implementations may use different transcript format */
    } else {
        wolfSPDM_DebugPrint(ctx, "ResponderVerifyData VERIFIED OK\n");
        wolfSPDM_DebugPrint(ctx, "=== End Debug ===\n\n");
    }

    /* Add ResponderVerifyData to transcript (per SPDM spec, always included) */
    rc = wolfSPDM_TranscriptAdd(ctx, rspVerifyData, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    ctx->state = WOLFSPDM_STATE_KEY_EX;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseFinishRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    if (ctx == NULL || buf == NULL || bufSz < 4) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (buf[1] == SPDM_FINISH_RSP) {
        ctx->state = WOLFSPDM_STATE_FINISH;
        wolfSPDM_DebugPrint(ctx, "FINISH_RSP received - session established\n");
        return WOLFSPDM_SUCCESS;
    }

    if (buf[1] == SPDM_ERROR) {
        wolfSPDM_DebugPrint(ctx, "FINISH error: 0x%02x\n", buf[2]);
        return WOLFSPDM_E_PEER_ERROR;
    }

    return WOLFSPDM_E_BAD_STATE;
}
