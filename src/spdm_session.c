/* spdm_session.c
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

int wolfSPDM_GetVersion(WOLFSPDM_CTX* ctx)
{
    byte txBuf[8];
    byte rxBuf[32];  /* VERSION: 4 hdr + 2 count + up to 8 entries * 2 = 22 */
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    rc = wolfSPDM_BuildGetVersion(txBuf, &txSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_TranscriptAdd(ctx, txBuf, txSz);

    rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_TranscriptAdd(ctx, rxBuf, rxSz);

    return wolfSPDM_ParseVersion(ctx, rxBuf, rxSz);
}

int wolfSPDM_GetCapabilities(WOLFSPDM_CTX* ctx)
{
    byte txBuf[24];   /* GET_CAPABILITIES: 20 bytes */
    byte rxBuf[40];   /* CAPABILITIES: 20-36 bytes */
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    rc = wolfSPDM_BuildGetCapabilities(ctx, txBuf, &txSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_TranscriptAdd(ctx, txBuf, txSz);

    rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_TranscriptAdd(ctx, rxBuf, rxSz);

    return wolfSPDM_ParseCapabilities(ctx, rxBuf, rxSz);
}

int wolfSPDM_NegotiateAlgorithms(WOLFSPDM_CTX* ctx)
{
    byte txBuf[52];   /* NEGOTIATE_ALGORITHMS: 48 bytes */
    byte rxBuf[80];   /* ALGORITHMS: ~56 bytes with struct tables */
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    rc = wolfSPDM_BuildNegotiateAlgorithms(ctx, txBuf, &txSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_TranscriptAdd(ctx, txBuf, txSz);

    rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_TranscriptAdd(ctx, rxBuf, rxSz);

    return wolfSPDM_ParseAlgorithms(ctx, rxBuf, rxSz);
}

int wolfSPDM_GetDigests(WOLFSPDM_CTX* ctx)
{
    byte txBuf[8];
    byte rxBuf[256];
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    rc = wolfSPDM_BuildGetDigests(ctx, txBuf, &txSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Note: GET_DIGESTS/DIGESTS are NOT added to transcript for TH1 per libspdm */
    rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    return wolfSPDM_ParseDigests(ctx, rxBuf, rxSz);
}

int wolfSPDM_GetCertificate(WOLFSPDM_CTX* ctx, int slotId)
{
    byte txBuf[16];
    byte rxBuf[1040];  /* 8 hdr + up to 1024 cert data per chunk */
    word32 txSz;
    word32 rxSz;
    word16 offset = 0;
    word16 portionLen;
    word16 remainderLen = 1;
    int rc;

    while (remainderLen > 0) {
        txSz = sizeof(txBuf);
        rc = wolfSPDM_BuildGetCertificate(ctx, txBuf, &txSz, slotId, offset, 1024);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

        rxSz = sizeof(rxBuf);
        rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

        rc = wolfSPDM_ParseCertificate(ctx, rxBuf, rxSz, &portionLen, &remainderLen);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

        offset += portionLen;
        wolfSPDM_DebugPrint(ctx, "Certificate: offset=%u, portion=%u, remainder=%u\n",
            offset, portionLen, remainderLen);
    }

    /* Compute Ct = Hash(certificate_chain) and add to transcript */
    rc = wolfSPDM_ComputeCertChainHash(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    return wolfSPDM_TranscriptAdd(ctx, ctx->certChainHash, WOLFSPDM_HASH_SIZE);
}

int wolfSPDM_KeyExchange(WOLFSPDM_CTX* ctx)
{
    byte txBuf[192];  /* KEY_EXCHANGE: ~158 bytes */
    byte rxBuf[384];  /* KEY_EXCHANGE_RSP: ~302 bytes */
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    rc = wolfSPDM_BuildKeyExchange(ctx, txBuf, &txSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_TranscriptAdd(ctx, txBuf, txSz);

    rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE: SendReceive failed: %d\n", rc);
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "KEY_EXCHANGE_RSP: received %u bytes\n", rxSz);

    /* ParseKeyExchangeRsp handles transcript updates and key derivation */
    return wolfSPDM_ParseKeyExchangeRsp(ctx, rxBuf, rxSz);
}

int wolfSPDM_Finish(WOLFSPDM_CTX* ctx)
{
    byte finishBuf[152];  /* 148 bytes max for mutual auth FINISH */
    byte encBuf[256];     /* Encrypted: hdr(14) + padded(160) + tag(16) = 190 max */
    byte rxBuf[128];      /* Encrypted FINISH_RSP: ~94 bytes max */
    byte decBuf[64];      /* Decrypted FINISH_RSP: 4 hdr + 48 verify = 52 */
    word32 finishSz = sizeof(finishBuf);
    word32 encSz = sizeof(encBuf);
    word32 rxSz = sizeof(rxBuf);
    word32 decSz = sizeof(decBuf);
    int rc;

    rc = wolfSPDM_BuildFinish(ctx, finishBuf, &finishSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* FINISH must be sent encrypted (HANDSHAKE_IN_THE_CLEAR not negotiated) */
    rc = wolfSPDM_EncryptInternal(ctx, finishBuf, finishSz, encBuf, &encSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "FINISH encrypt failed: %d\n", rc);
        return rc;
    }

    rc = wolfSPDM_SendReceive(ctx, encBuf, encSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "FINISH SendReceive failed: %d\n", rc);
        return rc;
    }

    /* Check if response is unencrypted SPDM message
     * SPDM messages start with version byte (0x10-0x1F).
     * Encrypted records start with session ID. */
    if (rxSz >= 2 && rxBuf[0] >= 0x10 && rxBuf[0] <= 0x1F) {
        /* Unencrypted SPDM message - check for ERROR */
        if (rxBuf[1] == 0x7F) {  /* SPDM_ERROR */
            wolfSPDM_DebugPrint(ctx, "FINISH: TPM returned unencrypted SPDM ERROR!\n");
            wolfSPDM_DebugPrint(ctx, "  Error code: 0x%02x (%s)\n", rxBuf[2],
                rxBuf[2] == SPDM_ERROR_INVALID_REQUEST ? "InvalidRequest" :
                rxBuf[2] == SPDM_ERROR_BUSY ? "Busy" :
                rxBuf[2] == SPDM_ERROR_UNEXPECTED_REQUEST ? "UnexpectedRequest" :
                rxBuf[2] == SPDM_ERROR_UNSPECIFIED ? "Unspecified" :
                rxBuf[2] == SPDM_ERROR_DECRYPT_ERROR ? "DecryptError" :
                rxBuf[2] == SPDM_ERROR_UNSUPPORTED_REQUEST ? "UnsupportedRequest" :
                rxBuf[2] == SPDM_ERROR_MAJOR_VERSION_MISMATCH ? "VersionMismatch" : "Unknown");
            wolfSPDM_DebugPrint(ctx, "  Error data: 0x%02x\n", (rxSz >= 4) ? rxBuf[3] : 0);
    
            return WOLFSPDM_E_PEER_ERROR;
        }
        wolfSPDM_DebugPrint(ctx, "FINISH: Unexpected unencrypted response code 0x%02x\n",
            rxBuf[1]);
        return WOLFSPDM_E_PEER_ERROR;
    }

    rc = wolfSPDM_DecryptInternal(ctx, rxBuf, rxSz, decBuf, &decSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "FINISH decrypt failed: %d\n", rc);

        return rc;
    }

    rc = wolfSPDM_ParseFinishRsp(ctx, decBuf, decSz);
    if (rc != WOLFSPDM_SUCCESS) {

        return rc;
    }

    /* Derive application data keys (transition from handshake to app phase) */
    rc = wolfSPDM_DeriveAppDataKeys(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "App data key derivation failed: %d\n", rc);

        return rc;
    }

    return WOLFSPDM_SUCCESS;
}
