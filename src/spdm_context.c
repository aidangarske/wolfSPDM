/* spdm_context.c
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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>

/* ==========================================================================
 * Context Management
 * ========================================================================== */

int wolfSPDM_Init(WOLFSPDM_CTX* ctx)
{
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Clean slate — do NOT read any fields before this (could be garbage) */
    XMEMSET(ctx, 0, sizeof(WOLFSPDM_CTX));
    ctx->state = WOLFSPDM_STATE_INIT;

    /* Initialize RNG */
    rc = wc_InitRng(&ctx->rng);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }
    ctx->rngInitialized = 1;

    /* Set default requester capabilities */
    ctx->reqCaps = WOLFSPDM_DEFAULT_REQ_CAPS;

    /* Set default session ID (0x0001 is valid; 0x0000/0xFFFF are reserved) */
    ctx->reqSessionId = 0x0001;

    ctx->initialized = 1;
    /* isDynamic remains 0 — only wolfSPDM_New sets it */

    return WOLFSPDM_SUCCESS;
}

#ifdef WOLFSPDM_DYNAMIC_MEMORY
WOLFSPDM_CTX* wolfSPDM_New(void)
{
    WOLFSPDM_CTX* ctx;

    ctx = (WOLFSPDM_CTX*)XMALLOC(sizeof(WOLFSPDM_CTX), NULL,
                                  DYNAMIC_TYPE_TMP_BUFFER);
    if (ctx == NULL) {
        return NULL;
    }

    if (wolfSPDM_Init(ctx) != WOLFSPDM_SUCCESS) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return NULL;
    }
    ctx->isDynamic = 1;  /* Tag AFTER Init so it isn't wiped */

    return ctx;
}
#endif /* WOLFSPDM_DYNAMIC_MEMORY */

void wolfSPDM_Free(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return;
    }

#ifdef WOLFSPDM_DYNAMIC_MEMORY
    {
        int wasDynamic = ctx->isDynamic;
#endif

    /* Free RNG */
    if (ctx->rngInitialized) {
        wc_FreeRng(&ctx->rng);
    }

    /* Free ephemeral key */
    if (ctx->ephemeralKeyInitialized) {
        wc_ecc_free(&ctx->ephemeralKey);
    }

    /* Free responder public key (used for measurement/challenge verification) */
    if (ctx->hasResponderPubKey) {
        wc_ecc_free(&ctx->responderPubKey);
    }

#ifndef NO_WOLFSPDM_CHALLENGE
    /* Free M1/M2 challenge hash if still initialized */
    if (ctx->m1m2HashInit) {
        wc_Sha384Free(&ctx->m1m2Hash);
        ctx->m1m2HashInit = 0;
    }
#endif

    /* Zero entire struct (covers all sensitive key material) */
    wc_ForceZero(ctx, sizeof(WOLFSPDM_CTX));

#ifdef WOLFSPDM_DYNAMIC_MEMORY
        if (wasDynamic) {
            XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }
#endif
}

int wolfSPDM_GetCtxSize(void)
{
    return (int)sizeof(WOLFSPDM_CTX);
}

int wolfSPDM_InitStatic(WOLFSPDM_CTX* ctx, int size)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (size < (int)sizeof(WOLFSPDM_CTX)) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    return wolfSPDM_Init(ctx);
}

/* ==========================================================================
 * Configuration
 * ========================================================================== */

int wolfSPDM_SetIO(WOLFSPDM_CTX* ctx, WOLFSPDM_IO_CB ioCb, void* userCtx)
{
    if (ctx == NULL || ioCb == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    ctx->ioCb = ioCb;
    ctx->ioUserCtx = userCtx;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_SetResponderPubKey(WOLFSPDM_CTX* ctx,
    const byte* pubKey, word32 pubKeySz)
{
    if (ctx == NULL || pubKey == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (pubKeySz != WOLFSPDM_ECC_POINT_SIZE) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    XMEMCPY(ctx->rspPubKey, pubKey, pubKeySz);
    ctx->rspPubKeyLen = pubKeySz;
    ctx->hasRspPubKey = 1;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_SetRequesterKeyPair(WOLFSPDM_CTX* ctx,
    const byte* privKey, word32 privKeySz,
    const byte* pubKey, word32 pubKeySz)
{
    if (ctx == NULL || privKey == NULL || pubKey == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (privKeySz != WOLFSPDM_ECC_KEY_SIZE ||
        pubKeySz != WOLFSPDM_ECC_POINT_SIZE) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    XMEMCPY(ctx->reqPrivKey, privKey, privKeySz);
    ctx->reqPrivKeyLen = privKeySz;
    XMEMCPY(ctx->reqPubKey, pubKey, pubKeySz);
    ctx->reqPubKeyLen = pubKeySz;
    ctx->hasReqKeyPair = 1;

    return WOLFSPDM_SUCCESS;
}

#ifdef WOLFSPDM_NUVOTON
int wolfSPDM_SetRequesterKeyTPMT(WOLFSPDM_CTX* ctx,
    const byte* tpmtPub, word32 tpmtPubSz)
{
    if (ctx == NULL || tpmtPub == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (tpmtPubSz > sizeof(ctx->reqPubKeyTPMT)) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    XMEMCPY(ctx->reqPubKeyTPMT, tpmtPub, tpmtPubSz);
    ctx->reqPubKeyTPMTLen = tpmtPubSz;
    return WOLFSPDM_SUCCESS;
}
#endif /* WOLFSPDM_NUVOTON */

int wolfSPDM_SetTrustedCAs(WOLFSPDM_CTX* ctx, const byte* derCerts,
    word32 derCertsSz)
{
    if (ctx == NULL || derCerts == NULL || derCertsSz == 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (derCertsSz > WOLFSPDM_MAX_CERT_CHAIN) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    XMEMCPY(ctx->trustedCAs, derCerts, derCertsSz);
    ctx->trustedCAsSz = derCertsSz;
    ctx->hasTrustedCAs = 1;

    return WOLFSPDM_SUCCESS;
}

void wolfSPDM_SetDebug(WOLFSPDM_CTX* ctx, int enable)
{
    if (ctx != NULL) {
        ctx->debug = enable;
    }
}

int wolfSPDM_SetMode(WOLFSPDM_CTX* ctx, WOLFSPDM_MODE mode)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (mode == WOLFSPDM_MODE_NUVOTON) {
#ifdef WOLFSPDM_NUVOTON
        ctx->mode = WOLFSPDM_MODE_NUVOTON;
        /* Initialize Nuvoton-specific fields */
        ctx->connectionHandle = WOLFSPDM_NUVOTON_CONN_HANDLE_DEFAULT;
        ctx->fipsIndicator = WOLFSPDM_NUVOTON_FIPS_DEFAULT;
        return WOLFSPDM_SUCCESS;
#else
        return WOLFSPDM_E_INVALID_ARG;  /* Nuvoton support not compiled in */
#endif
    }

    ctx->mode = WOLFSPDM_MODE_STANDARD;
    return WOLFSPDM_SUCCESS;
}

WOLFSPDM_MODE wolfSPDM_GetMode(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return WOLFSPDM_MODE_STANDARD;
    }
    return ctx->mode;
}

/* ==========================================================================
 * Session Status
 * ========================================================================== */

int wolfSPDM_IsConnected(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return (ctx->state == WOLFSPDM_STATE_CONNECTED) ? 1 : 0;
}

word32 wolfSPDM_GetSessionId(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL || ctx->state != WOLFSPDM_STATE_CONNECTED) {
        return 0;
    }
    return ctx->sessionId;
}

byte wolfSPDM_GetVersion_Negotiated(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL || ctx->state < WOLFSPDM_STATE_VERSION) {
        return 0;
    }
    return ctx->spdmVersion;
}

#ifdef WOLFSPDM_NUVOTON
word32 wolfSPDM_GetConnectionHandle(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->connectionHandle;
}

word16 wolfSPDM_GetFipsIndicator(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return ctx->fipsIndicator;
}
#endif

/* ==========================================================================
 * Session Establishment - Connect (Full Handshake)
 * ========================================================================== */

/* Standard SPDM 1.2 connection flow (for libspdm emulator, etc.) */
static int wolfSPDM_ConnectStandard(WOLFSPDM_CTX* ctx)
{
    int rc;

    /* Reset state for new connection */
    ctx->state = WOLFSPDM_STATE_INIT;
    wolfSPDM_TranscriptReset(ctx);

    /* Step 1: GET_VERSION / VERSION */
    wolfSPDM_DebugPrint(ctx, "Step 1: GET_VERSION\n");
    rc = wolfSPDM_GetVersion(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }

    /* Step 2: GET_CAPABILITIES / CAPABILITIES */
    wolfSPDM_DebugPrint(ctx, "Step 2: GET_CAPABILITIES\n");
    rc = wolfSPDM_GetCapabilities(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }

    /* Step 3: NEGOTIATE_ALGORITHMS / ALGORITHMS */
    wolfSPDM_DebugPrint(ctx, "Step 3: NEGOTIATE_ALGORITHMS\n");
    rc = wolfSPDM_NegotiateAlgorithms(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }

    /* Step 4: GET_DIGESTS / DIGESTS */
    wolfSPDM_DebugPrint(ctx, "Step 4: GET_DIGESTS\n");
    rc = wolfSPDM_GetDigests(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }

    /* Step 5: GET_CERTIFICATE / CERTIFICATE */
    wolfSPDM_DebugPrint(ctx, "Step 5: GET_CERTIFICATE\n");
    rc = wolfSPDM_GetCertificate(ctx, 0);  /* Slot 0 */
    if (rc != WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }

    /* Validate certificate chain if trusted CAs are loaded.
     * Public key extraction now happens automatically in GetCertificate. */
    if (ctx->hasTrustedCAs) {
        rc = wolfSPDM_ValidateCertChain(ctx);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx,
                "Certificate chain validation failed (%d)\n", rc);
            ctx->state = WOLFSPDM_STATE_ERROR;
            return rc;
        }
    }
    else if (!ctx->hasResponderPubKey) {
        wolfSPDM_DebugPrint(ctx,
            "Warning: No trusted CAs loaded — chain not validated\n");
    }

    /* Step 6: KEY_EXCHANGE / KEY_EXCHANGE_RSP */
    wolfSPDM_DebugPrint(ctx, "Step 6: KEY_EXCHANGE\n");
    rc = wolfSPDM_KeyExchange(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }

    /* Step 7: FINISH / FINISH_RSP */
    wolfSPDM_DebugPrint(ctx, "Step 7: FINISH\n");
    rc = wolfSPDM_Finish(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        ctx->state = WOLFSPDM_STATE_ERROR;
        return rc;
    }

    ctx->state = WOLFSPDM_STATE_CONNECTED;
    wolfSPDM_DebugPrint(ctx, "SPDM Session Established! SessionID=0x%08x\n",
        ctx->sessionId);

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Connect(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->initialized) {
        return WOLFSPDM_E_BAD_STATE;
    }

    if (ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }

    /* Dispatch based on mode */
#ifdef WOLFSPDM_NUVOTON
    if (ctx->mode == WOLFSPDM_MODE_NUVOTON) {
        return wolfSPDM_ConnectNuvoton(ctx);
    }
#endif

    return wolfSPDM_ConnectStandard(ctx);
}

int wolfSPDM_Disconnect(WOLFSPDM_CTX* ctx)
{
    int rc;
    byte txBuf[8];
    byte rxBuf[16];   /* END_SESSION_ACK: 4 bytes */
    word32 txSz, rxSz;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state != WOLFSPDM_STATE_CONNECTED) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    /* Build END_SESSION */
    txSz = sizeof(txBuf);
    rc = wolfSPDM_BuildEndSession(ctx, txBuf, &txSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Send as secured message */
    rxSz = sizeof(rxBuf);
    rc = wolfSPDM_SecuredExchange(ctx, txBuf, txSz, rxBuf, &rxSz);

    /* Reset state regardless of result */
    ctx->state = WOLFSPDM_STATE_INIT;
    ctx->sessionId = 0;
    ctx->reqSeqNum = 0;
    ctx->rspSeqNum = 0;

    return (rc == WOLFSPDM_SUCCESS) ? WOLFSPDM_SUCCESS : rc;
}

/* ==========================================================================
 * I/O Helper
 * ========================================================================== */

int wolfSPDM_SendReceive(WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz)
{
    int rc;

    if (ctx == NULL || ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }

    rc = ctx->ioCb(ctx, txBuf, txSz, rxBuf, rxSz, ctx->ioUserCtx);
    if (rc != 0) {
        return WOLFSPDM_E_IO_FAIL;
    }

    return WOLFSPDM_SUCCESS;
}

/* ==========================================================================
 * Debug Utilities
 * ========================================================================== */

void wolfSPDM_DebugPrint(WOLFSPDM_CTX* ctx, const char* fmt, ...)
{
    va_list args;

    if (ctx == NULL || !ctx->debug) {
        return;
    }

    printf("[wolfSPDM] ");
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    fflush(stdout);
}

void wolfSPDM_DebugHex(WOLFSPDM_CTX* ctx, const char* label,
    const byte* data, word32 len)
{
    word32 i;

    if (ctx == NULL || !ctx->debug || data == NULL) {
        return;
    }

    printf("[wolfSPDM] %s (%u bytes): ", label, len);
    for (i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) {
        printf("...");
    }
    printf("\n");
    fflush(stdout);
}

/* ==========================================================================
 * Measurement Accessors
 * ========================================================================== */

#ifndef NO_WOLFSPDM_MEAS

int wolfSPDM_GetMeasurementCount(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL || !ctx->hasMeasurements) {
        return 0;
    }
    return (int)ctx->measBlockCount;
}

int wolfSPDM_GetMeasurementBlock(WOLFSPDM_CTX* ctx, int blockIdx,
    byte* measIndex, byte* measType, byte* value, word32* valueSz)
{
    WOLFSPDM_MEAS_BLOCK* blk;

    if (ctx == NULL || !ctx->hasMeasurements) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (blockIdx < 0 || blockIdx >= (int)ctx->measBlockCount) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    if (valueSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    blk = &ctx->measBlocks[blockIdx];

    if (measIndex != NULL) {
        *measIndex = blk->index;
    }
    if (measType != NULL) {
        *measType = blk->dmtfType;
    }

    if (value != NULL) {
        word32 copySize = blk->valueSize;
        if (copySize > *valueSz) {
            copySize = *valueSz;
        }
        XMEMCPY(value, blk->value, copySize);
    }
    *valueSz = blk->valueSize;

    return WOLFSPDM_SUCCESS;
}

#endif /* !NO_WOLFSPDM_MEAS */

/* ==========================================================================
 * Error String
 * ========================================================================== */

const char* wolfSPDM_GetErrorString(int error)
{
    switch (error) {
        case WOLFSPDM_SUCCESS:            return "Success";
        case WOLFSPDM_E_INVALID_ARG:      return "Invalid argument";
        case WOLFSPDM_E_BUFFER_SMALL:     return "Buffer too small";
        case WOLFSPDM_E_BAD_STATE:        return "Invalid state";
        case WOLFSPDM_E_VERSION_MISMATCH: return "Version mismatch";
        case WOLFSPDM_E_CRYPTO_FAIL:      return "Crypto operation failed";
        case WOLFSPDM_E_BAD_SIGNATURE:    return "Bad signature";
        case WOLFSPDM_E_BAD_HMAC:         return "HMAC verification failed";
        case WOLFSPDM_E_IO_FAIL:          return "I/O failure";
        case WOLFSPDM_E_TIMEOUT:          return "Timeout";
        case WOLFSPDM_E_PEER_ERROR:       return "Peer error response";
        case WOLFSPDM_E_DECRYPT_FAIL:     return "Decryption failed";
        case WOLFSPDM_E_SEQUENCE:         return "Sequence number error";
        case WOLFSPDM_E_NOT_CONNECTED:    return "Not connected";
        case WOLFSPDM_E_ALREADY_INIT:     return "Already initialized";
        case WOLFSPDM_E_NO_MEMORY:        return "Memory allocation failed";
        case WOLFSPDM_E_CERT_FAIL:        return "Certificate error";
        case WOLFSPDM_E_CAPS_MISMATCH:    return "Capability mismatch";
        case WOLFSPDM_E_ALGO_MISMATCH:    return "Algorithm mismatch";
        case WOLFSPDM_E_SESSION_INVALID:  return "Invalid session";
        case WOLFSPDM_E_KEY_EXCHANGE:     return "Key exchange failed";
        case WOLFSPDM_E_MEASUREMENT:     return "Measurement retrieval failed";
        case WOLFSPDM_E_MEAS_NOT_VERIFIED: return "Measurements not signature-verified";
        case WOLFSPDM_E_MEAS_SIG_FAIL:   return "Measurement signature verification failed";
        case WOLFSPDM_E_CERT_PARSE:      return "Failed to parse responder certificate";
        case WOLFSPDM_E_CHALLENGE:       return "Challenge authentication failed";
        case WOLFSPDM_E_KEY_UPDATE:      return "Key update failed";
        default:                          return "Unknown error";
    }
}
