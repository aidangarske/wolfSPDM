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
#include <stdarg.h>
#include <stdio.h>

/* --- Context Management --- */

/* Wipe every long-lived session-key field. Used by Disconnect, ConnectStandard
 * reset, and anywhere derived material from a prior session must not leak
 * into the next. */
static void wolfSPDM_WipeSessionKeys(WOLFSPDM_CTX* ctx)
{
    wc_ForceZero(ctx->sharedSecret, sizeof(ctx->sharedSecret));
    wc_ForceZero(ctx->handshakeSecret, sizeof(ctx->handshakeSecret));
    wc_ForceZero(ctx->reqHsSecret, sizeof(ctx->reqHsSecret));
    wc_ForceZero(ctx->rspHsSecret, sizeof(ctx->rspHsSecret));
    wc_ForceZero(ctx->reqFinishedKey, sizeof(ctx->reqFinishedKey));
    wc_ForceZero(ctx->rspFinishedKey, sizeof(ctx->rspFinishedKey));
    wc_ForceZero(ctx->reqDataKey, sizeof(ctx->reqDataKey));
    wc_ForceZero(ctx->rspDataKey, sizeof(ctx->rspDataKey));
    wc_ForceZero(ctx->reqDataIv, sizeof(ctx->reqDataIv));
    wc_ForceZero(ctx->rspDataIv, sizeof(ctx->rspDataIv));
    wc_ForceZero(ctx->reqAppSecret, sizeof(ctx->reqAppSecret));
    wc_ForceZero(ctx->rspAppSecret, sizeof(ctx->rspAppSecret));
    wc_ForceZero(ctx->th1, sizeof(ctx->th1));
    ctx->sharedSecretSz = 0;
}

int wolfSPDM_Init(WOLFSPDM_CTX* ctx)
{
    int rc;
    word16 sid;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Clean slate - do NOT read any fields before this (could be garbage).
     * Callers must wolfSPDM_Free before re-initializing an existing ctx;
     * skipping that step leaks the wolfCrypt RNG/ECC/SHA states opened by
     * the prior Init. We cannot reliably detect that from inside Init
     * (the flag byte is itself part of the garbage we are about to wipe). */
    XMEMSET(ctx, 0, sizeof(WOLFSPDM_CTX));
    ctx->state = WOLFSPDM_STATE_INIT;

    /* Initialize RNG */
    rc = wc_InitRng(&ctx->rng);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }
    ctx->flags.rngInitialized = 1;

    /* Set default requester capabilities */
    ctx->reqCaps = WOLFSPDM_DEFAULT_REQ_CAPS;

    /* Pick a random, non-reserved ReqSessionID (DSP0277 reserves 0x0000 and
     * 0xFFFF). Callers needing determinism can override via
     * wolfSPDM_SetRequesterSessionId. */
    do {
        if (wc_RNG_GenerateBlock(&ctx->rng, (byte*)&sid, sizeof(sid)) != 0) {
            sid = 0x0001;  /* RNG failed; fall back to legacy default */
            break;
        }
    } while (sid == 0x0000 || sid == 0xFFFF);
    ctx->reqSessionId = sid;

    ctx->flags.initialized = 1;
    /* isDynamic remains 0 - only wolfSPDM_New sets it */

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
    ctx->flags.isDynamic = 1;  /* Tag AFTER Init so it isn't wiped */

    return ctx;
}
#endif /* WOLFSPDM_DYNAMIC_MEMORY */

void wolfSPDM_Free(WOLFSPDM_CTX* ctx)
{
#ifdef WOLFSPDM_DYNAMIC_MEMORY
    int wasDynamic;
#endif

    if (ctx == NULL) {
        return;
    }

#ifdef WOLFSPDM_DYNAMIC_MEMORY
    /* Capture before wc_ForceZero wipes ctx->flags. */
    wasDynamic = ctx->flags.isDynamic;
#endif

    /* Free RNG */
    if (ctx->flags.rngInitialized) {
        wc_FreeRng(&ctx->rng);
    }

    /* Free ephemeral key */
    if (ctx->flags.ephemeralKeyInit) {
        wc_ecc_free(&ctx->ephemeralKey);
    }

    /* Free responder public key (used for measurement/challenge verification) */
    if (ctx->flags.hasResponderPubKey) {
        wolfSPDM_FreeResponderPubKey(ctx);
    }

#ifndef NO_WOLFSPDM_CHALLENGE
    /* Free M1/M2 challenge hash if still initialized */
    if (ctx->flags.m1m2HashInit) {
        wc_Sha384Free(&ctx->m1m2Hash);
        ctx->flags.m1m2HashInit = 0;
    }
#endif

    /* Zero entire struct (covers all sensitive key material) */
    wc_ForceZero(ctx, sizeof(WOLFSPDM_CTX));

#ifdef WOLFSPDM_DYNAMIC_MEMORY
    if (wasDynamic) {
        XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif
}

int wolfSPDM_GetCtxSize(void)
{
    return (int)sizeof(WOLFSPDM_CTX);
}

/* Catch struct growth past the public WOLFSPDM_CTX_STATIC_SIZE at compile
 * time rather than at wolfSPDM_InitStatic runtime. Negative array size if
 * the static buffer is no longer sufficient. */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(struct WOLFSPDM_CTX) <= WOLFSPDM_CTX_STATIC_SIZE,
    "WOLFSPDM_CTX_STATIC_SIZE must be >= sizeof(struct WOLFSPDM_CTX); "
    "bump the public macro in wolfspdm/spdm.h");
#else
typedef char wolfSPDM_ctx_static_size_check
    [(sizeof(struct WOLFSPDM_CTX) <= WOLFSPDM_CTX_STATIC_SIZE) ? 1 : -1];
#endif

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

/* --- Configuration --- */

int wolfSPDM_SetIO(WOLFSPDM_CTX* ctx, WOLFSPDM_IO_CB ioCb, void* userCtx)
{
    if (ctx == NULL || ioCb == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    ctx->ioCb = ioCb;
    ctx->ioUserCtx = userCtx;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_SetTrustedCAs(WOLFSPDM_CTX* ctx, const byte* derCerts,
    word32 derCertsSz)
{
    if (ctx == NULL || derCerts == NULL || derCertsSz == 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (derCertsSz > WOLFSPDM_MAX_TRUSTED_CA) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    XMEMCPY(ctx->trustedCAs, derCerts, derCertsSz);
    ctx->trustedCAsSz = derCertsSz;
    ctx->flags.hasTrustedCAs = 1;

    return WOLFSPDM_SUCCESS;
}

void wolfSPDM_SetDebug(WOLFSPDM_CTX* ctx, int enable)
{
    if (ctx != NULL) {
        ctx->flags.debug = enable ? 1 : 0;
    }
}

byte wolfSPDM_GetLastPeerError(WOLFSPDM_CTX* ctx)
{
    return (ctx != NULL) ? ctx->lastPeerErrorCode : 0;
}

/* Backwards-compat: the old function name from before the rename to
 * wolfSPDM_GetNegotiatedVersion. Kept so binaries already linked against
 * the old symbol still resolve. */
byte wolfSPDM_GetVersion_Negotiated(WOLFSPDM_CTX* ctx)
{
    return wolfSPDM_GetNegotiatedVersion(ctx);
}

int wolfSPDM_SetRequesterSessionId(WOLFSPDM_CTX* ctx, word16 reqSessionId)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    /* DSP0277: 0x0000 and 0xFFFF are reserved and shall not appear on wire. */
    if (reqSessionId == 0x0000 || reqSessionId == 0xFFFF) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    ctx->reqSessionId = reqSessionId;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_AllowUntrustedCerts(WOLFSPDM_CTX* ctx, int allow)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }
    ctx->flags.allowUntrustedCert = allow ? 1 : 0;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_SetMaxVersion(WOLFSPDM_CTX* ctx, byte maxVersion)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* 0 means reset to compile-time default */
    if (maxVersion == 0) {
        ctx->maxVersion = 0;
        return WOLFSPDM_SUCCESS;
    }

    /* Validate range. WOLFSPDM_MAX_SPDM_VERSION is the build-time ceiling
     * and is authoritative: the runtime setter cannot raise it. */
    if (maxVersion < WOLFSPDM_MIN_SPDM_VERSION ||
        maxVersion > WOLFSPDM_MAX_SPDM_VERSION) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    ctx->maxVersion = maxVersion;
    return WOLFSPDM_SUCCESS;
}

/* --- Session Status --- */

int wolfSPDM_IsConnected(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    return (ctx->state == WOLFSPDM_STATE_CONNECTED) ? 1 : 0;
}

word32 wolfSPDM_GetSessionId(WOLFSPDM_CTX* ctx)
{
    /* Return the negotiated session ID once KEY_EXCHANGE_RSP has set it
     * (I/O callbacks need it between KEY_EXCHANGE and FINISH to tag the
     * encrypted FINISH record). Restrict the exposure window to states
     * where the value is actually meaningful: from KEY_EX through CONNECTED
     * / MEASURED. Pre-KEY_EX or in the error state, return 0 so callers
     * that test "GetSessionId() != 0" don't see a stale or transitional id. */
    if (ctx == NULL || ctx->state < WOLFSPDM_STATE_KEY_EX ||
        ctx->state == WOLFSPDM_STATE_ERROR) {
        return 0;
    }
    return ctx->sessionId;
}

byte wolfSPDM_GetNegotiatedVersion(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL || ctx->state < WOLFSPDM_STATE_VERSION) {
        return 0;
    }
    return ctx->spdmVersion;
}

/* --- Session Establishment - Connect (Full Handshake) --- */

/* Standard SPDM 1.2 connection flow (for libspdm emulator, etc.) */
static int wolfSPDM_ConnectStandard(WOLFSPDM_CTX* ctx)
{
    int rc;
    int slot;
    int i;

    /* Reset state for new connection. Drop any cached responder public
     * key from a prior attempt - GetCertificate's guard otherwise skips
     * re-extraction, and KEY_EXCHANGE_RSP signature verification would
     * then run against the stale key from the previous responder. Also
     * clear sessionId / seqNums so a partial prior attempt can't leak
     * state into the new handshake. */
    if (ctx->flags.hasResponderPubKey) {
        wolfSPDM_FreeResponderPubKey(ctx);
        ctx->flags.hasResponderPubKey = 0;
    }
    /* Wipe derived key material from any prior session before starting a
     * fresh handshake. If this new handshake fails before
     * wolfSPDM_DeriveHandshakeKeys overwrites the fields, the prior
     * session's secrets must not linger in the context. */
    wolfSPDM_WipeSessionKeys(ctx);
    ctx->state = WOLFSPDM_STATE_INIT;
    ctx->sessionId = 0;
    /* Preserve caller-set reqSessionId from Init / SetRequesterSessionId. */
    ctx->rspSessionId = 0;
    ctx->reqSeqNum = 0;
    ctx->rspSeqNum = 0;
    ctx->lastPeerErrorCode = 0;
    ctx->slotMask = 0;
    ctx->currentSlotId = 0;
#ifndef NO_WOLFSPDM_MEAS
    /* Drop stale measurement state from a prior connect so reconnect-
     * without-disconnect doesn't surface old blocks. */
    ctx->measBlockCount = 0;
    ctx->measSignatureSize = 0;
    ctx->flags.hasMeasurements = 0;
#endif
    wolfSPDM_TranscriptReset(ctx);

    SPDM_CONNECT_STEP(ctx, "Step 1: GET_VERSION\n",
        wolfSPDM_GetVersion(ctx));
    SPDM_CONNECT_STEP(ctx, "Step 2: GET_CAPABILITIES\n",
        wolfSPDM_GetCapabilities(ctx));
    SPDM_CONNECT_STEP(ctx, "Step 3: NEGOTIATE_ALGORITHMS\n",
        wolfSPDM_NegotiateAlgorithms(ctx));
    SPDM_CONNECT_STEP(ctx, "Step 4: GET_DIGESTS\n",
        wolfSPDM_GetDigests(ctx));

    /* DSP0274 Sec. 10.5: pick the lowest-numbered slot the responder said
     * is populated (DIGESTS Param1 SlotMask). Fall back to slot 0 if the
     * responder did not report a mask, matching the prior behavior. */
    slot = 0;
    if (ctx->slotMask != 0) {
        for (i = 0; i < 8; i++) {
            if (ctx->slotMask & (1 << i)) {
                slot = i;
                break;
            }
        }
    }
    SPDM_CONNECT_STEP(ctx, "Step 5: GET_CERTIFICATE\n",
        wolfSPDM_GetCertificate(ctx, slot));

    /* Validate certificate chain if trusted CAs are loaded. GetCertificate
     * already guarantees flags.hasResponderPubKey is set on success (returns
     * an error otherwise), so we only need to gate on the CA-bundle. Fail
     * closed by default: refuse to derive session keys against an
     * unauthenticated responder unless the caller has explicitly opted
     * into untrusted operation via wolfSPDM_AllowUntrustedCerts. */
    if (ctx->flags.hasTrustedCAs) {
        SPDM_CONNECT_STEP(ctx, "Validating certificate chain\n",
            wolfSPDM_ValidateCertChain(ctx));
    }
    else if (!ctx->flags.allowUntrustedCert) {
        wolfSPDM_DebugPrint(ctx,
            "Refusing handshake: no trust anchor configured; call "
            "wolfSPDM_SetTrustedCAs or wolfSPDM_AllowUntrustedCerts\n");
        ctx->state = WOLFSPDM_STATE_ERROR;
        return WOLFSPDM_E_CERT_FAIL;
    }
    else {
        wolfSPDM_DebugPrint(ctx,
            "Warning: No trusted CAs loaded - chain not validated\n");
    }

    SPDM_CONNECT_STEP(ctx, "Step 6: KEY_EXCHANGE\n",
        wolfSPDM_KeyExchange(ctx));
    SPDM_CONNECT_STEP(ctx, "Step 7: FINISH\n",
        wolfSPDM_Finish(ctx));

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

    if (!ctx->flags.initialized) {
        return WOLFSPDM_E_BAD_STATE;
    }

    if (ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }

    return wolfSPDM_ConnectStandard(ctx);
}

int wolfSPDM_Disconnect(WOLFSPDM_CTX* ctx)
{
    int rc = WOLFSPDM_SUCCESS;
    byte txBuf[8];
    byte rxBuf[16];   /* END_SESSION_ACK: 4 bytes */
    word32 txSz, rxSz;
    int sendEndSession;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Only send END_SESSION when we actually have a connected secured
     * channel. For partial-handshake failures (state below CONNECTED) we
     * still want to wipe locally derived material on the way out. */
    sendEndSession = (ctx->state == WOLFSPDM_STATE_CONNECTED);

    if (sendEndSession) {
        txSz = sizeof(txBuf);
        rc = wolfSPDM_BuildEndSession(ctx, txBuf, &txSz);
        if (rc == WOLFSPDM_SUCCESS) {
            rxSz = sizeof(rxBuf);
            rc = wolfSPDM_SecuredExchange(ctx, txBuf, txSz, rxBuf, &rxSz);
        }
    }

    /* Reset state regardless of result. Free the cached responder public
     * key so the next Connect re-extracts it from the (potentially new)
     * responder's certificate chain - otherwise KEY_EXCHANGE_RSP signature
     * verification on the reconnect would run against the old key. */
    if (ctx->flags.hasResponderPubKey) {
        wolfSPDM_FreeResponderPubKey(ctx);
        ctx->flags.hasResponderPubKey = 0;
    }
    /* Wipe every long-lived session secret so disconnected contexts cannot
     * be recovered for the duration before wolfSPDM_Free or a fresh
     * Connect overwrites them. */
    wolfSPDM_WipeSessionKeys(ctx);
    ctx->state = WOLFSPDM_STATE_INIT;
    ctx->sessionId = 0;
    ctx->rspSessionId = 0;
    ctx->reqSeqNum = 0;
    ctx->rspSeqNum = 0;
    ctx->lastPeerErrorCode = 0;
    ctx->slotMask = 0;
    ctx->currentSlotId = 0;
#ifndef NO_WOLFSPDM_MEAS
    /* Drop stale measurement state so callers can't accidentally read
     * blocks from the previous session after a reconnect. */
    ctx->measBlockCount = 0;
    ctx->measSignatureSize = 0;
    ctx->flags.hasMeasurements = 0;
#endif

    /* If we never had a session, the caller did not request a real
     * Disconnect; surface that distinction without masking it as a
     * successful teardown. */
    if (!sendEndSession) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }
    return rc;
}

/* --- I/O Helper --- */

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

/* --- Debug Utilities --- */

void wolfSPDM_DebugPrint(WOLFSPDM_CTX* ctx, const char* fmt, ...)
{
    va_list args;

    if (ctx == NULL || !ctx->flags.debug) {
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

    if (ctx == NULL || !ctx->flags.debug || data == NULL) {
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

/* --- Measurement Accessors --- */

#ifndef NO_WOLFSPDM_MEAS

int wolfSPDM_GetMeasurementCount(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL || !ctx->flags.hasMeasurements) {
        return 0;
    }
    return (int)ctx->measBlockCount;
}

int wolfSPDM_GetMeasurementBlock(WOLFSPDM_CTX* ctx, int blockIdx,
    byte* measIndex, byte* measType, byte* value, word32* valueSz)
{
    const WOLFSPDM_MEAS_BLOCK* blk;

    if (ctx == NULL || !ctx->flags.hasMeasurements) {
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

/* --- Error String --- */

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
