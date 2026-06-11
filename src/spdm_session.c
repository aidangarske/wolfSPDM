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

/* Callback types for build/parse functions */
typedef int (*wolfSPDM_BuildFn)(WOLFSPDM_CTX*, byte*, word32*);
typedef int (*wolfSPDM_ParseFn)(WOLFSPDM_CTX*, const byte*, word32);

/* Exchange helper: build -> transcript(tx) -> sendrecv -> transcript(rx) -> parse.
 * Snapshot transcriptLen on entry and roll back if anything after the
 * first TranscriptAdd fails - otherwise a transient failure would leave a
 * partial TX/RX pair committed and corrupt TH1/TH2 on retry. */
static int wolfSPDM_ExchangeMsg(WOLFSPDM_CTX* ctx,
    wolfSPDM_BuildFn buildFn, wolfSPDM_ParseFn parseFn,
    byte* txBuf, word32 txBufSz, byte* rxBuf, word32 rxBufSz)
{
    word32 txSz = txBufSz;
    word32 rxSz = rxBufSz;
    word32 transcriptSnapshot;
    int rc;

    /* Not every adapter (e.g. BuildGetVersion's) validates ctx, so guard
     * here to keep wolfSPDM_GetVersion(NULL) and similar paths from
     * dereferencing a NULL context. */
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    rc = buildFn(ctx, txBuf, &txSz);
    if (rc != WOLFSPDM_SUCCESS) return rc;

    transcriptSnapshot = ctx->transcriptLen;

    rc = wolfSPDM_TranscriptAdd(ctx, txBuf, txSz);
    if (rc != WOLFSPDM_SUCCESS) goto rollback;

    rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) goto rollback;

    rc = wolfSPDM_TranscriptAdd(ctx, rxBuf, rxSz);
    if (rc != WOLFSPDM_SUCCESS) goto rollback;

    rc = parseFn(ctx, rxBuf, rxSz);
    if (rc != WOLFSPDM_SUCCESS) goto rollback;

    return WOLFSPDM_SUCCESS;

rollback:
    ctx->transcriptLen = transcriptSnapshot;
    return rc;
}

/* Adapter: BuildGetVersion doesn't take ctx */
static int wolfSPDM_BuildGetVersionAdapter(WOLFSPDM_CTX* ctx, byte* buf,
    word32* bufSz)
{
    (void)ctx;
    return wolfSPDM_BuildGetVersion(buf, bufSz);
}

int wolfSPDM_GetVersion(WOLFSPDM_CTX* ctx)
{
    byte txBuf[8];
    byte rxBuf[64];  /* VERSION: 4 hdr + 2 count + up to ~29 entries * 2 */

    return wolfSPDM_ExchangeMsg(ctx, wolfSPDM_BuildGetVersionAdapter,
        wolfSPDM_ParseVersion, txBuf, sizeof(txBuf), rxBuf, sizeof(rxBuf));
}

int wolfSPDM_GetCapabilities(WOLFSPDM_CTX* ctx)
{
    byte txBuf[24];   /* GET_CAPABILITIES: 20 bytes */
    byte rxBuf[40];   /* CAPABILITIES: 20-36 bytes */

    return wolfSPDM_ExchangeMsg(ctx, wolfSPDM_BuildGetCapabilities,
        wolfSPDM_ParseCapabilities, txBuf, sizeof(txBuf), rxBuf, sizeof(rxBuf));
}

int wolfSPDM_NegotiateAlgorithms(WOLFSPDM_CTX* ctx)
{
    byte txBuf[52];   /* NEGOTIATE_ALGORITHMS: 48 B, or 52 with the KEM struct */
    byte rxBuf[80];   /* ALGORITHMS: ~56 bytes with struct tables */
    int rc;
#ifndef NO_WOLFSPDM_CHALLENGE
    int hashRc;
#endif

    rc = wolfSPDM_ExchangeMsg(ctx, wolfSPDM_BuildNegotiateAlgorithms,
        wolfSPDM_ParseAlgorithms, txBuf, sizeof(txBuf), rxBuf, sizeof(rxBuf));
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Save VCA transcript length (GET_VERSION through ALGORITHMS).
     * Used by measurement signature verification per DSP0274. */
    ctx->vcaLen = ctx->transcriptLen;

#ifndef NO_WOLFSPDM_CHALLENGE
    /* Initialize M1/M2 running hash for potential CHALLENGE auth.
     * Start with VCA (A portion of the M1/M2 transcript per DSP0274).
     * Free a stale hash from a prior call so wc_InitSha384 doesn't
     * leak whatever wolfCrypt allocated previously.
     * Non-fatal: challenge just won't work if this fails. */
    if (ctx->flags.m1m2HashInit) {
        wc_Sha384Free(&ctx->m1m2Hash);
        ctx->flags.m1m2HashInit = 0;
    }
    hashRc = wc_InitSha384(&ctx->m1m2Hash);
    if (hashRc == 0) {
        hashRc = wc_Sha384Update(&ctx->m1m2Hash, ctx->transcript,
            ctx->vcaLen);
        if (hashRc == 0) {
            ctx->flags.m1m2HashInit = 1;
        }
        else {
            wc_Sha384Free(&ctx->m1m2Hash);
        }
    }
#endif

    return WOLFSPDM_SUCCESS;
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

    /* Note: GET_DIGESTS/DIGESTS are NOT added to main transcript for TH1,
     * but ARE needed for CHALLENGE M1/M2 (the "B" portion per DSP0274). */
    rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

#ifndef NO_WOLFSPDM_CHALLENGE
    /* Feed GET_DIGESTS request + DIGESTS response to M1/M2 challenge hash */
    if (ctx->flags.m1m2HashInit) {
        wc_Sha384Update(&ctx->m1m2Hash, txBuf, txSz);
        wc_Sha384Update(&ctx->m1m2Hash, rxBuf, rxSz);
    }
#endif

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
    word16 chunkLen;
    word32 iterations = 0;
    /* (WOLFSPDM_MAX_CERT_CHAIN / 1) + slack: every progressing chunk delivers
     * at least 1 byte, so the chain itself bounds the loop. The extra slack
     * absorbs any responder that returns smaller-than-requested chunks. */
    const word32 maxIterations = WOLFSPDM_MAX_CERT_CHAIN + 16;
    int rc;

    /* DSP0274 Sec. 10.3: per-fragment Length must not exceed the responder's
     * negotiated DataTransferSize. Our chunk buffer also caps at 1024. */
    chunkLen = 1024;
    if (ctx->dataTransferSize != 0 && ctx->dataTransferSize < chunkLen) {
        chunkLen = (word16)ctx->dataTransferSize;
    }

    ctx->currentSlotId = (byte)(slotId & 0x0F);

    while (remainderLen > 0) {
        if (++iterations > maxIterations) {
            wolfSPDM_DebugPrint(ctx,
                "GET_CERTIFICATE: iteration cap reached; aborting\n");
            return WOLFSPDM_E_CERT_FAIL;
        }

        txSz = sizeof(txBuf);
        rc = wolfSPDM_BuildGetCertificate(ctx, txBuf, &txSz, slotId, offset,
            chunkLen);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

        rxSz = sizeof(rxBuf);
        rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

#ifndef NO_WOLFSPDM_CHALLENGE
        /* Feed each GET_CERTIFICATE/CERTIFICATE chunk to M1/M2 challenge hash */
        if (ctx->flags.m1m2HashInit) {
            wc_Sha384Update(&ctx->m1m2Hash, txBuf, txSz);
            wc_Sha384Update(&ctx->m1m2Hash, rxBuf, rxSz);
        }
#endif

        rc = wolfSPDM_ParseCertificate(ctx, rxBuf, rxSz, &portionLen, &remainderLen);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }

        /* Forward-progress guard: a responder reporting portionLen=0 with
         * remainderLen>0 is non-compliant and would spin this loop. Per
         * DSP0274 each non-final chunk shall deliver some data. */
        if (portionLen == 0 && remainderLen > 0) {
            wolfSPDM_DebugPrint(ctx,
                "GET_CERTIFICATE: responder returned portionLen=0 with "
                "remainder=%u\n", remainderLen);
            return WOLFSPDM_E_CERT_FAIL;
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

    rc = wolfSPDM_TranscriptAdd(ctx, ctx->certChainHash, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Auto-extract responder public key from leaf cert. Required by every
     * downstream signature check (KEY_EXCHANGE_RSP, MEASUREMENTS, CHALLENGE).
     * Fail hard: a chain we couldn't bind to a public key gives us no
     * identity assurance, so refusing the session is the safe default. */
    if (!ctx->flags.hasResponderPubKey) {
        int keyRc = wolfSPDM_ExtractResponderPubKey(ctx);
        if (keyRc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx,
                "Could not extract responder public key (%d)\n", keyRc);
            return WOLFSPDM_E_CERT_PARSE;
        }
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_KeyExchange(WOLFSPDM_CTX* ctx)
{
    byte txBuf[WOLFSPDM_KEX_REQ_BUF];  /* KEY_EXCHANGE: ~158 B / ML-KEM ek */
    byte rxBuf[WOLFSPDM_SIG_RSP_BUF];  /* KEY_EXCHANGE_RSP (ECDSA ~302 / ML-DSA) */
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Refuse KEY_EXCHANGE without an extracted responder public key:
     * the responder's ECDSA signature would silently skip otherwise,
     * leaving only the HMAC ResponderVerifyData (which proves the peer
     * derived the same DHE secret but not its long-term identity). */
    if (!ctx->flags.hasResponderPubKey) {
        wolfSPDM_DebugPrint(ctx,
            "KEY_EXCHANGE refused: GET_CERTIFICATE must run first\n");
        return WOLFSPDM_E_BAD_STATE;
    }

    /* DSP0274 Sec. 10.13.5: HANDSHAKE_IN_THE_CLEAR is only entered when
     * the requester also opts in (KEY_EXCHANGE Param1 bit set). wolfSPDM
     * never opts in, so the encrypted FINISH_RSP path always applies and
     * a responder merely advertising HANDSHAKE_IN_THE_CLEAR is fine. The
     * separate ResponderVerifyData-in-the-clear parsing path is therefore
     * intentionally unimplemented. */

    rc = wolfSPDM_BuildKeyExchange(ctx, txBuf, &txSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* An ML-KEM encapsulation key makes this request large (up to ~1.6 KB for
     * ML-KEM-1024), unlike the ~158-byte ECDHE request. wolfSPDM implements
     * CHUNK_GET (response reassembly) but not CHUNK_SEND (request
     * fragmentation), so if the request exceeds the responder's advertised
     * DataTransferSize, fail fast with a clear error rather than transmit a
     * non-conformant oversized request (DSP0274 Sec. 10.27). */
    if (ctx->dataTransferSize != 0 && txSz > ctx->dataTransferSize) {
        wolfSPDM_DebugPrint(ctx,
            "KEY_EXCHANGE %u B exceeds responder DataTransferSize %u "
            "(no CHUNK_SEND)\n",
            (unsigned)txSz, (unsigned)ctx->dataTransferSize);
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    rc = wolfSPDM_TranscriptAdd(ctx, txBuf, txSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

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
    /* Cap stack pressure for embedded callers: 1.4 FINISH_RSP carries a
     * u16 OpaqueLength in theory, but spec-aligned responders keep it
     * small. ParseFinishRsp enforces FINISH_RSP_MAX_OPAQUE so we know the
     * decrypted size up front. */
    byte finishBuf[64];   /* FINISH: 4 hdr + 2 OpaqueLen (1.4) + 48 HMAC = 54 */
    byte encBuf[256];     /* Encrypted: hdr(14) + padded(160) + tag(16) = 190 max */
    byte rxBuf[768];      /* Encrypted FINISH_RSP: hdr + ciphertext + tag */
    byte decBuf[512];     /* Decrypted: 4 hdr + 2 OpaqueLen + up to ~500B OpaqueData */
    word32 finishSz = sizeof(finishBuf);
    word32 encSz = sizeof(encBuf);
    word32 rxSz = sizeof(rxBuf);
    word32 decSz = sizeof(decBuf);
    int rc;

    rc = wolfSPDM_BuildFinish(ctx, finishBuf, &finishSz);
    if (rc != WOLFSPDM_SUCCESS) {
        goto cleanup;
    }

    /* FINISH must be sent encrypted (HANDSHAKE_IN_THE_CLEAR not negotiated) */
    /* FINISH is encrypted; use the raw transport so the cleartext chunk hook
     * in wolfSPDM_SendReceive does not inspect the encrypted record. */
    rc = wolfSPDM_EncryptInternal(ctx, finishBuf, finishSz, encBuf, &encSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "FINISH encrypt failed: %d\n", rc);
        goto cleanup;
    }

    rc = wolfSPDM_SendReceiveRaw(ctx, encBuf, encSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "FINISH SendReceive failed: %d\n", rc);
        goto cleanup;
    }

    /* Classify the response: an encrypted record's first 4 bytes are the
     * session ID we just negotiated. Anything else is an unencrypted SPDM
     * message (typically an SPDM_ERROR from the peer). Compare against the
     * session id explicitly rather than relying on the version-byte range
     * heuristic, which can collide if reqSessionId's low byte falls in
     * 0x10-0x1F. */
    if (rxSz >= 4 && SPDM_Get32LE(rxBuf) != ctx->sessionId) {
        if (rxBuf[1] == SPDM_ERROR) {
            ctx->lastPeerErrorCode = rxBuf[2];
            wolfSPDM_DebugPrint(ctx, "FINISH: peer returned SPDM ERROR 0x%02x\n",
                rxBuf[2]);
            rc = WOLFSPDM_E_PEER_ERROR;
            goto cleanup;
        }
        wolfSPDM_DebugPrint(ctx, "FINISH: unexpected response code 0x%02x\n",
            rxBuf[1]);
        rc = WOLFSPDM_E_PEER_ERROR;
        goto cleanup;
    }

    rc = wolfSPDM_DecryptInternal(ctx, rxBuf, rxSz, decBuf, &decSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "FINISH decrypt failed: %d\n", rc);
        goto cleanup;
    }

    rc = wolfSPDM_ParseFinishRsp(ctx, decBuf, decSz);
    if (rc != WOLFSPDM_SUCCESS) {
        goto cleanup;
    }

    /* Derive application data keys (transition from handshake to app phase) */
    rc = wolfSPDM_DeriveAppDataKeys(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "App data key derivation failed: %d\n", rc);
        goto cleanup;
    }
    rc = WOLFSPDM_SUCCESS;

cleanup:
    /* finishBuf holds the requester VerifyData MAC; decBuf holds decrypted
     * FINISH_RSP including the responder VerifyData MAC. Wipe both so the
     * FINISH-stage authentication material does not linger on the stack. */
    wc_ForceZero(finishBuf, sizeof(finishBuf));
    wc_ForceZero(decBuf, sizeof(decBuf));
    return rc;
}

/* --- Measurements (Device Attestation) --- */

#ifndef NO_WOLFSPDM_MEAS

int wolfSPDM_GetMeasurements(WOLFSPDM_CTX* ctx, byte measOperation,
    int requestSignature)
{
    byte txBuf[48];   /* GET_MEASUREMENTS: max 37 bytes (with sig request) */
    byte rxBuf[WOLFSPDM_MAX_MSG_SIZE];
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int errCode;
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Refuse to fetch measurements over an unencrypted channel: device
     * attestation content is sensitive, and the public API is intended for
     * post-session use. Allow STATE_FINISH (intermediate, but session keys
     * have been derived), CONNECTED, and MEASURED. */
    if (ctx->state < WOLFSPDM_STATE_FINISH) {
        wolfSPDM_DebugPrint(ctx,
            "GET_MEASUREMENTS: refusing in state %d (need >= FINISH)\n",
            ctx->state);
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    /* Build GET_MEASUREMENTS request */
    rc = wolfSPDM_BuildGetMeasurements(ctx, txBuf, &txSz,
        measOperation, (byte)requestSignature);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

#ifndef NO_WOLFSPDM_MEAS_VERIFY
    /* Save request message for L1 transcript (signature verification) */
    if (txSz <= sizeof(ctx->measReqMsg)) {
        XMEMCPY(ctx->measReqMsg, txBuf, txSz);
        ctx->measReqMsgSz = txSz;
    }
#endif

    /* Send over the secured channel; the state guard above already ensures
     * session keys are installed. */
    rc = wolfSPDM_SecuredExchange(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "GET_MEASUREMENTS exchange failed: %d\n", rc);
        return rc;
    }

    /* Check for SPDM_ERROR before parsing - SPDM error responses are only
     * 4 bytes, which would be rejected by ParseMeasurements's minimum-size
     * check (8 bytes) as WOLFSPDM_E_INVALID_ARG. Catch it here so the
     * caller sees the more accurate PEER_ERROR. Stash the responder's
     * error code so callers can retrieve it via wolfSPDM_GetLastPeerError
     * (e.g. back off on BUSY, abort on UNSUPPORTED_REQUEST). */
    errCode = 0;
    if (wolfSPDM_CheckError(rxBuf, rxSz, &errCode)) {
        ctx->lastPeerErrorCode = (byte)errCode;
        wolfSPDM_DebugPrint(ctx,
            "GET_MEASUREMENTS: responder error 0x%02x\n", errCode);
        return WOLFSPDM_E_PEER_ERROR;
    }

    /* Parse the response */
    rc = wolfSPDM_ParseMeasurements(ctx, rxBuf, rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

#ifndef NO_WOLFSPDM_MEAS_VERIFY
    /* Verify signature if requested and signature was captured */
    if (requestSignature && ctx->measSignatureSize > 0) {
        if (!ctx->flags.hasResponderPubKey) {
            wolfSPDM_DebugPrint(ctx,
                "No responder public key - cannot verify signature\n");
            return WOLFSPDM_E_MEAS_NOT_VERIFIED;
        }

        rc = wolfSPDM_VerifyMeasurementSig(ctx, rxBuf, rxSz,
            ctx->measReqMsg, ctx->measReqMsgSz);
        if (rc != WOLFSPDM_SUCCESS) {
            /* Pass through CRYPTO_FAIL vs MEAS_SIG_FAIL distinction. */
            return rc;
        }

        ctx->state = WOLFSPDM_STATE_MEASURED;
        return WOLFSPDM_SUCCESS;  /* Verified! */
    }
#else
    (void)requestSignature;
#endif /* !NO_WOLFSPDM_MEAS_VERIFY */

    /* DSP0274: when the caller did not request a signature, treat the
     * retrieval as success. Reserve WOLFSPDM_E_MEAS_NOT_VERIFIED for the
     * case where verification was requested but cannot be performed (no
     * responder public key, or build compiled without verify support). */
    ctx->state = WOLFSPDM_STATE_MEASURED;
    if (requestSignature) {
        return WOLFSPDM_E_MEAS_NOT_VERIFIED;
    }
    return WOLFSPDM_SUCCESS;
}

#endif /* !NO_WOLFSPDM_MEAS */

/* --- Challenge Authentication (Sessionless Attestation) --- */

#ifndef NO_WOLFSPDM_CHALLENGE

int wolfSPDM_Challenge(WOLFSPDM_CTX* ctx, int slotId, byte measHashType)
{
    byte txBuf[48];   /* CHALLENGE: 36 bytes (1.2) or 44 bytes (1.3+) */
    byte rxBuf[WOLFSPDM_SIG_RSP_BUF];  /* CHALLENGE_AUTH (ECDSA ~300 / ML-DSA) */
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    word32 sigOffset = 0;
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Need cert chain for signature verification */
    if (ctx->state < WOLFSPDM_STATE_CERT) {
        return WOLFSPDM_E_BAD_STATE;
    }

    if (!ctx->flags.hasResponderPubKey) {
        wolfSPDM_DebugPrint(ctx,
            "CHALLENGE: No responder public key for verification\n");
        return WOLFSPDM_E_CHALLENGE;
    }

    /* If trusted CAs are loaded, anchor the responder's leaf cert against
     * the trust store before CHALLENGE issues. Otherwise the caller is
     * trusting whatever leaf cert the responder shipped. */
    if (ctx->flags.hasTrustedCAs) {
        rc = wolfSPDM_ValidateCertChain(ctx);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx,
                "CHALLENGE: cert chain validation failed (%d)\n", rc);
            return rc;
        }
    }

    /* Build CHALLENGE request */
    rc = wolfSPDM_BuildChallenge(ctx, txBuf, &txSz, slotId, measHashType);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "Sending CHALLENGE (slot=%d, measHash=0x%02x)\n",
        slotId, measHashType);

    /* Cleartext exchange (no session needed) */
    rc = wolfSPDM_SendReceive(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "CHALLENGE: SendReceive failed: %d\n", rc);
        return rc;
    }

    /* Parse CHALLENGE_AUTH response */
    rc = wolfSPDM_ParseChallengeAuth(ctx, rxBuf, rxSz, &sigOffset);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Verify signature */
    rc = wolfSPDM_VerifyChallengeAuthSig(ctx, rxBuf, rxSz,
        txBuf, txSz, sigOffset);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "CHALLENGE authentication PASSED\n");
    return WOLFSPDM_SUCCESS;
}

#endif /* !NO_WOLFSPDM_CHALLENGE */

/* --- Heartbeat (Session Keep-Alive) --- */

int wolfSPDM_Heartbeat(WOLFSPDM_CTX* ctx)
{
    byte txBuf[8];
    byte rxBuf[32];
    word32 txSz = sizeof(txBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state != WOLFSPDM_STATE_CONNECTED
#ifndef NO_WOLFSPDM_MEAS
        && ctx->state != WOLFSPDM_STATE_MEASURED
#endif
        ) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    rc = wolfSPDM_BuildHeartbeat(ctx, txBuf, &txSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Must be sent over encrypted channel */
    rc = wolfSPDM_SecuredExchange(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "HEARTBEAT: SecuredExchange failed: %d\n", rc);
        return rc;
    }

    return wolfSPDM_ParseHeartbeatAck(ctx, rxBuf, rxSz);
}

/* --- Key Update (Session Key Rotation) --- */

int wolfSPDM_KeyUpdate(WOLFSPDM_CTX* ctx, int updateAll)
{
    byte txBuf[8];
    byte rxBuf[32];
    byte encBuf[64];
    byte rawRxBuf[64];
    /* Snapshot the request-side keying material so a failed ACK decrypt
     * can roll the session back to the pre-update state instead of
     * leaving requester and responder permanently desynchronised. The
     * responder side is only mutated when updateAll is set, so the rsp
     * snapshot is only relevant in that branch. */
    byte savedReqDataKey[WOLFSPDM_AEAD_KEY_SIZE];
    byte savedReqDataIv[WOLFSPDM_AEAD_IV_SIZE];
    byte savedReqAppSecret[WOLFSPDM_HASH_SIZE];
    byte savedRspDataKey[WOLFSPDM_AEAD_KEY_SIZE];
    byte savedRspDataIv[WOLFSPDM_AEAD_IV_SIZE];
    byte savedRspAppSecret[WOLFSPDM_HASH_SIZE];
    word64 savedReqSeqNum;
    word64 savedRspSeqNum;
    word32 txSz, rxSz, encSz, rawRxSz;
    byte tag, tag2;
    byte operation;
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state != WOLFSPDM_STATE_CONNECTED
#ifndef NO_WOLFSPDM_MEAS
        && ctx->state != WOLFSPDM_STATE_MEASURED
#endif
        ) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    operation = updateAll ? SPDM_KEY_UPDATE_OP_UPDATE_ALL_KEYS
                          : SPDM_KEY_UPDATE_OP_UPDATE_KEY;

    /* Step 1: Send KEY_UPDATE encrypted with CURRENT req key */
    txSz = sizeof(txBuf);
    rc = wolfSPDM_BuildKeyUpdate(ctx, txBuf, &txSz, operation, &tag);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "Sending KEY_UPDATE\n");

    encSz = sizeof(encBuf);
    rawRxSz = sizeof(rawRxBuf);
    savedReqSeqNum = ctx->reqSeqNum;
    savedRspSeqNum = ctx->rspSeqNum;

    XMEMCPY(savedReqDataKey, ctx->reqDataKey, sizeof(savedReqDataKey));
    XMEMCPY(savedReqDataIv, ctx->reqDataIv, sizeof(savedReqDataIv));
    XMEMCPY(savedReqAppSecret, ctx->reqAppSecret, sizeof(savedReqAppSecret));
    XMEMCPY(savedRspDataKey, ctx->rspDataKey, sizeof(savedRspDataKey));
    XMEMCPY(savedRspDataIv, ctx->rspDataIv, sizeof(savedRspDataIv));
    XMEMCPY(savedRspAppSecret, ctx->rspAppSecret, sizeof(savedRspAppSecret));

    /* Encrypt with current req key */
    rc = wolfSPDM_EncryptInternal(ctx, txBuf, txSz, encBuf, &encSz);
    if (rc != WOLFSPDM_SUCCESS) {
        goto kupd_cleanup;
    }

    /* Send and receive raw (don't decrypt yet) */
    rc = wolfSPDM_SendReceiveRaw(ctx, encBuf, encSz, rawRxBuf, &rawRxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "KEY_UPDATE: SendReceive failed: %d\n", rc);
        goto kupd_cleanup;
    }

    /* Step 2: Derive new keys BEFORE decrypting ACK.
     * The responder derives new keys upon receiving KEY_UPDATE and
     * encrypts the ACK with the NEW response key. */
    rc = wolfSPDM_DeriveUpdatedKeys(ctx, updateAll);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "KEY_UPDATE: DeriveUpdatedKeys failed: %d\n", rc);
        goto kupd_cleanup;
    }
    /* Per DSP0277 Sec 11: reset only the seqNum for directions whose
     * keys actually rotated. updateAll=0 (UpdateKey) only rotates the
     * requester's send-direction; the responder keeps incrementing its
     * old rspSeqNum until UpdateAll happens. */
    ctx->reqSeqNum = 0;
    if (updateAll) {
        ctx->rspSeqNum = 0;
    }

    /* Decrypt ACK with new rsp key. If this fails, roll the session
     * back to the pre-update keys / seqNums - otherwise a single failed
     * ACK leaves the requester and responder permanently desynchronised
     * (DoS). */
    rxSz = sizeof(rxBuf);
    rc = wolfSPDM_DecryptInternal(ctx, rawRxBuf, rawRxSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx,
            "KEY_UPDATE: ACK decrypt failed (%d); rolling keys back\n", rc);
        XMEMCPY(ctx->reqDataKey, savedReqDataKey, sizeof(savedReqDataKey));
        XMEMCPY(ctx->reqDataIv, savedReqDataIv, sizeof(savedReqDataIv));
        XMEMCPY(ctx->reqAppSecret, savedReqAppSecret,
            sizeof(savedReqAppSecret));
        if (updateAll) {
            XMEMCPY(ctx->rspDataKey, savedRspDataKey, sizeof(savedRspDataKey));
            XMEMCPY(ctx->rspDataIv, savedRspDataIv, sizeof(savedRspDataIv));
            XMEMCPY(ctx->rspAppSecret, savedRspAppSecret,
                sizeof(savedRspAppSecret));
        }
        ctx->reqSeqNum = savedReqSeqNum;
        ctx->rspSeqNum = savedRspSeqNum;
    }

kupd_cleanup:
    wc_ForceZero(savedReqDataKey, sizeof(savedReqDataKey));
    wc_ForceZero(savedReqDataIv, sizeof(savedReqDataIv));
    wc_ForceZero(savedReqAppSecret, sizeof(savedReqAppSecret));
    wc_ForceZero(savedRspDataKey, sizeof(savedRspDataKey));
    wc_ForceZero(savedRspDataIv, sizeof(savedRspDataIv));
    wc_ForceZero(savedRspAppSecret, sizeof(savedRspAppSecret));
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rc = wolfSPDM_ParseKeyUpdateAck(ctx, rxBuf, rxSz, operation, tag);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Step 3: Verify new key works (send VERIFY_NEW_KEY with new keys) */
    txSz = sizeof(txBuf);
    rc = wolfSPDM_BuildKeyUpdate(ctx, txBuf, &txSz,
        SPDM_KEY_UPDATE_OP_VERIFY_NEW_KEY, &tag2);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rxSz = sizeof(rxBuf);
    rc = wolfSPDM_SecuredExchange(ctx, txBuf, txSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "KEY_UPDATE: VerifyNewKey exchange failed: %d\n", rc);
        return rc;
    }

    rc = wolfSPDM_ParseKeyUpdateAck(ctx, rxBuf, rxSz,
        SPDM_KEY_UPDATE_OP_VERIFY_NEW_KEY, tag2);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "KEY_UPDATE completed, new keys active\n");
    return WOLFSPDM_SUCCESS;
}
