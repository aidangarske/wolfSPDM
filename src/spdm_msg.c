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
#include <wolfssl/wolfcrypt/asn.h>

int wolfSPDM_BuildGetVersion(byte* buf, word32* bufSz)
{
    /* Note: ctx is not used for GET_VERSION, check buf/bufSz directly */
    if (buf == NULL || bufSz == NULL || *bufSz < 4)
        return WOLFSPDM_E_BUFFER_SMALL;

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
    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 20);

    XMEMSET(buf, 0, 20);
    buf[0] = ctx->spdmVersion;  /* Use negotiated version */
    buf[1] = SPDM_GET_CAPABILITIES;
    buf[2] = 0x00;
    buf[3] = 0x00;
    /* CTExponent and reserved at offsets 4-7 */

    /* Requester flags (4 bytes LE) */
    SPDM_Set32LE(&buf[8], ctx->reqCaps);

    /* DataTransferSize (4 LE): with chunking we advertise the MTU so the
     * responder splits anything larger (which we reassemble); without it we
     * advertise the full message size. */
#ifdef WOLFSPDM_HAVE_CHUNK
    SPDM_Set32LE(&buf[12], WOLFSPDM_CHUNK_BUF_SIZE);
#else
    SPDM_Set32LE(&buf[12], WOLFSPDM_MAX_MSG_SIZE);
#endif
    /* MaxSPDMmsgSize (4 LE): largest logical (reassembled) message we accept */
    SPDM_Set32LE(&buf[16], WOLFSPDM_MAX_MSG_SIZE);

    *bufSz = 20;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_BuildNegotiateAlgorithms(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 48);

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

#ifdef WOLFSPDM_HAVE_MLDSA
    /* DSP0274 1.4 Table 19: PqcAsymAlgo (8-byte field at offset 16). Advertise
     * ML-DSA-44/65/87 alongside ECDSA (dual-stack); the responder selects
     * exactly one across BaseAsymAlgo and PqcAsymAlgo. Bytes 16-31 are
     * reserved-zero before 1.4, so only emit the selection there. */
    if (ctx->spdmVersion >= SPDM_VERSION_14) {
        buf[16] = (byte)(SPDM_PQC_ASYM_ALGO_ML_DSA_44 |
                         SPDM_PQC_ASYM_ALGO_ML_DSA_65 |
                         SPDM_PQC_ASYM_ALGO_ML_DSA_87);
    }
#endif

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

static int wolfSPDM_BuildSimpleMsg(WOLFSPDM_CTX* ctx, byte msgCode,
    byte* buf, word32* bufSz)
{
    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 4);
    buf[0] = ctx->spdmVersion;
    buf[1] = msgCode;
    buf[2] = 0x00;
    buf[3] = 0x00;
    *bufSz = 4;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_BuildGetDigests(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    return wolfSPDM_BuildSimpleMsg(ctx, SPDM_GET_DIGESTS, buf, bufSz);
}

int wolfSPDM_BuildGetCertificate(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    int slotId, word16 offset, word16 length)
{
    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 8);

    buf[0] = ctx->spdmVersion;  /* Use negotiated version */
    buf[1] = SPDM_GET_CERTIFICATE;
    buf[2] = (byte)(slotId & 0x0F);
    buf[3] = 0x00;
    SPDM_Set16LE(&buf[4], offset);
    SPDM_Set16LE(&buf[6], length);
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

    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 180);

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
    /* SlotIDParam: authenticate the slot selected during GET_CERTIFICATE.
     * Hard-coding 0 would break responders whose DIGESTS SlotMask omits
     * slot 0 (the requester would then KEY_EXCHANGE against a different
     * or empty slot than the one whose chain it just fetched). */
    buf[offset++] = (byte)(ctx->currentSlotId & 0x0F);

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

    /* OpaqueData for secured message version negotiation. DSP0277 v1.2 is
     * the current spec, defining secured-message versions 1.0, 1.1, 1.2.
     * Higher SPDM control versions reuse the 1.2 secured-message format;
     * there is no DSP0277 1.3 or 1.4. OpaqueLength must be a multiple of
     * 4 per DSP0274 - the 20-byte fixed block satisfies that. */
    buf[offset++] = 0x14;  /* OpaqueLength = 20 */
    buf[offset++] = 0x00;
    buf[offset++] = 0x01; buf[offset++] = 0x00;  /* TotalElements */
    buf[offset++] = 0x00; buf[offset++] = 0x00;  /* Reserved */
    buf[offset++] = 0x00; buf[offset++] = 0x00;
    buf[offset++] = 0x09; buf[offset++] = 0x00;  /* DataSize */
    buf[offset++] = 0x01;  /* Registry ID = DMTF */
    buf[offset++] = 0x01;  /* VendorLen */
    buf[offset++] = 0x03; buf[offset++] = 0x00;  /* VersionCount */
    buf[offset++] = 0x10; buf[offset++] = 0x00;  /* 1.0 */
    buf[offset++] = 0x11; buf[offset++] = 0x00;  /* 1.1 */
    buf[offset++] = 0x12; buf[offset++] = 0x00;  /* 1.2 */
    buf[offset++] = 0x00; buf[offset++] = 0x00;  /* Padding to mult of 4 */

    *bufSz = offset;
    return WOLFSPDM_SUCCESS;
}

/* --- Shared Signing Helpers --- */

/* Size of the negotiated signature field (DSP0274 1.4 Table 19 SigLen). */
static word32 wolfSPDM_GetSigSize(const WOLFSPDM_CTX* ctx)
{
#ifdef WOLFSPDM_HAVE_MLDSA
    if (ctx->asymType == WOLFSPDM_ASYM_MLDSA) {
        if (ctx->pqcAsymSel == SPDM_PQC_ASYM_ALGO_ML_DSA_44) {
            return WOLFSPDM_MLDSA44_SIG_SIZE;
        }
        if (ctx->pqcAsymSel == SPDM_PQC_ASYM_ALGO_ML_DSA_87) {
            return WOLFSPDM_MLDSA87_SIG_SIZE;
        }
        return WOLFSPDM_MLDSA65_SIG_SIZE;
    }
#else
    (void)ctx;
#endif
    return WOLFSPDM_ECC_SIG_SIZE;
}

/* Assemble the SPDM 1.2+ data_to_be_signed message M per DSP0274 Sec. 15:
 * M = combined_spdm_prefix || message_hash
 *   combined_spdm_prefix = "dmtf-spdm-v1.X.*" x4 (64) || zero_pad || spdm_context
 *                          (100 bytes total)
 *   message_hash = inputDigest (Hash of data_to_be_signed, 48 bytes SHA-384)
 * contextStr already carries the "responder-"/"requester-" spdm_context prefix.
 * outMsg must hold >= 148 bytes. */
static int wolfSPDM_BuildSignedMsg(byte spdmVersion,
    const char* contextStr, word32 contextStrLen,
    const byte* inputDigest, byte* outMsg, word32* outMsgLen)
{
    word32 signMsgLen = 0;
    word32 zeroPadLen;
    byte majorVer, minorVer;
    int i;

    /* Reject overlong context strings before computing zeroPadLen (which
     * is 36 - contextStrLen and would underflow). */
    if (contextStr == NULL || contextStrLen > 36 ||
        outMsg == NULL || outMsgLen == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    majorVer = (byte)('0' + ((spdmVersion >> 4) & 0xF));
    minorVer = (byte)('0' + (spdmVersion & 0xF));

    /* spdm_prefix: "dmtf-spdm-v1.X.*" x4 = 64 bytes */
    for (i = 0; i < 4; i++) {
        XMEMCPY(&outMsg[signMsgLen], "dmtf-spdm-v1.2.*", 16);
        outMsg[signMsgLen + 11] = majorVer;
        outMsg[signMsgLen + 13] = minorVer;
        outMsg[signMsgLen + 15] = '*';
        signMsgLen += 16;
    }

    /* Zero padding: 36 - contextStrLen bytes (combined prefix is 100 bytes) */
    zeroPadLen = 36 - contextStrLen;
    XMEMSET(&outMsg[signMsgLen], 0x00, zeroPadLen);
    signMsgLen += zeroPadLen;

    /* spdm_context string */
    XMEMCPY(&outMsg[signMsgLen], contextStr, contextStrLen);
    signMsgLen += contextStrLen;

    /* message_hash */
    XMEMCPY(&outMsg[signMsgLen], inputDigest, WOLFSPDM_HASH_SIZE);
    signMsgLen += WOLFSPDM_HASH_SIZE;

    *outMsgLen = signMsgLen;
    return WOLFSPDM_SUCCESS;
}

/* Build the pre-hashed signing input used by RSA/ECDSA: outputDigest = Hash(M).
 * ECDSA hashes M internally, so verify_hash takes Hash(M). */
static int wolfSPDM_BuildSignedHash(byte spdmVersion,
    const char* contextStr, word32 contextStrLen,
    const byte* inputDigest, byte* outputDigest)
{
    byte signMsg[200]; /* 64 + 36 + 48 = 148 bytes max */
    word32 signMsgLen = 0;
    int rc;

    rc = wolfSPDM_BuildSignedMsg(spdmVersion, contextStr, contextStrLen,
        inputDigest, signMsg, &signMsgLen);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_Sha384Hash(outputDigest, signMsg, signMsgLen,
            NULL, 0, NULL, 0);
    }
    /* signMsg embeds the inputDigest (a transcript-state hash). Wipe it
     * before returning so the assembled signing input does not linger on
     * the stack frame. */
    wc_ForceZero(signMsg, sizeof(signMsg));
    return rc;
}

/* Verify an SPDM ECDSA signature (raw r||s format) against a digest
 * using the responder's public key stored in ctx. */
static int wolfSPDM_VerifyEccSig(WOLFSPDM_CTX* ctx,
    const byte* sigRaw, word32 sigRawSz,
    const byte* digest, word32 digestSz)
{
    byte derSig[256];
    word32 derSigSz = sizeof(derSig);
    const byte* sigR = sigRaw;
    const byte* sigS = sigRaw + (sigRawSz / 2);
    int verified = 0;
    int rc;

    rc = wc_ecc_rs_raw_to_sig(sigR, sigRawSz / 2,
        sigS, sigRawSz / 2, derSig, &derSigSz);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "ECC rs_raw_to_sig failed: %d\n", rc);
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    rc = wc_ecc_verify_hash(derSig, derSigSz, digest, digestSz,
        &verified, &ctx->responderPubKey.ecc);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "ECC verify_hash failed: %d\n", rc);
        /* Internal wolfCrypt failure (memory pressure, missing curve, etc.)
         * - distinguish from an actual bad signature so the caller doesn't
         * impeach the responder identity over a transient infra issue. */
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    /* verified == 1 means the signature is good; 0 means tamper/wrong key. */
    return (verified == 1) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_BAD_SIGNATURE;
}

/* ECDSA signing tail: hash M, then verify the raw r||s signature. */
static int wolfSPDM_VerifyEcdsaSigned(WOLFSPDM_CTX* ctx,
    const char* contextStr, word32 contextStrLen,
    byte* digest, const byte* sig, word32 sigSz)
{
    int rc = wolfSPDM_BuildSignedHash(ctx->spdmVersion, contextStr,
        contextStrLen, digest, digest);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_VerifyEccSig(ctx, sig, sigSz, digest, WOLFSPDM_HASH_SIZE);
    }
    return rc;
}

#ifdef WOLFSPDM_HAVE_MLDSA
/* Verify an SPDM ML-DSA signature against message_hash using the responder's
 * ML-DSA public key. Per DSP0274 1.4 Sec. 15.5, SPDM uses Algorithm 2 (pure
 * ML-DSA.Sign), NOT the pre-hash variant: M = combined_spdm_prefix ||
 * message_hash, and the ML-DSA ctx parameter is spdm_context (contextStr). */
static int wolfSPDM_VerifyMlDsaSig(WOLFSPDM_CTX* ctx,
    const char* contextStr, word32 contextStrLen,
    const byte* messageHash, const byte* sig, word32 sigSz)
{
    byte signMsg[200]; /* combined_spdm_prefix(100) + message_hash(48) = 148 */
    word32 signMsgLen = 0;
    int verified = 0;
    int rc;

    rc = wolfSPDM_BuildSignedMsg(ctx->spdmVersion, contextStr, contextStrLen,
        messageHash, signMsg, &signMsgLen);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wc_MlDsaKey_VerifyCtx(&ctx->responderPubKey.mldsa, sig, sigSz,
            (const byte*)contextStr, (byte)contextStrLen,
            signMsg, signMsgLen, &verified);
        if (rc != 0) {
            wolfSPDM_DebugPrint(ctx, "ML-DSA VerifyCtx failed: %d\n", rc);
            rc = WOLFSPDM_E_CRYPTO_FAIL;
        }
        else {
            rc = (verified == 1) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_BAD_SIGNATURE;
        }
    }
    /* signMsg embeds message_hash (transcript-state). Wipe before return. */
    wc_ForceZero(signMsg, sizeof(signMsg));
    return rc;
}
#endif /* WOLFSPDM_HAVE_MLDSA */

/* Verify an SPDM signature over message_hash using whichever asymmetric family
 * the responder selected in NEGOTIATE_ALGORITHMS. digest holds message_hash;
 * the ECDSA path overwrites it with Hash(M). Returns the raw verify rc. */
static int wolfSPDM_VerifySig(WOLFSPDM_CTX* ctx,
    const char* contextStr, word32 contextStrLen,
    byte* digest, const byte* sig, word32 sigSz)
{
#ifdef WOLFSPDM_HAVE_MLDSA
    if (ctx->asymType == WOLFSPDM_ASYM_MLDSA) {
        return wolfSPDM_VerifyMlDsaSig(ctx, contextStr, contextStrLen,
            digest, sig, sigSz);
    }
#endif
    return wolfSPDM_VerifyEcdsaSigned(ctx, contextStr, contextStrLen,
        digest, sig, sigSz);
}

int wolfSPDM_BuildFinish(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    byte th2Hash[WOLFSPDM_HASH_SIZE];
    byte verifyData[WOLFSPDM_HASH_SIZE];
    word32 offset = 4;  /* Start after header */
    word32 minSz;
    int rc;

    /* Check arguments first before any ctx dereference */
    if (ctx == NULL || buf == NULL || bufSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Check buffer size: header(4) + [OpaqueLength(2) for 1.4+] + HMAC(48) */
    minSz = 4 + WOLFSPDM_HASH_SIZE;  /* header + HMAC */
    if (ctx->spdmVersion >= SPDM_VERSION_14)
        minSz += 2;  /* OpaqueLength */
    if (*bufSz < minSz)
        return WOLFSPDM_E_BUFFER_SMALL;

    /* Build FINISH header (mutual auth not supported in standard requester) */
    buf[0] = ctx->spdmVersion;
    buf[1] = SPDM_FINISH;
    buf[2] = 0x00;  /* Param1: No signature */
    buf[3] = 0x00;  /* Param2: SlotID = 0 when no signature */

    /* SPDM 1.4 adds OpaqueLength(2) + OpaqueData(var) after header */
    if (ctx->spdmVersion >= SPDM_VERSION_14) {
        buf[offset++] = 0x00;  /* OpaqueLength = 0 (LE) */
        buf[offset++] = 0x00;
    }

    /* Add FINISH header (+ OpaqueLength for 1.4) to transcript for TH2 */
    rc = wolfSPDM_TranscriptAdd(ctx, buf, offset);
    if (rc != WOLFSPDM_SUCCESS) {
        goto cleanup;
    }

    /* TH2 = Hash(transcript with FINISH header) */
    rc = wolfSPDM_TranscriptHash(ctx, th2Hash);
    if (rc != WOLFSPDM_SUCCESS) {
        goto cleanup;
    }

    /* RequesterVerifyData = HMAC(reqFinishedKey, TH2) where TH2 is the
     * transcript hash through the FINISH header. */
    rc = wolfSPDM_ComputeVerifyData(ctx->reqFinishedKey, th2Hash, verifyData);
    if (rc != WOLFSPDM_SUCCESS) {
        goto cleanup;
    }

    XMEMCPY(&buf[offset], verifyData, WOLFSPDM_HASH_SIZE);
    offset += WOLFSPDM_HASH_SIZE;

    /* Add RequesterVerifyData to transcript for TH2_final (app data key derivation) */
    rc = wolfSPDM_TranscriptAdd(ctx, verifyData, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        goto cleanup;
    }

    *bufSz = offset;
    rc = WOLFSPDM_SUCCESS;

cleanup:
    /* th2Hash is the FINISH transcript-state digest; verifyData is the
     * requester FINISH MAC keyed with reqFinishedKey. Both must not linger
     * on the stack frame after this call returns. */
    wc_ForceZero(th2Hash, sizeof(th2Hash));
    wc_ForceZero(verifyData, sizeof(verifyData));
    return rc;
}

int wolfSPDM_BuildEndSession(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    return wolfSPDM_BuildSimpleMsg(ctx, SPDM_END_SESSION, buf, bufSz);
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
    word16 maxEntries;
    byte highestVersion = 0;  /* No version found yet */
    byte maxVer;
    word32 i;

    SPDM_CHECK_PARSE_OR_ERROR_ARGS(ctx, buf, bufSz, 6);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_VERSION, WOLFSPDM_E_VERSION_MISMATCH);

    /* Parse VERSION response:
     * Offset 4-5: VersionNumberEntryCount (LE)
     * Offset 6+: VersionNumberEntry array (2 bytes each, LE) */
    entryCount = SPDM_Get16LE(&buf[4]);

    /* Cap entryCount to what actually fits in the buffer to prevent
     * overflow on exotic compilers where i*2 could wrap */
    maxEntries = (word16)((bufSz - 6) / 2);
    if (entryCount > maxEntries) {
        entryCount = maxEntries;
    }

    /* Find highest mutually supported version.
     * Per DSP0274, negotiated version must be the highest version
     * that both sides support. We support WOLFSPDM_MIN_SPDM_VERSION
     * through WOLFSPDM_MAX_SPDM_VERSION (or ctx->maxVersion if set). */
    maxVer = (ctx->maxVersion != 0) ? ctx->maxVersion
                                    : WOLFSPDM_MAX_SPDM_VERSION;
    for (i = 0; i < entryCount; i++) {
        /* Each entry is 2 bytes; high byte (offset +1) is Major.Minor */
        byte ver = buf[6 + i * 2 + 1];
        if (ver >= WOLFSPDM_MIN_SPDM_VERSION &&
            ver <= maxVer &&
            ver > highestVersion) {
            highestVersion = ver;
        }
    }

    /* If no mutually supported version found, fail */
    if (highestVersion == 0) {
        wolfSPDM_DebugPrint(ctx, "No mutually supported SPDM version found "
            "(require >= 0x%02x)\n", WOLFSPDM_MIN_SPDM_VERSION);
        return WOLFSPDM_E_VERSION_MISMATCH;
    }

    ctx->spdmVersion = highestVersion;
    ctx->state = WOLFSPDM_STATE_VERSION;

    wolfSPDM_DebugPrint(ctx, "Negotiated SPDM version: 0x%02x\n", ctx->spdmVersion);
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseCapabilities(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    SPDM_CHECK_PARSE_OR_ERROR_ARGS(ctx, buf, bufSz, 12);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_CAPABILITIES, WOLFSPDM_E_CAPS_MISMATCH);

    /* DSP0274 Table 12: CAPABILITIES response layout
     *   buf[4]:    CTExponent
     *   buf[8-11]: Flags (rspCaps)
     *   buf[12-15]: DataTransferSize (SPDM 1.2+)
     *   buf[16-19]: MaxSPDMmsgSize   (SPDM 1.2+)
     * The 1.2+ fields are populated when the response carries them; pre-1.2
     * leaves them as 0 and downstream paths fall back to fixed defaults. */
    ctx->ctExponent = buf[4];
    ctx->rspCaps = SPDM_Get32LE(&buf[8]);
    if (ctx->spdmVersion >= SPDM_VERSION_12 && bufSz >= 20) {
        ctx->dataTransferSize = SPDM_Get32LE(&buf[12]);
        ctx->maxSpdmMsgSize   = SPDM_Get32LE(&buf[16]);
    }
    ctx->state = WOLFSPDM_STATE_CAPS;

    wolfSPDM_DebugPrint(ctx, "Responder caps: 0x%08x\n", ctx->rspCaps);
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseAlgorithms(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    word32 baseAsymAlgo;
    word32 baseHashAlgo;
    word32 pqcAsymSel;
    word16 declaredLen;
    byte numAlgs;
    byte extAsymCount;
    byte extHashCount;
    byte ai;
    word32 algStart;
    word32 off;
    int dheOk = 0;
    int aeadOk = 0;
    int ksOk = 0;

    SPDM_CHECK_PARSE_OR_ERROR_ARGS(ctx, buf, bufSz, 36);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_ALGORITHMS, WOLFSPDM_E_ALGO_MISMATCH);

    /* DSP0274 Table 18: Length (offset 4-5, LE) is the entire response size
     * including header. Reject responses whose declared length does not
     * match the received buffer. */
    declaredLen = SPDM_Get16LE(&buf[4]);
    if (declaredLen != bufSz) {
        wolfSPDM_DebugPrint(ctx,
            "ALGORITHMS: declared Length %u != bufSz %u\n",
            declaredLen, bufSz);
        return WOLFSPDM_E_ALGO_MISMATCH;
    }

    /* DSP0274 Table 18 offsets 6-7: MeasurementSpecificationSel and
     * OtherParamsSel. We advertise DMTF (0x01) and OpaqueDataFormat1 (0x02)
     * in NEGOTIATE_ALGORITHMS; reject responders that select a different
     * bit or zero. */
    if (buf[6] != 0x01) {
        wolfSPDM_DebugPrint(ctx,
            "ALGORITHMS: MeasurementSpecificationSel != DMTF (0x%02x)\n",
            buf[6]);
        return WOLFSPDM_E_ALGO_MISMATCH;
    }
    if (ctx->spdmVersion >= SPDM_VERSION_12 && buf[7] != 0x02) {
        wolfSPDM_DebugPrint(ctx,
            "ALGORITHMS: OtherParamsSel != OpaqueDataFormat1 (0x%02x)\n",
            buf[7]);
        return WOLFSPDM_E_ALGO_MISMATCH;
    }

    /* Validate negotiated algorithms match Algorithm Set B.
     * ALGORITHMS response layout (DSP0274 Table 18):
     *   Offset 8-11:  MeasurementHashAlgo (4 LE)
     *   Offset 12-15: BaseAsymSel (4 LE)
     *   Offset 16-19: BaseHashSel (4 LE)
     * Note: Response has MeasurementHashAlgo before BaseAsymSel,
     * unlike the request which has BaseAsymAlgo at offset 8. */
    baseAsymAlgo = SPDM_Get32LE(&buf[12]);
    baseHashAlgo = SPDM_Get32LE(&buf[16]);

    /* Defensive: a second NEGOTIATE_ALGORITHMS via the fine-grained API could
     * flip asymType while a responder key from a prior round is still live,
     * which would later free the wrong union member. Drop any live key first
     * so the union member always matches the asymType set below. */
    if (ctx->flags.hasResponderPubKey) {
        wolfSPDM_FreeResponderPubKey(ctx);
        ctx->flags.hasResponderPubKey = 0;
    }

    /* DSP0274 1.4 Table 20: PqcAsymSel (offset 20). Present from 1.4; earlier
     * versions leave these bytes reserved-zero. The spec caps the combined
     * bit count of BaseAsymSel and PqcAsymSel at one, so exactly one of the
     * two fields carries the selected signature algorithm. */
    pqcAsymSel = 0;
    if (ctx->spdmVersion >= SPDM_VERSION_14) {
        pqcAsymSel = SPDM_Get32LE(&buf[20]);
    }

    if (pqcAsymSel != 0) {
#ifdef WOLFSPDM_HAVE_MLDSA
        if (baseAsymAlgo != 0) {
            wolfSPDM_DebugPrint(ctx,
                "ALGORITHMS: BaseAsymSel and PqcAsymSel both set "
                "(0x%08x/0x%08x)\n", baseAsymAlgo, pqcAsymSel);
            return WOLFSPDM_E_ALGO_MISMATCH;
        }
        if (pqcAsymSel != SPDM_PQC_ASYM_ALGO_ML_DSA_44 &&
            pqcAsymSel != SPDM_PQC_ASYM_ALGO_ML_DSA_65 &&
            pqcAsymSel != SPDM_PQC_ASYM_ALGO_ML_DSA_87) {
            wolfSPDM_DebugPrint(ctx,
                "ALGORITHMS: unsupported PqcAsymSel (0x%08x)\n", pqcAsymSel);
            return WOLFSPDM_E_ALGO_MISMATCH;
        }
        ctx->asymType = WOLFSPDM_ASYM_MLDSA;
        ctx->pqcAsymSel = pqcAsymSel;
#else
        wolfSPDM_DebugPrint(ctx,
            "ALGORITHMS: PqcAsymSel set but ML-DSA not built in (0x%08x)\n",
            pqcAsymSel);
        return WOLFSPDM_E_ALGO_MISMATCH;
#endif
    }
    else {
        /* Per DSP0274 Table 18, BaseAsymSel carries the responder's SELECTED
         * algorithm - exactly one bit. Strict equality enforces Algorithm
         * Set B rather than accepting any superset. */
        if (baseAsymAlgo != SPDM_ASYM_ALGO_ECDSA_P384) {
            wolfSPDM_DebugPrint(ctx,
                "ALGORITHMS: BaseAsymSel != ECDSA_P384 (0x%08x)\n",
                baseAsymAlgo);
            return WOLFSPDM_E_ALGO_MISMATCH;
        }
        ctx->asymType = WOLFSPDM_ASYM_ECDSA;
        ctx->pqcAsymSel = 0;
    }
    if (baseHashAlgo != SPDM_HASH_ALGO_SHA_384) {
        wolfSPDM_DebugPrint(ctx,
            "ALGORITHMS: BaseHashSel != SHA_384 (0x%08x)\n", baseHashAlgo);
        return WOLFSPDM_E_ALGO_MISMATCH;
    }

    /* AlgStruct tables follow the fixed-size response header. Walk them
     * and confirm DHE, AEAD, and KeySchedule selections are Algorithm
     * Set B (SECP_384_R1 / AES_256_GCM / SPDM). Require all three to be
     * present and match - a responder offering AlgStructCount=0 must not
     * bypass the Set-B contract. Layout per DSP0274 Table 18:
     *   each struct: AlgType(1) | AlgCount(1) | AlgSupported(2 LE) | ext...
     *
     * DSP0274 Table 18: ExtAsymSelCount (buf[32]) + ExtHashSelCount
     * (buf[33]) push the AlgStruct array past the fixed 36 bytes.
     * Skip both ExtAsym/ExtHash tables (each entry is 4 bytes) before
     * walking AlgStructs. */
    numAlgs = buf[2];  /* Param1 = AlgStructCount */
    extAsymCount = (bufSz >= 33) ? buf[32] : 0;
    extHashCount = (bufSz >= 34) ? buf[33] : 0;
    algStart = (word32)36 +
        (word32)extAsymCount * 4 + (word32)extHashCount * 4;
    if (algStart > bufSz) {
        return WOLFSPDM_E_ALGO_MISMATCH;
    }
    off = algStart;
    for (ai = 0; ai < numAlgs && off + 4 <= bufSz; ai++) {
        byte algType  = buf[off];
        byte algCount = buf[off + 1];
        word16 algSel = SPDM_Get16LE(&buf[off + 2]);
        /* Per DSP0274 Table 16: AlgCount low nibble = ExtAlgCount
         * (each ExtAlg is 4 bytes); high nibble = fixed-size marker
         * (= 2 in current spec). Use the LOW nibble for extLen. */
        word32 extLen = ((word32)(algCount & 0x0F)) * 4;
        switch (algType) {
            case SPDM_ALG_TYPE_DHE:
                if (algSel != SPDM_DHE_ALGO_SECP384R1) {
                    wolfSPDM_DebugPrint(ctx,
                        "ALGORITHMS: DHE not SECP_384_R1 (0x%04x)\n", algSel);
                    return WOLFSPDM_E_ALGO_MISMATCH;
                }
                dheOk = 1;
                break;
            case SPDM_ALG_TYPE_AEAD:
                if (algSel != SPDM_AEAD_ALGO_AES_256_GCM) {
                    wolfSPDM_DebugPrint(ctx,
                        "ALGORITHMS: AEAD not AES_256_GCM (0x%04x)\n", algSel);
                    return WOLFSPDM_E_ALGO_MISMATCH;
                }
                aeadOk = 1;
                break;
            case SPDM_ALG_TYPE_KEY_SCHEDULE:
                if (algSel != SPDM_KEY_SCHEDULE_SPDM) {
                    wolfSPDM_DebugPrint(ctx,
                        "ALGORITHMS: KeySchedule not SPDM (0x%04x)\n", algSel);
                    return WOLFSPDM_E_ALGO_MISMATCH;
                }
                ksOk = 1;
                break;
            default: break;
        }
        off += 4 + extLen;
    }
    if (!dheOk || !aeadOk || !ksOk) {
        wolfSPDM_DebugPrint(ctx,
            "ALGORITHMS: missing required AlgStruct(s) dhe=%d aead=%d ks=%d\n",
            dheOk, aeadOk, ksOk);
        return WOLFSPDM_E_ALGO_MISMATCH;
    }

    wolfSPDM_DebugPrint(ctx, "ALGORITHMS: BaseAsym=0x%08x BaseHash=0x%08x\n",
        baseAsymAlgo, baseHashAlgo);

    ctx->state = WOLFSPDM_STATE_ALGO;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseDigests(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    SPDM_CHECK_PARSE_OR_ERROR_ARGS(ctx, buf, bufSz, 4);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_DIGESTS, WOLFSPDM_E_CERT_FAIL);

    /* DSP0274 Sec. 10.5: Param1 = SlotMask, bit i = slot i populated.
     * Stash it so GetCertificate can pick a populated slot rather than
     * blindly requesting slot 0. */
    ctx->slotMask = buf[2];
    ctx->state = WOLFSPDM_STATE_DIGESTS;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseCertificate(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz,
    word16* portionLen, word16* remainderLen)
{
    if (portionLen == NULL || remainderLen == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Use the shared parse-or-error helper so a 4-byte SPDM_ERROR is allowed
     * to fall through to SPDM_CHECK_RESPONSE, which surfaces it as
     * WOLFSPDM_E_PEER_ERROR and stashes the responder error code. */
    SPDM_CHECK_PARSE_OR_ERROR_ARGS(ctx, buf, bufSz, 8);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_CERTIFICATE, WOLFSPDM_E_CERT_FAIL);

    /* DSP0274 Sec. 10.6: Param1[3:0] echoes the SlotID the requester asked
     * for. A responder returning a different slot's chain could trick us
     * into validating the wrong identity. */
    if ((buf[2] & 0x0F) != (ctx->currentSlotId & 0x0F)) {
        wolfSPDM_DebugPrint(ctx,
            "CERTIFICATE: SlotID echo mismatch (got %u, expected %u)\n",
            buf[2] & 0x0F, ctx->currentSlotId & 0x0F);
        return WOLFSPDM_E_CERT_FAIL;
    }

    *portionLen = SPDM_Get16LE(&buf[4]);
    *remainderLen = SPDM_Get16LE(&buf[6]);

    /* Reject truncated chunks - returning success here would let GetCertificate
     * advance offset by a portionLen that was never actually delivered, and
     * eventually advance state with a partial chain. */
    if (*portionLen > 0) {
        int rc;
        if (bufSz < (word32)(8 + *portionLen)) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }
        rc = wolfSPDM_CertChainAdd(ctx, buf + 8, *portionLen);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }
    }

    if (*remainderLen == 0) {
        ctx->state = WOLFSPDM_STATE_CERT;
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseKeyExchangeRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    static const char sigCtx[] = "responder-key_exchange_rsp signing";
    word16 opaqueLen;
    word32 sigOffset;
    word32 keRspPartialLen;
    byte peerPubKeyX[WOLFSPDM_ECC_KEY_SIZE];
    byte peerPubKeyY[WOLFSPDM_ECC_KEY_SIZE];
    const byte* signature;
    const byte* rspVerifyData;
    byte expectedHmac[WOLFSPDM_HASH_SIZE];
    byte th1Partial[WOLFSPDM_HASH_SIZE];
    word32 sigSize;
    int rc;

    SPDM_CHECK_PARSE_OR_ERROR_ARGS(ctx, buf, bufSz, 140);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_KEY_EXCHANGE_RSP, WOLFSPDM_E_KEY_EXCHANGE);

    /* Defensive: the new in-parser signature verification dereferences
     * ctx->responderPubKey. Internal callers (wolfSPDM_KeyExchange) gate
     * on hasResponderPubKey, but enforce it here too so any future direct
     * caller fails cleanly instead of dereferencing an uninitialized key. */
    if (!ctx->flags.hasResponderPubKey) {
        return WOLFSPDM_E_BAD_STATE;
    }

    sigSize = wolfSPDM_GetSigSize(ctx);

    /* MutAuthRequested (offset 6) per DSP0274 Table 35. We don't implement
     * the requester-signed FINISH path; refuse before committing sessionId
     * so a rejected handshake doesn't leak partial session state into ctx. */
    if (buf[6] != 0) {
        wolfSPDM_DebugPrint(ctx, "Responder requested mutual auth (%02x); "
            "not supported in this build\n", buf[6]);
        return WOLFSPDM_E_KEY_EXCHANGE;
    }

    /* Compute and validate the layout BEFORE committing any ctx fields so
     * a truncated response doesn't leak partial sessionId/peer-key state. */
    opaqueLen = SPDM_Get16LE(&buf[136]);
    sigOffset = 138 + opaqueLen;
    keRspPartialLen = sigOffset;

    if (bufSz < sigOffset + sigSize + WOLFSPDM_HASH_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Now safe to commit session state. */
    ctx->rspSessionId = SPDM_Get16LE(&buf[4]);
    ctx->sessionId = (word32)ctx->reqSessionId | ((word32)ctx->rspSessionId << 16);

    /* Extract responder's ephemeral public key (offset 40 = 4+2+1+1+32) */
    XMEMCPY(peerPubKeyX, &buf[40], WOLFSPDM_ECC_KEY_SIZE);
    XMEMCPY(peerPubKeyY, &buf[88], WOLFSPDM_ECC_KEY_SIZE);

    signature = buf + sigOffset;
    rspVerifyData = buf + sigOffset + sigSize;

    /* Add KEY_EXCHANGE_RSP partial (without sig/verify) to transcript */
    rc = wolfSPDM_TranscriptAdd(ctx, buf, keRspPartialLen);
    if (rc != WOLFSPDM_SUCCESS) {
        goto cleanup;
    }

    /* Verify responder signature per DSP0274 Sec 14: signature is over the
     * partial transcript hash with context "responder-key_exchange_rsp
     * signing", using the negotiated asym family (ECDSA or ML-DSA).
     * wolfSPDM_KeyExchange refuses to proceed without a parsed cert chain,
     * so hasResponderPubKey is always true here. */
    rc = wolfSPDM_TranscriptHash(ctx, th1Partial);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_VerifySig(ctx, sigCtx, (word32)(sizeof(sigCtx) - 1),
            th1Partial, signature, sigSize);
        if (rc != WOLFSPDM_SUCCESS) {
            wolfSPDM_DebugPrint(ctx,
                "KEY_EXCHANGE_RSP signature verification failed (rc=%d)\n",
                rc);
        }
        else {
            wolfSPDM_DebugPrint(ctx,
                "KEY_EXCHANGE_RSP signature verified\n");
        }
    }
    if (rc != WOLFSPDM_SUCCESS) {
        goto cleanup;
    }

    /* Add signature to transcript (TH1 includes signature) */
    rc = wolfSPDM_TranscriptAdd(ctx, signature, sigSize);
    if (rc != WOLFSPDM_SUCCESS) {
        goto cleanup;
    }

    /* Compute ECDH shared secret */
    rc = wolfSPDM_ComputeSharedSecret(ctx, peerPubKeyX, peerPubKeyY);
    if (rc != WOLFSPDM_SUCCESS) {
        goto cleanup;
    }

    /* Compute TH1 = Hash(transcript including signature) */
    rc = wolfSPDM_TranscriptHash(ctx, ctx->th1);
    if (rc != WOLFSPDM_SUCCESS) {
        goto cleanup;
    }
    /* Derive all session keys */
    rc = wolfSPDM_DeriveHandshakeKeys(ctx, ctx->th1);
    if (rc != WOLFSPDM_SUCCESS) {
        goto cleanup;
    }

    /* Verify ResponderVerifyData = HMAC(rspFinishedKey, TH1) */
    rc = wolfSPDM_ComputeVerifyData(ctx->rspFinishedKey, ctx->th1, expectedHmac);
    if (rc != WOLFSPDM_SUCCESS) {
        goto cleanup;
    }

    /* Constant-time compare to avoid leaking HMAC bytes via timing. */
    if (wolfSPDM_ConstCompare(expectedHmac, rspVerifyData,
            WOLFSPDM_HASH_SIZE) != 0) {
        wolfSPDM_DebugPrint(ctx, "ResponderVerifyData MISMATCH\n");
        rc = WOLFSPDM_E_BAD_HMAC;
        goto cleanup;
    }
    wolfSPDM_DebugPrint(ctx, "ResponderVerifyData VERIFIED OK\n");

    /* Add ResponderVerifyData to transcript (per SPDM spec, always included) */
    rc = wolfSPDM_TranscriptAdd(ctx, rspVerifyData, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        goto cleanup;
    }

    ctx->state = WOLFSPDM_STATE_KEY_EX;
    rc = WOLFSPDM_SUCCESS;

cleanup:
    /* expectedHmac is derived from rspFinishedKey; wipe regardless of path.
     * th1Partial is intermediate handshake material - wipe it too so it does
     * not linger on the stack frame. */
    wc_ForceZero(expectedHmac, sizeof(expectedHmac));
    wc_ForceZero(peerPubKeyX, sizeof(peerPubKeyX));
    wc_ForceZero(peerPubKeyY, sizeof(peerPubKeyY));
    wc_ForceZero(th1Partial, sizeof(th1Partial));
    return rc;
}

int wolfSPDM_ParseFinishRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    SPDM_CHECK_PARSE_OR_ERROR_ARGS(ctx, buf, bufSz, 4);

    if (buf[1] == SPDM_FINISH_RSP) {
        int addRc;
        word32 rspMsgLen = 4;

        /* SPDM 1.4 adds OpaqueLength(2) + OpaqueData(var) to FINISH_RSP.
         * Cap accepted OpaqueData size to keep wolfSPDM_Finish's decBuf
         * footprint bounded. Per DSP0274 the field is u16 (theoretical
         * 65535) but real responders keep it small. */
        if (ctx->spdmVersion >= SPDM_VERSION_14) {
            word16 opaqueLen;
            if (bufSz < 6) {
                return WOLFSPDM_E_BUFFER_SMALL;
            }
            opaqueLen = SPDM_Get16LE(&buf[4]);
            if (opaqueLen > 256) {
                wolfSPDM_DebugPrint(ctx,
                    "FINISH_RSP: OpaqueLength %u exceeds 256B cap\n", opaqueLen);
                return WOLFSPDM_E_BUFFER_SMALL;
            }
            rspMsgLen = 4 + 2 + opaqueLen;
            if (bufSz < rspMsgLen) {
                return WOLFSPDM_E_BUFFER_SMALL;
            }
        }

        /* Add FINISH_RSP (header + OpaqueData for 1.4) to transcript */
        addRc = wolfSPDM_TranscriptAdd(ctx, buf, rspMsgLen);
        if (addRc != WOLFSPDM_SUCCESS) {
            return addRc;
        }
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

/* --- Measurement Message Building and Parsing --- */

#ifndef NO_WOLFSPDM_MEAS

int wolfSPDM_BuildGetMeasurements(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    byte operation, byte requestSig)
{
    word32 offset = 0;
    word32 minSz;

    if (ctx == NULL || buf == NULL || bufSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Size: 4 header + (requestSig ? 32 nonce + 1 slotId : 0)
     * SPDM 1.3+ adds RequesterContext(8) always. OpaqueDataLength is NOT
     * part of GET_MEASUREMENTS request per DSP0274 Table 51 / libspdm. */
    minSz = 4;
    if (requestSig) {
        minSz += 32 + 1;  /* Nonce + SlotIDParam */
    }
    if (ctx->spdmVersion >= SPDM_VERSION_13) {
        minSz += 8;       /* RequesterContext (always for 1.3+) */
    }
    if (*bufSz < minSz)
        return WOLFSPDM_E_BUFFER_SMALL;

    buf[offset++] = ctx->spdmVersion;
    buf[offset++] = SPDM_GET_MEASUREMENTS;
    /* Param1: bit 0 = signature requested */
    buf[offset++] = requestSig ? SPDM_MEAS_REQUEST_SIG_BIT : 0x00;
    /* Param2: MeasurementOperation */
    buf[offset++] = operation;

    if (requestSig) {
        /* Nonce (32 bytes) */
        int rc = wolfSPDM_GetRandom(ctx, &buf[offset], 32);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }
        XMEMCPY(ctx->measNonce, &buf[offset], 32);
        offset += 32;

        /* SlotIDParam: the slot whose certificate authenticates the
         * measurement signature. Must match the slot chosen during
         * GET_CERTIFICATE (ctx->currentSlotId) so the responder signs
         * with the key whose chain we hold. */
        buf[offset++] = (byte)(ctx->currentSlotId & 0x0F);
    }

    /* DSP0274 v1.3.0 Table 50 / v1.4.0 Table 49: RequesterContext (8 bytes)
     * is appended to GET_MEASUREMENTS for SPDM 1.3 and above, REGARDLESS of
     * whether a signature was requested. The MEASUREMENTS response echoes
     * these bytes back between OpaqueData and Signature; ParseMeasurements
     * skips over them. The signature already covers RequesterContext, so
     * we don't separately verify the echo here. */
    if (ctx->spdmVersion >= SPDM_VERSION_13) {
        int rc = wolfSPDM_GetRandom(ctx, &buf[offset], 8);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }
        offset += 8;
    }

    *bufSz = offset;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseMeasurements(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz)
{
    word32 offset;
    byte numBlocks;
    word32 recordLen;
    word32 recordEnd;
    word32 blockIdx;
    word32 sigSize;

    SPDM_CHECK_PARSE_OR_ERROR_ARGS(ctx, buf, bufSz, 8);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_MEASUREMENTS, WOLFSPDM_E_MEASUREMENT);

    /* DSP0274: Param2[3:0] echoes the SlotID the requester sent. The
     * requester picks ctx->currentSlotId for signed requests, so reject
     * any other slot value. */
    if ((buf[3] & 0x0F) != (ctx->currentSlotId & 0x0F)) {
        wolfSPDM_DebugPrint(ctx,
            "MEASUREMENTS: SlotID echo mismatch (got %u expected %u)\n",
            buf[3] & 0x0F, ctx->currentSlotId & 0x0F);
        return WOLFSPDM_E_MEASUREMENT;
    }

    numBlocks = buf[4];
    /* MeasurementRecordLength: 3 bytes LE at offset 5..7 */
    recordLen = (word32)buf[5] | ((word32)buf[6] << 8) | ((word32)buf[7] << 16);

    wolfSPDM_DebugPrint(ctx, "MEASUREMENTS: numBlocks=%u, recordLen=%u\n",
        numBlocks, recordLen);

    /* Validate record fits in buffer */
    if (8 + recordLen > bufSz) {
        wolfSPDM_DebugPrint(ctx, "MEASUREMENTS: recordLen %u exceeds bufSz %u\n",
            recordLen, bufSz);
        return WOLFSPDM_E_MEASUREMENT;
    }

    recordEnd = 8 + recordLen;
    offset = 8;  /* Start of measurement record */
    ctx->measBlockCount = 0;

    /* Parse each measurement block */
    for (blockIdx = 0; blockIdx < numBlocks; blockIdx++) {
        word16 measSize;

        /* Check block header fits */
        if (offset + WOLFSPDM_MEAS_BLOCK_HDR_SIZE > recordEnd) {
            wolfSPDM_DebugPrint(ctx, "MEASUREMENTS: block %u header truncated\n",
                blockIdx);
            return WOLFSPDM_E_MEASUREMENT;
        }

        /* Read block header: Index(1) + MeasSpec(1) + MeasSize(2 LE) */
        measSize = SPDM_Get16LE(&buf[offset + 2]);

        /* Check block data fits */
        if (offset + WOLFSPDM_MEAS_BLOCK_HDR_SIZE + measSize > recordEnd) {
            wolfSPDM_DebugPrint(ctx, "MEASUREMENTS: block %u data truncated\n",
                blockIdx);
            return WOLFSPDM_E_MEASUREMENT;
        }

        /* Store if we have room */
        if (ctx->measBlockCount < WOLFSPDM_MAX_MEAS_BLOCKS) {
            WOLFSPDM_MEAS_BLOCK* blk = &ctx->measBlocks[ctx->measBlockCount];
            blk->index = buf[offset];
            blk->measurementSpec = buf[offset + 1];

            /* Parse DMTF measurement value if MeasSpec==1 and size >= 3 */
            if (blk->measurementSpec == 0x01 && measSize >= 3) {
                word16 valueSize;
                word16 copySize;

                blk->dmtfType = buf[offset + WOLFSPDM_MEAS_BLOCK_HDR_SIZE];
                valueSize = (word16)(
                    buf[offset + WOLFSPDM_MEAS_BLOCK_HDR_SIZE + 1] |
                    (buf[offset + WOLFSPDM_MEAS_BLOCK_HDR_SIZE + 2] << 8));

                /* Validate valueSize against measSize */
                if (valueSize > measSize - 3) {
                    wolfSPDM_DebugPrint(ctx,
                        "MEASUREMENTS: block %u valueSize %u > measSize-3 %u\n",
                        blockIdx, valueSize, measSize - 3);
                    return WOLFSPDM_E_MEASUREMENT;
                }

                /* Truncate if value exceeds our buffer */
                copySize = valueSize;
                if (copySize > WOLFSPDM_MAX_MEAS_VALUE_SIZE) {
                    copySize = WOLFSPDM_MAX_MEAS_VALUE_SIZE;
                }
                blk->valueSize = copySize;
                XMEMCPY(blk->value,
                    &buf[offset + WOLFSPDM_MEAS_BLOCK_HDR_SIZE + 3], copySize);
            }
            else {
                /* Non-DMTF or too small: store raw */
                word16 copySize = measSize;
                blk->dmtfType = 0;
                if (copySize > WOLFSPDM_MAX_MEAS_VALUE_SIZE) {
                    copySize = WOLFSPDM_MAX_MEAS_VALUE_SIZE;
                }
                blk->valueSize = copySize;
                if (copySize > 0) {
                    XMEMCPY(blk->value,
                        &buf[offset + WOLFSPDM_MEAS_BLOCK_HDR_SIZE], copySize);
                }
            }

            ctx->measBlockCount++;
        }
        else {
            wolfSPDM_DebugPrint(ctx,
                "MEASUREMENTS: block %u exceeds MAX_MEAS_BLOCKS (%u), skipping\n",
                blockIdx, WOLFSPDM_MAX_MEAS_BLOCKS);
        }

        offset += WOLFSPDM_MEAS_BLOCK_HDR_SIZE + measSize;
    }

    /* After measurement record: Nonce(32) + OpaqueDataLength(2) + OpaqueData
     * + [RequesterContext(8) for 1.3+] + Signature(96). Nonce/Sig only
     * appear when signature was requested. Distinguish the two cases by
     * whether the response carries ANY tail bytes:
     *   - offset == bufSz: unsigned request, no tail. Accepted.
     *   - bufSz > offset: signed request - the FULL tail must be present;
     *     a partial tail is a truncated/malformed response. */
    ctx->measSignatureSize = 0;

    if (offset == bufSz) {
        /* Unsigned measurement response - no tail expected. */
    }
    else if (offset + 32 + 2 > bufSz) {
        wolfSPDM_DebugPrint(ctx, "MEASUREMENTS: signed tail truncated\n");
        return WOLFSPDM_E_MEASUREMENT;
    }
    else {
        /* Nonce (32 bytes) - skip, we already have our own in ctx->measNonce */
        offset += 32;

        /* OpaqueDataLength (2 LE) */
        word16 opaqueLen = SPDM_Get16LE(&buf[offset]);
        offset += 2;

        /* Skip opaque data */
        if (offset + opaqueLen > bufSz) {
            wolfSPDM_DebugPrint(ctx, "MEASUREMENTS: opaque data truncated\n");
            return WOLFSPDM_E_MEASUREMENT;
        }
        offset += opaqueLen;

        /* DSP0274 1.3+ Table 50 mandates an 8-byte RequesterContext echo
         * between OpaqueData and Signature. Require room for the 8 bytes
         * but NOT for the signature - unsigned measurements omit the sig
         * tail and must still parse. The Signature copy below remains
         * conditional on its own bufSz check. */
        if (ctx->spdmVersion >= SPDM_VERSION_13) {
            if (offset + 8 > bufSz) {
                wolfSPDM_DebugPrint(ctx,
                    "MEASUREMENTS: 1.3+ response missing RequesterContext\n");
                return WOLFSPDM_E_MEASUREMENT;
            }
            offset += 8;
        }

        /* Signature (if present). Size is the negotiated SigLen (ECDSA or
         * ML-DSA); the stored copy bounds at WOLFSPDM_MAX_SIG_SIZE. */
        sigSize = wolfSPDM_GetSigSize(ctx);
        if (offset + sigSize <= bufSz) {
            XMEMCPY(ctx->measSignature, &buf[offset], sigSize);
            ctx->measSignatureSize = sigSize;
        }
    }

    ctx->flags.hasMeasurements = 1;
    wolfSPDM_DebugPrint(ctx, "MEASUREMENTS: parsed %u blocks\n",
        ctx->measBlockCount);

    return WOLFSPDM_SUCCESS;
}

#ifndef NO_WOLFSPDM_MEAS_VERIFY

/* Shared tail: BuildSignedHash -> VerifyEccSig -> debug print -> return */
static int wolfSPDM_VerifySignedDigest(WOLFSPDM_CTX* ctx,
    const char* contextStr, word32 contextStrLen,
    byte* digest,  /* in: message_hash (ECDSA path overwrites it) */
    const byte* sig, word32 sigSz,
    const char* passMsg, const char* failMsg, int failErr)
{
    int rc = wolfSPDM_VerifySig(ctx, contextStr, contextStrLen,
        digest, sig, sigSz);

    if (rc == WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "%s\n", passMsg);
        return WOLFSPDM_SUCCESS;
    }
    wolfSPDM_DebugPrint(ctx, "%s\n", failMsg);
    /* Preserve CRYPTO_FAIL (transient infra) vs BAD_SIGNATURE (peer-level
     * violation) - only the latter gets mapped to the caller's domain
     * error code (MEAS_SIG_FAIL / CHALLENGE). */
    return (rc == WOLFSPDM_E_BAD_SIGNATURE) ? failErr : rc;
}

int wolfSPDM_VerifyMeasurementSig(WOLFSPDM_CTX* ctx,
    const byte* rspBuf, word32 rspBufSz,
    const byte* reqMsg, word32 reqMsgSz)
{
    byte digest[WOLFSPDM_HASH_SIZE];
    word32 sigOffset;
    word32 sigSize;
    int rc;

    if (ctx == NULL || rspBuf == NULL || reqMsg == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.hasResponderPubKey) {
        return WOLFSPDM_E_MEAS_NOT_VERIFIED;
    }

    /* Signature is the last SigLen bytes of the response (ECDSA or ML-DSA) */
    sigSize = wolfSPDM_GetSigSize(ctx);
    if (rspBufSz < sigSize) {
        return WOLFSPDM_E_MEASUREMENT;
    }
    sigOffset = rspBufSz - sigSize;

    /* Compute L1||L2 hash per DSP0274 Section 10.11.1:
     * L1/L2 = VCA || GET_MEASUREMENTS_request || MEASUREMENTS_response(before sig) */
    rc = wolfSPDM_Sha384Hash(digest,
        ctx->transcript, ctx->vcaLen,
        reqMsg, reqMsgSz,
        rspBuf, sigOffset);
    if (rc == WOLFSPDM_SUCCESS) {
        rc = wolfSPDM_VerifySignedDigest(ctx,
            "responder-measurements signing", 30, digest,
            rspBuf + sigOffset, sigSize,
            "Measurement signature VERIFIED",
            "Measurement signature INVALID",
            WOLFSPDM_E_MEAS_SIG_FAIL);
    }
    wc_ForceZero(digest, sizeof(digest));
    return rc;
}

#endif /* !NO_WOLFSPDM_MEAS_VERIFY */
#endif /* !NO_WOLFSPDM_MEAS */

/* --- Responder Public Key Extraction ---
 * Extract responder's ECC P-384 public key from the leaf certificate in the
 * SPDM certificate chain. Used by both measurement signature verification
 * and CHALLENGE authentication, so it lives outside measurement guards. */

/* Helper: find leaf cert in SPDM cert chain buffer.
 * SPDM cert chain header: Length(2 LE) + Reserved(2) + RootHash(48) = 52 bytes
 * After header: concatenated DER certificates, leaf is the last one. */
static int wolfSPDM_FindLeafCert(const byte* certChain, word32 certChainLen,
    const byte** leafCert, word32* leafCertSz)
{
    const byte* certDer;
    word32 certDerSz;
    word32 pos;
    const byte* lastCert;
    word32 lastCertSz;

    if (certChainLen <= 52) {
        return WOLFSPDM_E_CERT_PARSE;
    }

    certDer = certChain + 52;
    certDerSz = certChainLen - 52;
    lastCert = certDer;
    lastCertSz = certDerSz;
    pos = 0;

    while (pos < certDerSz) {
        word32 certLen;
        word32 hdrLen;

        if (certDer[pos] != 0x30) {
            break;
        }

        if (pos + 1 >= certDerSz) break;

        if (certDer[pos + 1] < 0x80) {
            certLen = certDer[pos + 1];
            hdrLen = 2;
        }
        else if (certDer[pos + 1] == 0x81) {
            if (pos + 2 >= certDerSz) break;
            certLen = certDer[pos + 2];
            hdrLen = 3;
        }
        else if (certDer[pos + 1] == 0x82) {
            if (pos + 3 >= certDerSz) break;
            certLen = ((word32)certDer[pos + 2] << 8) | certDer[pos + 3];
            hdrLen = 4;
        }
        else if (certDer[pos + 1] == 0x83) {
            if (pos + 4 >= certDerSz) break;
            certLen = ((word32)certDer[pos + 2] << 16) |
                      ((word32)certDer[pos + 3] << 8) | certDer[pos + 4];
            hdrLen = 5;
        }
        else {
            break;
        }

        if (pos + hdrLen + certLen > certDerSz) break;

        lastCert = certDer + pos;
        lastCertSz = hdrLen + certLen;
        pos += hdrLen + certLen;
    }

    *leafCert = lastCert;
    *leafCertSz = lastCertSz;
    return WOLFSPDM_SUCCESS;
}

/* Import the ECDSA P-384 public key from the parsed leaf cert. */
static int wolfSPDM_ImportEccPubKey(WOLFSPDM_CTX* ctx, DecodedCert* cert)
{
    word32 idx = 0;
    int rc = wc_ecc_init(&ctx->responderPubKey.ecc);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }
    rc = wc_EccPublicKeyDecode(cert->publicKey, &idx,
        &ctx->responderPubKey.ecc, cert->pubKeySize);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "ECC public key decode failed: %d\n", rc);
        wc_ecc_free(&ctx->responderPubKey.ecc);
        return WOLFSPDM_E_CERT_PARSE;
    }
    wolfSPDM_DebugPrint(ctx, "Extracted responder ECC P-384 public key\n");
    return WOLFSPDM_SUCCESS;
}

#ifdef WOLFSPDM_HAVE_MLDSA
/* Import the ML-DSA public key from the parsed leaf cert. The parameter set
 * is pinned from the negotiated PqcAsymSel, so a cert whose AlgorithmIdentifier
 * OID names a different level is rejected by the decoder. */
static int wolfSPDM_ImportMlDsaPubKey(WOLFSPDM_CTX* ctx, DecodedCert* cert)
{
    word32 idx = 0;
    byte level;
    int rc;

    if (ctx->pqcAsymSel == SPDM_PQC_ASYM_ALGO_ML_DSA_44) {
        level = WC_ML_DSA_44;
    }
    else if (ctx->pqcAsymSel == SPDM_PQC_ASYM_ALGO_ML_DSA_87) {
        level = WC_ML_DSA_87;
    }
    else {
        level = WC_ML_DSA_65;
    }

    rc = wc_MlDsaKey_Init(&ctx->responderPubKey.mldsa, NULL, INVALID_DEVID);
    if (rc == 0) {
        rc = wc_MlDsaKey_SetParams(&ctx->responderPubKey.mldsa, level);
    }
    if (rc != 0) {
        wc_MlDsaKey_Free(&ctx->responderPubKey.mldsa);
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    rc = wc_MlDsaKey_PublicKeyDecode(&ctx->responderPubKey.mldsa,
        cert->publicKey, cert->pubKeySize, &idx);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "ML-DSA public key decode failed: %d\n", rc);
        wc_MlDsaKey_Free(&ctx->responderPubKey.mldsa);
        return WOLFSPDM_E_CERT_PARSE;
    }
    wolfSPDM_DebugPrint(ctx, "Extracted responder ML-DSA public key (level %u)\n",
        level);
    return WOLFSPDM_SUCCESS;
}
#endif /* WOLFSPDM_HAVE_MLDSA */

int wolfSPDM_ExtractResponderPubKey(WOLFSPDM_CTX* ctx)
{
    DecodedCert cert;
    const byte* leafCert;
    word32 leafCertSz;
    int rc;

    if (ctx == NULL || ctx->certChainLen == 0) {
        return WOLFSPDM_E_CERT_PARSE;
    }

    /* Find the leaf (last) certificate in the SPDM cert chain */
    rc = wolfSPDM_FindLeafCert(ctx->certChain, ctx->certChainLen,
        &leafCert, &leafCertSz);
    if (rc != WOLFSPDM_SUCCESS) {
        wolfSPDM_DebugPrint(ctx, "Certificate chain too short for header\n");
        return rc;
    }

    /* Parse the leaf certificate */
    wc_InitDecodedCert(&cert, leafCert, leafCertSz, NULL);
    rc = wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "Certificate parse failed: %d\n", rc);
        wc_FreeDecodedCert(&cert);
        return WOLFSPDM_E_CERT_PARSE;
    }

    /* Import the responder verify key for whichever family was negotiated. */
#ifdef WOLFSPDM_HAVE_MLDSA
    if (ctx->asymType == WOLFSPDM_ASYM_MLDSA) {
        rc = wolfSPDM_ImportMlDsaPubKey(ctx, &cert);
    }
    else {
        rc = wolfSPDM_ImportEccPubKey(ctx, &cert);
    }
#else
    rc = wolfSPDM_ImportEccPubKey(ctx, &cert);
#endif

    wc_FreeDecodedCert(&cert);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    ctx->flags.hasResponderPubKey = 1;
    return WOLFSPDM_SUCCESS;
}

/* --- Certificate Chain Validation --- */

int wolfSPDM_ValidateCertChain(WOLFSPDM_CTX* ctx)
{
    byte caHash[WOLFSPDM_HASH_SIZE];
    const byte* chainRootHash;
    int rc;

    if (ctx == NULL || ctx->certChainLen == 0) {
        return WOLFSPDM_E_CERT_PARSE;
    }

    if (!ctx->flags.hasTrustedCAs) {
        return WOLFSPDM_E_CERT_PARSE;
    }

    /* SPDM cert chain header: Length(2 LE) + Reserved(2) + RootHash(48) */
    if (ctx->certChainLen <= 52) {
        return WOLFSPDM_E_CERT_PARSE;
    }

    /* Validate the root hash against our trusted CA */
    rc = wolfSPDM_Sha384Hash(caHash, ctx->trustedCAs, ctx->trustedCAsSz,
        NULL, 0, NULL, 0);
    if (rc != WOLFSPDM_SUCCESS) return rc;

    chainRootHash = ctx->certChain + 4;  /* Skip Length(2) + Reserved(2) */
    if (XMEMCMP(caHash, chainRootHash, WOLFSPDM_HASH_SIZE) != 0) {
        wolfSPDM_DebugPrint(ctx,
            "Root cert hash mismatch - chain not from trusted CA\n");
        return WOLFSPDM_E_CERT_PARSE;
    }

    wolfSPDM_DebugPrint(ctx, "Root certificate hash VERIFIED against trusted CA\n");

    /* Extract public key from the leaf cert. GetCertificate already
     * ran ExtractResponderPubKey, so skip the re-init - calling
     * wc_ecc_init on an already-initialized key leaks the previous
     * key's internal allocations. */
    if (!ctx->flags.hasResponderPubKey) {
        rc = wolfSPDM_ExtractResponderPubKey(ctx);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }
    }

    wolfSPDM_DebugPrint(ctx, "Certificate chain validated\n");
    return WOLFSPDM_SUCCESS;
}

/* --- Challenge Authentication (DSP0274 Section 10.8) --- */

#ifndef NO_WOLFSPDM_CHALLENGE

int wolfSPDM_BuildChallenge(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    int slotId, byte measHashType)
{
    word32 offset = 0;
    word32 minSz;
    int rc;

    if (ctx == NULL || buf == NULL || bufSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* SPDM 1.3+ adds RequesterContext(8) per DSP0274 Table 46 */
    minSz = 36;
    if (ctx->spdmVersion >= SPDM_VERSION_13)
        minSz += 8;  /* RequesterContext */
    if (*bufSz < minSz)
        return WOLFSPDM_E_BUFFER_SMALL;

    buf[offset++] = ctx->spdmVersion;
    buf[offset++] = SPDM_CHALLENGE;
    buf[offset++] = (byte)(slotId & 0x0F);
    buf[offset++] = measHashType;

    /* Save measHashType + slotId for ParseChallengeAuth echo check */
    ctx->challengeMeasHashType = measHashType;
    ctx->challengeSlotId = (byte)(slotId & 0x0F);

    /* Nonce (32 bytes random) */
    rc = wolfSPDM_GetRandom(ctx, &buf[offset], 32);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    XMEMCPY(ctx->challengeNonce, &buf[offset], 32);
    offset += 32;

    /* SPDM 1.3+ adds RequesterContext(8) per DSP0274 Table 46.
     * Save it so ParseChallengeAuth can verify the responder echoed it.
     * Note: OpaqueDataLength is NOT part of the CHALLENGE request. */
    if (ctx->spdmVersion >= SPDM_VERSION_13) {
        rc = wolfSPDM_GetRandom(ctx, &buf[offset], 8);
        if (rc != WOLFSPDM_SUCCESS) {
            return rc;
        }
        XMEMCPY(ctx->challengeReqCtx, &buf[offset], 8);
        offset += 8;
    }

    *bufSz = offset;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseChallengeAuth(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz, word32* sigOffset)
{
    word32 offset;
    word16 opaqueLen;

    if (ctx == NULL || buf == NULL || sigOffset == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Minimum size: 4 hdr + 48 certChainHash + 48 nonce + 48 measSummary
     * + 2 opaqueLen + 96 sig = 246 bytes (with meas hash) */
    if (bufSz < 4) {
        return WOLFSPDM_E_CHALLENGE;
    }

    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_CHALLENGE_AUTH, WOLFSPDM_E_CHALLENGE);

    /* DSP0274 Sec. 10.8: Param1[3:0] echoes the requested SlotID.
     * BuildChallenge saved the slot it sent in ctx->challengeSlotId;
     * reject a responder that authenticates a different slot. */
    if ((buf[2] & 0x0F) != (ctx->challengeSlotId & 0x0F)) {
        wolfSPDM_DebugPrint(ctx,
            "CHALLENGE_AUTH: SlotID echo mismatch (got %u expected %u)\n",
            buf[2] & 0x0F, ctx->challengeSlotId & 0x0F);
        return WOLFSPDM_E_CHALLENGE;
    }

    offset = 4;

    /* CertChainHash (H bytes, 48 for SHA-384) */
    if (offset + WOLFSPDM_HASH_SIZE > bufSz) {
        wolfSPDM_DebugPrint(ctx, "CHALLENGE_AUTH: too short for CertChainHash\n");
        return WOLFSPDM_E_CHALLENGE;
    }
    /* Verify cert chain hash matches what we computed */
    if (XMEMCMP(&buf[offset], ctx->certChainHash, WOLFSPDM_HASH_SIZE) != 0) {
        wolfSPDM_DebugPrint(ctx, "CHALLENGE_AUTH: CertChainHash mismatch\n");
        return WOLFSPDM_E_CHALLENGE;
    }
    offset += WOLFSPDM_HASH_SIZE;

    /* Nonce (32 bytes per DSP0274) */
    if (offset + 32 > bufSz) {
        wolfSPDM_DebugPrint(ctx, "CHALLENGE_AUTH: too short for Nonce\n");
        return WOLFSPDM_E_CHALLENGE;
    }
    offset += 32;

    /* MeasurementSummaryHash (H bytes if requested, 0 bytes if type=NONE) */
    if (ctx->challengeMeasHashType != SPDM_MEAS_SUMMARY_HASH_NONE) {
        if (offset + WOLFSPDM_HASH_SIZE > bufSz) {
            wolfSPDM_DebugPrint(ctx,
                "CHALLENGE_AUTH: too short for MeasurementSummaryHash\n");
            return WOLFSPDM_E_CHALLENGE;
        }
        offset += WOLFSPDM_HASH_SIZE;
    }

    /* OpaqueDataLength (2 LE) */
    if (offset + 2 > bufSz) {
        return WOLFSPDM_E_CHALLENGE;
    }
    opaqueLen = SPDM_Get16LE(&buf[offset]);
    offset += 2;

    /* Skip opaque data */
    if (offset + opaqueLen > bufSz) {
        return WOLFSPDM_E_CHALLENGE;
    }
    offset += opaqueLen;

    /* SPDM 1.3+ adds RequesterContext (8 bytes echoed from request).
     * Per DSP0274, this comes AFTER OpaqueData and BEFORE Signature.
     * Verify the responder echoed the same value we sent - the signature
     * already covers it, so a tampered value would fail signature check,
     * but the explicit echo check catches responder-side bugs / cached
     * stale responses early. */
    if (ctx->spdmVersion >= SPDM_VERSION_13) {
        if (offset + 8 > bufSz) {
            wolfSPDM_DebugPrint(ctx,
                "CHALLENGE_AUTH: too short for RequesterContext\n");
            return WOLFSPDM_E_CHALLENGE;
        }
        if (XMEMCMP(&buf[offset], ctx->challengeReqCtx, 8) != 0) {
            wolfSPDM_DebugPrint(ctx,
                "CHALLENGE_AUTH: RequesterContext echo mismatch\n");
            return WOLFSPDM_E_CHALLENGE;
        }
        offset += 8;
    }

    /* Signature starts here (ECDSA or ML-DSA SigLen) */
    if (offset + wolfSPDM_GetSigSize(ctx) > bufSz) {
        wolfSPDM_DebugPrint(ctx, "CHALLENGE_AUTH: no room for signature\n");
        return WOLFSPDM_E_CHALLENGE;
    }

    *sigOffset = offset;
    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_VerifyChallengeAuthSig(WOLFSPDM_CTX* ctx,
    const byte* rspBuf, word32 rspBufSz,
    const byte* reqMsg, word32 reqMsgSz, word32 sigOffset)
{
    byte digest[WOLFSPDM_HASH_SIZE];
    int rc;

    (void)rspBufSz;

    if (ctx == NULL || rspBuf == NULL || reqMsg == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.hasResponderPubKey) {
        return WOLFSPDM_E_CHALLENGE;
    }

    /* Build M1/M2 hash per DSP0274 Section 10.8.3:
     * A+B are already accumulated in ctx->m1m2Hash. Now add C and finalize. */
    if (!ctx->flags.m1m2HashInit) {
        wolfSPDM_DebugPrint(ctx, "CHALLENGE: M1/M2 hash not initialized\n");
        return WOLFSPDM_E_CHALLENGE;
    }

    /* Add C: CHALLENGE request + CHALLENGE_AUTH response (before sig).
     * If a step fails, free the hash state and clear the init flag so a
     * retry rebuilds from scratch instead of using a partially-updated hash. */
    rc = wc_Sha384Update(&ctx->m1m2Hash, reqMsg, reqMsgSz);
    if (rc != 0) {
        wc_Sha384Free(&ctx->m1m2Hash);
        ctx->flags.m1m2HashInit = 0;
        return WOLFSPDM_E_CRYPTO_FAIL;
    }
    rc = wc_Sha384Update(&ctx->m1m2Hash, rspBuf, sigOffset);
    if (rc != 0) {
        wc_Sha384Free(&ctx->m1m2Hash);
        ctx->flags.m1m2HashInit = 0;
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    /* Finalize M1/M2 hash */
    rc = wc_Sha384Final(&ctx->m1m2Hash, digest);
    ctx->flags.m1m2HashInit = 0; /* Hash consumed regardless */
    if (rc != 0) {
        wc_ForceZero(digest, sizeof(digest));
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    rc = wolfSPDM_VerifySignedDigest(ctx,
        "responder-challenge_auth signing", 32, digest,
        rspBuf + sigOffset, wolfSPDM_GetSigSize(ctx),
        "CHALLENGE_AUTH signature VERIFIED",
        "CHALLENGE_AUTH signature INVALID",
        WOLFSPDM_E_CHALLENGE);
    wc_ForceZero(digest, sizeof(digest));
    return rc;
}

#endif /* !NO_WOLFSPDM_CHALLENGE */

/* --- Heartbeat (DSP0274 Section 10.10) --- */

int wolfSPDM_BuildHeartbeat(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz)
{
    return wolfSPDM_BuildSimpleMsg(ctx, SPDM_HEARTBEAT, buf, bufSz);
}

int wolfSPDM_ParseHeartbeatAck(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz)
{
    SPDM_CHECK_PARSE_OR_ERROR_ARGS(ctx, buf, bufSz, 4);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_HEARTBEAT_ACK, WOLFSPDM_E_BAD_STATE);

    wolfSPDM_DebugPrint(ctx, "HEARTBEAT_ACK received\n");
    return WOLFSPDM_SUCCESS;
}

/* --- Key Update (DSP0274 Section 10.9) --- */

int wolfSPDM_BuildKeyUpdate(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    byte operation, byte* tag)
{
    int rc;

    SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, 4);
    if (tag == NULL)
        return WOLFSPDM_E_INVALID_ARG;

    /* Generate random tag for request/response matching */
    rc = wolfSPDM_GetRandom(ctx, tag, 1);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    buf[0] = ctx->spdmVersion;
    buf[1] = SPDM_KEY_UPDATE;
    buf[2] = operation;
    buf[3] = *tag;
    *bufSz = 4;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ParseKeyUpdateAck(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz, byte operation, byte tag)
{
    SPDM_CHECK_PARSE_OR_ERROR_ARGS(ctx, buf, bufSz, 4);
    SPDM_CHECK_RESPONSE(ctx, buf, bufSz, SPDM_KEY_UPDATE_ACK, WOLFSPDM_E_KEY_UPDATE);

    /* Verify echoed operation and tag */
    if (buf[2] != operation) {
        wolfSPDM_DebugPrint(ctx, "KEY_UPDATE_ACK: operation mismatch: 0x%02x != 0x%02x\n",
            buf[2], operation);
        return WOLFSPDM_E_KEY_UPDATE;
    }

    if (buf[3] != tag) {
        wolfSPDM_DebugPrint(ctx, "KEY_UPDATE_ACK: tag mismatch: 0x%02x != 0x%02x\n",
            buf[3], tag);
        return WOLFSPDM_E_KEY_UPDATE;
    }

    wolfSPDM_DebugPrint(ctx, "KEY_UPDATE_ACK received\n");
    return WOLFSPDM_SUCCESS;
}
