/* spdm_secured.c
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

/*
 * SPDM Secured Message Format (DSP0277):
 *
 * MCTP transport:
 *   Header/AAD: SessionID(4 LE) + SeqNum(2 LE) + Length(2 LE) = 8 bytes
 *   IV XOR: Leftmost 2 bytes (bytes 0-1) with 2-byte LE sequence number
 *
 * Full message: Header || Ciphertext || Tag (16)
 */


int wolfSPDM_EncryptInternal(WOLFSPDM_CTX* ctx,
    const byte* plain, word32 plainSz,
    byte* enc, word32* encSz)
{
    Aes aes;
    byte iv[WOLFSPDM_AEAD_IV_SIZE];
    byte aad[8];
    byte plainBuf[WOLFSPDM_MAX_MSG_SIZE + 16];
    byte tag[WOLFSPDM_AEAD_TAG_SIZE];
    word16 appDataLen;
    word16 encDataLen;
    word32 plainBufSz;
    word16 recordLen;
    word32 hdrSz;
    word32 aadSz;
    int rc;

    if (ctx == NULL || plain == NULL || enc == NULL || encSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Defense-in-depth: the public wolfSPDM_EncryptMessage wrapper exposes
     * this function with caller-supplied plainSz. plainBuf holds
     * AppDataLen(2) + MCTPheader(1) + plaintext, so bound plainSz against
     * the buffer size minus those 3 prefix bytes. */
    if (plainSz > sizeof(plainBuf) - 3) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* DSP0277 Sec. 11.3: the sequence number shall not wrap. The wire field is
     * 16-bit and wolfSPDM_BuildIV mixes only the low 16 bits into the AES-GCM
     * IV, so a wrap would reuse an IV under the same key. Refuse to encrypt
     * once the counter reaches 0x10000 - caller must wolfSPDM_KeyUpdate. */
    if (ctx->reqSeqNum > 0xFFFF) {
        return WOLFSPDM_E_SEQUENCE;
    }

    /* MCTP format (per DSP0277):
     * Plaintext: AppDataLen(2 LE) + MCTP header(0x05) + SPDM message
     * Header: SessionID(4 LE) + SeqNum(2 LE) + Length(2 LE) = 8 bytes
     * AAD = Header
     */
    appDataLen = (word16)(1 + plainSz);
    encDataLen = (word16)(2 + appDataLen);

    plainBufSz = encDataLen;
    recordLen = (word16)(encDataLen + WOLFSPDM_AEAD_TAG_SIZE);
    hdrSz = 8;  /* 4 + 2 + 2 */

    if (*encSz < hdrSz + recordLen) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Build plaintext: AppDataLen(2 LE) || MCTP header(0x05) || SPDM msg */
    SPDM_Set16LE(plainBuf, appDataLen);
    plainBuf[2] = MCTP_MESSAGE_TYPE_SPDM;
    XMEMCPY(&plainBuf[3], plain, plainSz);

    /* Build header/AAD: SessionID(4 LE) + SeqNum(2 LE) + Length(2 LE) */
    SPDM_Set32LE(&enc[0], ctx->sessionId);
    SPDM_Set16LE(&enc[4], (word16)ctx->reqSeqNum);
    SPDM_Set16LE(&enc[6], recordLen);

    aadSz = 8;
    XMEMCPY(aad, enc, aadSz);

    /* Build IV: BaseIV XOR sequence number (DSP0277) */
    wolfSPDM_BuildIV(iv, ctx->reqDataIv, ctx->reqSeqNum);

    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc != 0) {
        /* wc_AesInit failed: do NOT touch aes (don't call wc_AesFree on
         * an uninitialized object). Caller-side cleanup below is guarded
         * by aesInit. */
        wc_ForceZero(plainBuf, sizeof(plainBuf));
        return WOLFSPDM_E_CRYPTO_FAIL;
    }
    rc = wc_AesGcmSetKey(&aes, ctx->reqDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    if (rc != 0) {
        rc = WOLFSPDM_E_CRYPTO_FAIL;
        goto exit;
    }

    /* Encrypt directly into output buffer (enc + hdrSz) to avoid a copy */
    rc = wc_AesGcmEncrypt(&aes, &enc[hdrSz], plainBuf, plainBufSz,
        iv, WOLFSPDM_AEAD_IV_SIZE, tag, WOLFSPDM_AEAD_TAG_SIZE, aad, aadSz);
    if (rc != 0) {
        rc = WOLFSPDM_E_CRYPTO_FAIL;
        goto exit;
    }

    XMEMCPY(&enc[hdrSz + plainBufSz], tag, WOLFSPDM_AEAD_TAG_SIZE);
    *encSz = hdrSz + plainBufSz + WOLFSPDM_AEAD_TAG_SIZE;

    ctx->reqSeqNum++;

    wolfSPDM_DebugPrint(ctx, "Encrypted %u bytes -> %u bytes (seq=%llu)\n",
        plainSz, *encSz, (unsigned long long)(ctx->reqSeqNum - 1));

    rc = WOLFSPDM_SUCCESS;
exit:
    /* aes was initialized (we jumped here past the init check); safe to free. */
    wc_AesFree(&aes);
    /* Wipe the plaintext buffer so the outgoing payload doesn't linger
     * on the stack frame after this call returns. */
    wc_ForceZero(plainBuf, sizeof(plainBuf));
    return rc;
}

int wolfSPDM_DecryptInternal(WOLFSPDM_CTX* ctx,
    const byte* enc, word32 encSz,
    byte* plain, word32* plainSz)
{
    Aes aes;
    byte iv[WOLFSPDM_AEAD_IV_SIZE];
    byte aad[8];
    byte decrypted[WOLFSPDM_MAX_MSG_SIZE + 16];
    const byte* ciphertext;
    const byte* tag;
    word32 rspSessionId;
    word16 rspSeqNum;
    word16 rspLen;
    word16 cipherLen;
    word16 appDataLen;
    word32 hdrSz = 8;
    word32 aadSz = 8;
    int rc;

    if (ctx == NULL || enc == NULL || plain == NULL || plainSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* DSP0277 Sec. 11.3: refuse to decrypt past wire-counter exhaustion (matches
     * the encrypt-side cap; prevents AES-GCM IV reuse). Caller must
     * wolfSPDM_KeyUpdate before the responder's seqNum reaches 0x10000. */
    if (ctx->rspSeqNum > 0xFFFF) {
        return WOLFSPDM_E_SEQUENCE;
    }

    /* MCTP format */
    if (encSz < hdrSz + WOLFSPDM_AEAD_TAG_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Parse header: SessionID(4) + SeqNum(2) + Length(2) */
    rspSessionId = SPDM_Get32LE(&enc[0]);
    rspSeqNum = SPDM_Get16LE(&enc[4]);
    rspLen = SPDM_Get16LE(&enc[6]);

    if (rspSessionId != ctx->sessionId) {
        wolfSPDM_DebugPrint(ctx, "Session ID mismatch: 0x%08x != 0x%08x\n",
            rspSessionId, ctx->sessionId);
        return WOLFSPDM_E_SESSION_INVALID;
    }

    /* Validate sequence number matches expected (DSP0277 replay protection).
     * The wire field is 16-bit. Casting the 64-bit counter to word16 already
     * truncates, matching what the encrypt side wrote. */
    if (rspSeqNum != (word16)ctx->rspSeqNum) {
        wolfSPDM_DebugPrint(ctx, "Sequence number mismatch: %u != %llu\n",
            (unsigned)rspSeqNum, (unsigned long long)ctx->rspSeqNum);
        return WOLFSPDM_E_SEQUENCE;
    }

    if (rspLen < WOLFSPDM_AEAD_TAG_SIZE || encSz < (word32)(hdrSz + rspLen)) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    /* DSP0277: the Length field SHALL equal the exact length of the
     * encrypted payload. Reject over-received records with extra
     * unauthenticated trailing bytes. */
    if (encSz != (word32)(hdrSz + rspLen)) {
        wolfSPDM_DebugPrint(ctx,
            "Secured msg: encSz %u != hdrSz+rspLen %u\n",
            encSz, (unsigned)(hdrSz + rspLen));
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    cipherLen = (word16)(rspLen - WOLFSPDM_AEAD_TAG_SIZE);
    /* Defense-in-depth: the decrypted[] stack buffer is the upper bound on
     * what wc_AesGcmDecrypt may write. Reject anything larger before the
     * AEAD call so a wire-supplied rspLen cannot overflow the buffer. */
    if (cipherLen > sizeof(decrypted)) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }
    ciphertext = enc + hdrSz;
    tag = enc + hdrSz + cipherLen;

    XMEMCPY(aad, enc, aadSz);

    /* Build IV: BaseIV XOR sequence number (DSP0277) */
    wolfSPDM_BuildIV(iv, ctx->rspDataIv, (word64)rspSeqNum);

    rc = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (rc != 0) {
        /* wc_AesInit failed: aes is not safe to wc_AesFree. Wipe stack
         * decrypted buffer and bail without touching aes. */
        wc_ForceZero(decrypted, sizeof(decrypted));
        return WOLFSPDM_E_CRYPTO_FAIL;
    }
    rc = wc_AesGcmSetKey(&aes, ctx->rspDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    if (rc != 0) {
        rc = WOLFSPDM_E_CRYPTO_FAIL;
        goto exit;
    }

    rc = wc_AesGcmDecrypt(&aes, decrypted, ciphertext, cipherLen,
        iv, WOLFSPDM_AEAD_IV_SIZE, tag, WOLFSPDM_AEAD_TAG_SIZE, aad, aadSz);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "AES-GCM decrypt failed: %d\n", rc);
        rc = WOLFSPDM_E_DECRYPT_FAIL;
        goto exit;
    }

    /* Need at least AppDataLen(2) + MCTP(1) bytes in the decrypted output. */
    if (cipherLen < 3) {
        rc = WOLFSPDM_E_BUFFER_SMALL;
        goto exit;
    }

    /* Parse decrypted: AppDataLen (2) || MCTP (1) || SPDM msg */
    appDataLen = SPDM_Get16LE(decrypted);

    if (appDataLen < 1 || cipherLen < (word32)(2 + appDataLen)) {
        rc = WOLFSPDM_E_BUFFER_SMALL;
        goto exit;
    }

    /* Validate the inner MCTP type byte matches what the encrypt side
     * writes - catches responder-side framing bugs early. */
    if (decrypted[2] != MCTP_MESSAGE_TYPE_SPDM) {
        wolfSPDM_DebugPrint(ctx, "Inner MCTP type mismatch: 0x%02x\n",
            decrypted[2]);
        rc = WOLFSPDM_E_DECRYPT_FAIL;
        goto exit;
    }

    /* Skip MCTP header, copy SPDM message */
    if (*plainSz < (word32)(appDataLen - 1)) {
        rc = WOLFSPDM_E_BUFFER_SMALL;
        goto exit;
    }

    XMEMCPY(plain, &decrypted[3], appDataLen - 1);
    *plainSz = appDataLen - 1;

    ctx->rspSeqNum++;

    wolfSPDM_DebugPrint(ctx, "Decrypted %u bytes -> %u bytes (seq=%u)\n",
        encSz, *plainSz, rspSeqNum);

    rc = WOLFSPDM_SUCCESS;
exit:
    /* aes was initialized (we jumped here past the init check); safe to free. */
    wc_AesFree(&aes);
    /* Wipe the decrypted plaintext so secured-channel payloads don't
     * linger on the stack frame after this call returns. */
    wc_ForceZero(decrypted, sizeof(decrypted));
    return rc;
}

/* Public wrappers must only operate after FINISH has installed the
 * application-phase AEAD keys. Allow STATE_FINISH (DeriveAppDataKeys has
 * just run) through STATE_MEASURED, but reject STATE_KEY_EX (handshake
 * keys still in place) and below. */
static int wolfSPDM_AppPhaseStateOk(const WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    if (ctx->state == WOLFSPDM_STATE_FINISH ||
        ctx->state == WOLFSPDM_STATE_CONNECTED) {
        return 1;
    }
#ifndef NO_WOLFSPDM_MEAS
    if (ctx->state == WOLFSPDM_STATE_MEASURED) {
        return 1;
    }
#endif
    return 0;
}

#ifndef WOLFSPDM_LEAN
int wolfSPDM_EncryptMessage(WOLFSPDM_CTX* ctx,
    const byte* plain, word32 plainSz,
    byte* enc, word32* encSz)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!wolfSPDM_AppPhaseStateOk(ctx)) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    return wolfSPDM_EncryptInternal(ctx, plain, plainSz, enc, encSz);
}

int wolfSPDM_DecryptMessage(WOLFSPDM_CTX* ctx,
    const byte* enc, word32 encSz,
    byte* plain, word32* plainSz)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!wolfSPDM_AppPhaseStateOk(ctx)) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    return wolfSPDM_DecryptInternal(ctx, enc, encSz, plain, plainSz);
}
#endif /* !WOLFSPDM_LEAN */

int wolfSPDM_SecuredExchange(WOLFSPDM_CTX* ctx,
    const byte* cmdPlain, word32 cmdSz,
    byte* rspPlain, word32* rspSz)
{
    byte encBuf[WOLFSPDM_MAX_MSG_SIZE + 48];
    byte rxBuf[WOLFSPDM_MAX_MSG_SIZE + 48];
    word32 encSz = sizeof(encBuf);
    word32 rxSz = sizeof(rxBuf);
#if defined(WOLFSPDM_HAVE_CHUNK) && !defined(WOLFSPDM_CHUNK_NO_SECURED)
    word32 cap = (rspSz != NULL) ? *rspSz : 0;
    byte handle = 0;
#endif
    int rc;

    if (ctx == NULL || cmdPlain == NULL || rspPlain == NULL || rspSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Match the EncryptMessage/DecryptMessage state guard so callers can't
     * encrypt application data with handshake or zeroed keys. */
    if (!wolfSPDM_AppPhaseStateOk(ctx)) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    rc = wolfSPDM_EncryptInternal(ctx, cmdPlain, cmdSz, encBuf, &encSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Raw transport here: the cleartext chunk hook in wolfSPDM_SendReceive must
     * not run on the encrypted record. Chunking of the decrypted plaintext is
     * handled below. */
    rc = wolfSPDM_SendReceiveRaw(ctx, encBuf, encSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rc = wolfSPDM_DecryptInternal(ctx, rxBuf, rxSz, rspPlain, rspSz);

#if defined(WOLFSPDM_HAVE_CHUNK) && !defined(WOLFSPDM_CHUNK_NO_SECURED)
    /* Reassemble a secured response the responder chunked. */
    if (rc == WOLFSPDM_SUCCESS &&
        wolfSPDM_IsLargeResponse(rspPlain, *rspSz, &handle)) {
        rc = wolfSPDM_ReassembleLargeResponse(ctx, 1, handle, rspPlain, cap,
            rspSz);
    }
#endif
    return rc;
}

/* --- Application Data Transfer --- */

#ifndef WOLFSPDM_LEAN
int wolfSPDM_SendData(WOLFSPDM_CTX* ctx, const byte* data, word32 dataSz)
{
    byte encBuf[WOLFSPDM_MAX_MSG_SIZE + 48];
    byte rxBuf[16];
    word32 encSz = sizeof(encBuf);
    word32 rxSz;
    int rc;

    if (ctx == NULL || data == NULL || dataSz == 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state != WOLFSPDM_STATE_CONNECTED
#ifndef NO_WOLFSPDM_MEAS
        && ctx->state != WOLFSPDM_STATE_MEASURED
#endif
        ) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    /* Max payload: leave room for AEAD overhead */
    if (dataSz > WOLFSPDM_MAX_MSG_SIZE - 64) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    /* Encrypt the application data */
    rc = wolfSPDM_EncryptInternal(ctx, data, dataSz, encBuf, &encSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Send via I/O callback (no response expected for send-only) */
    if (ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }

    rxSz = sizeof(rxBuf);
    rc = ctx->ioCb(ctx, encBuf, encSz, rxBuf, &rxSz, ctx->ioUserCtx);
    if (rc != 0) {
        return WOLFSPDM_E_IO_FAIL;
    }

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ReceiveData(WOLFSPDM_CTX* ctx, byte* data, word32* dataSz)
{
    byte rxBuf[WOLFSPDM_MAX_MSG_SIZE + 48];
    word32 rxSz = sizeof(rxBuf);
    int rc;

    if (ctx == NULL || data == NULL || dataSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state != WOLFSPDM_STATE_CONNECTED
#ifndef NO_WOLFSPDM_MEAS
        && ctx->state != WOLFSPDM_STATE_MEASURED
#endif
        ) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    if (ctx->ioCb == NULL) {
        return WOLFSPDM_E_IO_FAIL;
    }

    /* Receive via I/O callback (NULL tx to indicate receive-only) */
    rc = ctx->ioCb(ctx, NULL, 0, rxBuf, &rxSz, ctx->ioUserCtx);
    if (rc != 0) {
        return WOLFSPDM_E_IO_FAIL;
    }

    /* Decrypt the received data */
    return wolfSPDM_DecryptInternal(ctx, rxBuf, rxSz, data, dataSz);
}
#endif /* !WOLFSPDM_LEAN */
