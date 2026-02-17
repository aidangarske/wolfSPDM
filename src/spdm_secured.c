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
#include <string.h>

/*
 * SPDM Secured Message Format (DSP0277):
 *
 * MCTP transport:
 *   Header/AAD: SessionID(4 LE) + SeqNum(2 LE) + Length(2 LE) = 8 bytes
 *   IV XOR: Leftmost 2 bytes (bytes 0-1) with 2-byte LE sequence number (DSP0277)
 *
 * Nuvoton TCG binding (Rev 1.11):
 *   Header/AAD: SessionID(4 LE) + SeqNum(8 LE) + Length(2 LE) = 14 bytes
 *   IV XOR: Leftmost 8 bytes (bytes 0-7) with 8-byte LE sequence number (DSP0277 1.2)
 *   Plaintext: AppDataLength(2 LE) + SPDM msg + RandomData (pad to 16)
 *
 * Full message: Header || Ciphertext || Tag (16)
 */

#ifdef WOLFSPDM_NUVOTON
/* Self-test: verify AES-GCM encrypt/decrypt round-trip with current keys.
 * Called before first encrypted message to confirm crypto parameters. */
static int wolfSPDM_AesGcmSelfTest(WOLFSPDM_CTX* ctx)
{
    Aes aesEnc, aesDec;
    byte testPlain[] = "wolfSPDM AES-GCM self-test 1234";  /* 31 bytes */
    byte testCipher[32];
    byte testDecrypted[32];
    byte testTag[WOLFSPDM_AEAD_TAG_SIZE];
    byte testAad[14];
    word32 testPlainSz = sizeof(testPlain);
    int rc;

    /* Build AAD matching what we'd use for SeqNum=0 */
    testAad[0] = (byte)(ctx->sessionId & 0xFF);
    testAad[1] = (byte)((ctx->sessionId >> 8) & 0xFF);
    testAad[2] = (byte)((ctx->sessionId >> 16) & 0xFF);
    testAad[3] = (byte)((ctx->sessionId >> 24) & 0xFF);
    XMEMSET(&testAad[4], 0, 8);  /* SeqNum = 0 */
    testAad[12] = (byte)((testPlainSz + 16) & 0xFF);
    testAad[13] = (byte)(((testPlainSz + 16) >> 8) & 0xFF);

    /* Encrypt */
    rc = wc_AesGcmSetKey(&aesEnc, ctx->reqDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "Self-test: AesGcmSetKey (enc) failed: %d\n", rc);
        return rc;
    }
    rc = wc_AesGcmEncrypt(&aesEnc, testCipher, testPlain, testPlainSz,
        ctx->reqDataIv, WOLFSPDM_AEAD_IV_SIZE,
        testTag, WOLFSPDM_AEAD_TAG_SIZE, testAad, 14);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "Self-test: AesGcmEncrypt failed: %d\n", rc);
        return rc;
    }

    /* Decrypt with same key */
    rc = wc_AesGcmSetKey(&aesDec, ctx->reqDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "Self-test: AesGcmSetKey (dec) failed: %d\n", rc);
        return rc;
    }
    rc = wc_AesGcmDecrypt(&aesDec, testDecrypted, testCipher, testPlainSz,
        ctx->reqDataIv, WOLFSPDM_AEAD_IV_SIZE,
        testTag, WOLFSPDM_AEAD_TAG_SIZE, testAad, 14);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "Self-test: AesGcmDecrypt FAILED: %d\n", rc);
        return rc;
    }

    /* Verify plaintext matches */
    if (XMEMCMP(testPlain, testDecrypted, testPlainSz) != 0) {
        wolfSPDM_DebugPrint(ctx, "Self-test: Plaintext mismatch!\n");
        return -1;
    }

    wolfSPDM_DebugPrint(ctx, "Self-test: AES-GCM round-trip PASSED\n");
    return 0;
}
#endif /* WOLFSPDM_NUVOTON */

int wolfSPDM_EncryptInternal(WOLFSPDM_CTX* ctx,
    const byte* plain, word32 plainSz,
    byte* enc, word32* encSz)
{
    Aes aes;
    byte iv[WOLFSPDM_AEAD_IV_SIZE];
    byte aad[16];  /* Up to 14 bytes for TCG format */
    byte plainBuf[WOLFSPDM_MAX_MSG_SIZE + 16];
    byte tag[WOLFSPDM_AEAD_TAG_SIZE];
    word32 plainBufSz;
    word16 recordLen;
    word32 hdrSz;
    word32 aadSz;
    word32 offset;
    int rc;

    if (ctx == NULL || plain == NULL || enc == NULL || encSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

#ifdef WOLFSPDM_NUVOTON
    if (ctx->mode == WOLFSPDM_MODE_NUVOTON) {
        /* Nuvoton TCG binding format per Rev 1.11 spec page 25:
         * Header/AAD: SessionID(4 LE) + SeqNum(8 LE) + Length(2 LE) = 14 bytes
         * IV XOR: Rightmost 8 bytes (bytes 4-11) with 8-byte sequence number
         */
        word16 appDataLen = (word16)plainSz;

        /* Run self-test before first encrypted message */
        if (ctx->reqSeqNum == 0) {
            rc = wolfSPDM_AesGcmSelfTest(ctx);
            if (rc != 0) {
                wolfSPDM_DebugPrint(ctx, "AES-GCM self-test FAILED: %d\n", rc);
                return WOLFSPDM_E_CRYPTO_FAIL;
            }
        }
        word16 unpadded = (word16)(2 + appDataLen);  /* AppDataLength + SPDM msg */
        word16 padLen = (word16)((16 - (unpadded % 16)) % 16);  /* Pad to 16-byte boundary */
        word16 encPayloadSz = (word16)(unpadded + padLen);

        plainBufSz = encPayloadSz;
        /* Length field = ciphertext + MAC (per Nuvoton spec page 25: Length=160=144+16) */
        recordLen = (word16)(encPayloadSz + WOLFSPDM_AEAD_TAG_SIZE);
        hdrSz = 14;  /* 4 + 8 + 2 (TCG binding format) */

        if (*encSz < hdrSz + plainBufSz + WOLFSPDM_AEAD_TAG_SIZE) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        /* Build plaintext: AppDataLength(2 LE) || SPDM message || RandomData */
        plainBuf[0] = (byte)(appDataLen & 0xFF);
        plainBuf[1] = (byte)((appDataLen >> 8) & 0xFF);
        XMEMCPY(&plainBuf[2], plain, plainSz);
        /* Fill RandomData with actual random bytes per Nuvoton spec */
        if (padLen > 0) {
            WC_RNG rng;
            if (wc_InitRng(&rng) == 0) {
                wc_RNG_GenerateBlock(&rng, &plainBuf[unpadded], padLen);
                wc_FreeRng(&rng);
            } else {
                /* Fallback to zeros if RNG fails */
                XMEMSET(&plainBuf[unpadded], 0, padLen);
            }
        }

        /* Build header/AAD: SessionID(4 LE) + SeqNum(8 LE) + Length(2 LE) = 14 bytes */
        offset = 0;
        /* SessionID (4 bytes LE): ReqSessionId || RspSessionId */
        enc[offset++] = (byte)(ctx->sessionId & 0xFF);
        enc[offset++] = (byte)((ctx->sessionId >> 8) & 0xFF);
        enc[offset++] = (byte)((ctx->sessionId >> 16) & 0xFF);
        enc[offset++] = (byte)((ctx->sessionId >> 24) & 0xFF);
        /* SequenceNumber (8 bytes LE) - per Nuvoton spec */
        enc[offset++] = (byte)(ctx->reqSeqNum & 0xFF);
        enc[offset++] = (byte)((ctx->reqSeqNum >> 8) & 0xFF);
        enc[offset++] = (byte)((ctx->reqSeqNum >> 16) & 0xFF);
        enc[offset++] = (byte)((ctx->reqSeqNum >> 24) & 0xFF);
        enc[offset++] = (byte)((ctx->reqSeqNum >> 32) & 0xFF);
        enc[offset++] = (byte)((ctx->reqSeqNum >> 40) & 0xFF);
        enc[offset++] = (byte)((ctx->reqSeqNum >> 48) & 0xFF);
        enc[offset++] = (byte)((ctx->reqSeqNum >> 56) & 0xFF);
        /* Length (2 bytes LE) = encrypted payload + MAC */
        enc[offset++] = (byte)(recordLen & 0xFF);
        enc[offset++] = (byte)((recordLen >> 8) & 0xFF);

        aadSz = 14;
        XMEMCPY(aad, enc, aadSz);
    }
    else
#endif
    {
        /* MCTP format (per DSP0277):
         * Plaintext: AppDataLen(2 LE) + MCTP header(0x05) + SPDM message
         * Header: SessionID(4 LE) + SeqNum(2 LE) + Length(2 LE) = 8 bytes
         * AAD = Header
         */
        word16 appDataLen = (word16)(1 + plainSz);
        word16 encDataLen = (word16)(2 + appDataLen);

        plainBufSz = encDataLen;
        recordLen = (word16)(encDataLen + WOLFSPDM_AEAD_TAG_SIZE);
        hdrSz = 8;  /* 4 + 2 + 2 */

        if (*encSz < hdrSz + recordLen) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        /* Build plaintext: AppDataLen(2 LE) || MCTP header(0x05) || SPDM msg */
        plainBuf[0] = (byte)(appDataLen & 0xFF);
        plainBuf[1] = (byte)((appDataLen >> 8) & 0xFF);
        plainBuf[2] = MCTP_MESSAGE_TYPE_SPDM;
        XMEMCPY(&plainBuf[3], plain, plainSz);

        /* Build header/AAD: SessionID(4 LE) + SeqNum(2 LE) + Length(2 LE) */
        offset = 0;
        enc[offset++] = (byte)(ctx->sessionId & 0xFF);
        enc[offset++] = (byte)((ctx->sessionId >> 8) & 0xFF);
        enc[offset++] = (byte)((ctx->sessionId >> 16) & 0xFF);
        enc[offset++] = (byte)((ctx->sessionId >> 24) & 0xFF);
        enc[offset++] = (byte)(ctx->reqSeqNum & 0xFF);
        enc[offset++] = (byte)((ctx->reqSeqNum >> 8) & 0xFF);
        enc[offset++] = (byte)(recordLen & 0xFF);
        enc[offset++] = (byte)((recordLen >> 8) & 0xFF);

        aadSz = 8;
        XMEMCPY(aad, enc, aadSz);
    }

    /* Build IV: BaseIV XOR sequence number */
    XMEMCPY(iv, ctx->reqDataIv, WOLFSPDM_AEAD_IV_SIZE);
#ifdef WOLFSPDM_NUVOTON
    if (ctx->mode == WOLFSPDM_MODE_NUVOTON) {
        /* DSP0277 1.2 IV construction:
         * Zero-extend 8-byte LE sequence number to iv_length (12 bytes),
         * then XOR with base IV. Seq occupies leftmost bytes (0-7),
         * zero-padding at bytes 8-11.
         */
        iv[0]  ^= (byte)(ctx->reqSeqNum & 0xFF);
        iv[1]  ^= (byte)((ctx->reqSeqNum >> 8) & 0xFF);
        iv[2]  ^= (byte)((ctx->reqSeqNum >> 16) & 0xFF);
        iv[3]  ^= (byte)((ctx->reqSeqNum >> 24) & 0xFF);
        iv[4]  ^= (byte)((ctx->reqSeqNum >> 32) & 0xFF);
        iv[5]  ^= (byte)((ctx->reqSeqNum >> 40) & 0xFF);
        iv[6]  ^= (byte)((ctx->reqSeqNum >> 48) & 0xFF);
        iv[7]  ^= (byte)((ctx->reqSeqNum >> 56) & 0xFF);
    }
    else
#endif
    {
        /* MCTP format: Zero-extend 2-byte LE sequence number to iv_length,
         * then XOR with base IV per DSP0277. LE integer starts at byte 0. */
        iv[0] ^= (byte)(ctx->reqSeqNum & 0xFF);
        iv[1] ^= (byte)((ctx->reqSeqNum >> 8) & 0xFF);
    }

    rc = wc_AesGcmSetKey(&aes, ctx->reqDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    /* Encrypt directly into output buffer (enc + hdrSz) to avoid a copy */
    rc = wc_AesGcmEncrypt(&aes, &enc[hdrSz], plainBuf, plainBufSz,
        iv, WOLFSPDM_AEAD_IV_SIZE, tag, WOLFSPDM_AEAD_TAG_SIZE, aad, aadSz);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    XMEMCPY(&enc[hdrSz + plainBufSz], tag, WOLFSPDM_AEAD_TAG_SIZE);
    *encSz = hdrSz + plainBufSz + WOLFSPDM_AEAD_TAG_SIZE;

    ctx->reqSeqNum++;

    wolfSPDM_DebugPrint(ctx, "Encrypted %u bytes -> %u bytes (seq=%llu)\n",
        plainSz, *encSz, (unsigned long long)(ctx->reqSeqNum - 1));

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_DecryptInternal(WOLFSPDM_CTX* ctx,
    const byte* enc, word32 encSz,
    byte* plain, word32* plainSz)
{
    Aes aes;
    byte iv[WOLFSPDM_AEAD_IV_SIZE];
    byte aad[16];
    byte decrypted[WOLFSPDM_MAX_MSG_SIZE + 16];
    const byte* ciphertext;
    const byte* tag;
    word32 rspSessionId;
    word16 rspSeqNum;
    word16 rspLen;
    word16 cipherLen;
    word16 appDataLen;
    word32 hdrSz;
    word32 aadSz;
    int rc;

    if (ctx == NULL || enc == NULL || plain == NULL || plainSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

#ifdef WOLFSPDM_NUVOTON
    if (ctx->mode == WOLFSPDM_MODE_NUVOTON) {
        /* Nuvoton TCG binding format per Rev 1.11 spec page 25:
         * Header/AAD: SessionID(4 LE) + SeqNum(8 LE) + Length(2 LE) = 14 bytes
         * Encrypted: AppDataLength(2 LE) + SPDM message + RandomData padding
         * MAC: 16 bytes
         */
        word64 rspSeqNum64;
        hdrSz = 14;
        aadSz = 14;

        if (encSz < hdrSz + WOLFSPDM_AEAD_TAG_SIZE) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        /* Parse header: SessionID(4) + SeqNum(8) + Length(2) */
        rspSessionId = (word32)enc[0] | ((word32)enc[1] << 8) |
                       ((word32)enc[2] << 16) | ((word32)enc[3] << 24);
        rspSeqNum64 = (word64)enc[4] | ((word64)enc[5] << 8) |
                      ((word64)enc[6] << 16) | ((word64)enc[7] << 24) |
                      ((word64)enc[8] << 32) | ((word64)enc[9] << 40) |
                      ((word64)enc[10] << 48) | ((word64)enc[11] << 56);
        rspLen = (word16)(enc[12] | (enc[13] << 8));
        rspSeqNum = (word16)(rspSeqNum64 & 0xFFFF);  /* For debug output */

        if (rspSessionId != ctx->sessionId) {
            wolfSPDM_DebugPrint(ctx, "Session ID mismatch: 0x%08x != 0x%08x\n",
                rspSessionId, ctx->sessionId);
            return WOLFSPDM_E_SESSION_INVALID;
        }

        /* Length field = ciphertext + MAC (per Nuvoton spec) */
        if (rspLen < WOLFSPDM_AEAD_TAG_SIZE || encSz < hdrSz + rspLen) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        cipherLen = (word16)(rspLen - WOLFSPDM_AEAD_TAG_SIZE);
        ciphertext = enc + hdrSz;
        tag = enc + hdrSz + cipherLen;

        XMEMCPY(aad, enc, aadSz);

        /* DSP0277 1.2 IV construction:
         * Zero-extend 8-byte LE sequence number to iv_length (12 bytes),
         * then XOR with base IV. Seq occupies leftmost bytes (0-7).
         * SeqNum bytes are at enc[4]-enc[11] in the record header. */
        XMEMCPY(iv, ctx->rspDataIv, WOLFSPDM_AEAD_IV_SIZE);
        iv[0]  ^= enc[4];   /* SeqNum byte 0 */
        iv[1]  ^= enc[5];   /* SeqNum byte 1 */
        iv[2]  ^= enc[6];   /* SeqNum byte 2 */
        iv[3]  ^= enc[7];   /* SeqNum byte 3 */
        iv[4]  ^= enc[8];   /* SeqNum byte 4 */
        iv[5]  ^= enc[9];   /* SeqNum byte 5 */
        iv[6]  ^= enc[10];  /* SeqNum byte 6 */
        iv[7]  ^= enc[11];  /* SeqNum byte 7 */

        rc = wc_AesGcmSetKey(&aes, ctx->rspDataKey, WOLFSPDM_AEAD_KEY_SIZE);
        if (rc != 0) {
            return WOLFSPDM_E_CRYPTO_FAIL;
        }

        rc = wc_AesGcmDecrypt(&aes, decrypted, ciphertext, cipherLen,
            iv, WOLFSPDM_AEAD_IV_SIZE, tag, WOLFSPDM_AEAD_TAG_SIZE, aad, aadSz);
        if (rc != 0) {
            wolfSPDM_DebugPrint(ctx, "AES-GCM decrypt failed: %d\n", rc);
            return WOLFSPDM_E_DECRYPT_FAIL;
        }

        /* Parse decrypted: AppDataLen (2 LE) || SPDM message || RandomData */
        appDataLen = (word16)(decrypted[0] | (decrypted[1] << 8));

        if (cipherLen < (word32)(2 + appDataLen)) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        if (*plainSz < appDataLen) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        /* Copy SPDM message (no MCTP header to skip) */
        XMEMCPY(plain, &decrypted[2], appDataLen);
        *plainSz = appDataLen;
    }
    else
#endif
    {
        /* MCTP format */
        hdrSz = 8;
        aadSz = 8;

        if (encSz < hdrSz + WOLFSPDM_AEAD_TAG_SIZE) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        /* Parse header */
        rspSessionId = (word32)enc[0] | ((word32)enc[1] << 8) |
                       ((word32)enc[2] << 16) | ((word32)enc[3] << 24);
        rspSeqNum = (word16)(enc[4] | (enc[5] << 8));
        rspLen = (word16)(enc[6] | (enc[7] << 8));

        if (rspSessionId != ctx->sessionId) {
            wolfSPDM_DebugPrint(ctx, "Session ID mismatch: 0x%08x != 0x%08x\n",
                rspSessionId, ctx->sessionId);
            return WOLFSPDM_E_SESSION_INVALID;
        }

        if (rspLen < WOLFSPDM_AEAD_TAG_SIZE || encSz < (word32)(hdrSz + rspLen)) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        cipherLen = (word16)(rspLen - WOLFSPDM_AEAD_TAG_SIZE);
        ciphertext = enc + hdrSz;
        tag = enc + hdrSz + cipherLen;

        XMEMCPY(aad, enc, aadSz);

        /* Build IV: Zero-extend 2-byte LE sequence number to iv_length,
         * then XOR with base IV per DSP0277. LE integer starts at byte 0. */
        XMEMCPY(iv, ctx->rspDataIv, WOLFSPDM_AEAD_IV_SIZE);
        iv[0] ^= (byte)(rspSeqNum & 0xFF);
        iv[1] ^= (byte)((rspSeqNum >> 8) & 0xFF);

        rc = wc_AesGcmSetKey(&aes, ctx->rspDataKey, WOLFSPDM_AEAD_KEY_SIZE);
        if (rc != 0) {
            return WOLFSPDM_E_CRYPTO_FAIL;
        }

        rc = wc_AesGcmDecrypt(&aes, decrypted, ciphertext, cipherLen,
            iv, WOLFSPDM_AEAD_IV_SIZE, tag, WOLFSPDM_AEAD_TAG_SIZE, aad, aadSz);
        if (rc != 0) {
            wolfSPDM_DebugPrint(ctx, "AES-GCM decrypt failed: %d\n", rc);
            return WOLFSPDM_E_DECRYPT_FAIL;
        }

        /* Parse decrypted: AppDataLen (2) || MCTP (1) || SPDM msg */
        appDataLen = (word16)(decrypted[0] | (decrypted[1] << 8));

        if (appDataLen < 1 || cipherLen < (word32)(2 + appDataLen)) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        /* Skip MCTP header, copy SPDM message */
        if (*plainSz < (word32)(appDataLen - 1)) {
            return WOLFSPDM_E_BUFFER_SMALL;
        }

        XMEMCPY(plain, &decrypted[3], appDataLen - 1);
        *plainSz = appDataLen - 1;
    }

    ctx->rspSeqNum++;

    wolfSPDM_DebugPrint(ctx, "Decrypted %u bytes -> %u bytes (seq=%u)\n",
        encSz, *plainSz, rspSeqNum);

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_EncryptMessage(WOLFSPDM_CTX* ctx,
    const byte* plain, word32 plainSz,
    byte* enc, word32* encSz)
{
    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state != WOLFSPDM_STATE_CONNECTED &&
        ctx->state != WOLFSPDM_STATE_KEY_EX &&
        ctx->state != WOLFSPDM_STATE_FINISH) {
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

    if (ctx->state != WOLFSPDM_STATE_CONNECTED &&
        ctx->state != WOLFSPDM_STATE_KEY_EX &&
        ctx->state != WOLFSPDM_STATE_FINISH) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    return wolfSPDM_DecryptInternal(ctx, enc, encSz, plain, plainSz);
}

int wolfSPDM_SecuredExchange(WOLFSPDM_CTX* ctx,
    const byte* cmdPlain, word32 cmdSz,
    byte* rspPlain, word32* rspSz)
{
    byte encBuf[WOLFSPDM_MAX_MSG_SIZE + 48];
    byte rxBuf[WOLFSPDM_MAX_MSG_SIZE + 48];
    word32 encSz = sizeof(encBuf);
    word32 rxSz = sizeof(rxBuf);
    int rc;

    if (ctx == NULL || cmdPlain == NULL || rspPlain == NULL || rspSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    rc = wolfSPDM_EncryptInternal(ctx, cmdPlain, cmdSz, encBuf, &encSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rc = wolfSPDM_SendReceive(ctx, encBuf, encSz, rxBuf, &rxSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rc = wolfSPDM_DecryptInternal(ctx, rxBuf, rxSz, rspPlain, rspSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    return WOLFSPDM_SUCCESS;
}

/* ==========================================================================
 * Application Data Transfer
 * ========================================================================== */

int wolfSPDM_SendData(WOLFSPDM_CTX* ctx, const byte* data, word32 dataSz)
{
    byte encBuf[WOLFSPDM_MAX_MSG_SIZE + 48];
    word32 encSz = sizeof(encBuf);
    int rc;

    if (ctx == NULL || data == NULL || dataSz == 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state != WOLFSPDM_STATE_CONNECTED) {
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

    {
        byte rxBuf[16];
        word32 rxSz = sizeof(rxBuf);
        rc = ctx->ioCb(ctx, encBuf, encSz, rxBuf, &rxSz, ctx->ioUserCtx);
        if (rc != 0) {
            return WOLFSPDM_E_IO_FAIL;
        }
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

    if (ctx->state != WOLFSPDM_STATE_CONNECTED) {
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
    rc = wolfSPDM_DecryptInternal(ctx, rxBuf, rxSz, data, dataSz);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    return WOLFSPDM_SUCCESS;
}
