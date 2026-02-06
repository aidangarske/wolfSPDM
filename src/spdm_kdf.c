/* spdm_kdf.c
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
 * SPDM Key Derivation (DSP0277)
 *
 * SPDM uses HKDF with a BinConcat info format different from TLS 1.3:
 *   info = Length (2 bytes, LE) || "spdm1.2 " || Label || Context
 *
 * Key hierarchy:
 *   HandshakeSecret = HKDF-Extract(salt=zeros, IKM=sharedSecret)
 *   reqHsSecret = HKDF-Expand(HS, "req hs data" || TH1, 48)
 *   rspHsSecret = HKDF-Expand(HS, "rsp hs data" || TH1, 48)
 *   reqFinishedKey = HKDF-Expand(reqHsSecret, "finished", 48)
 *   rspFinishedKey = HKDF-Expand(rspHsSecret, "finished", 48)
 *   reqDataKey = HKDF-Expand(reqHsSecret, "key", 32)
 *   reqDataIV = HKDF-Expand(reqHsSecret, "iv", 12)
 *   (same pattern for rsp keys)
 */

int wolfSPDM_HkdfExpandLabel(byte spdmVersion, const byte* secret, word32 secretSz,
    const char* label, const byte* context, word32 contextSz,
    byte* out, word32 outSz)
{
    byte info[128];
    word32 infoLen = 0;
    const char* prefix;
    int rc;

    if (secret == NULL || label == NULL || out == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* Select version-specific prefix */
    if (spdmVersion >= 0x14) {
        prefix = SPDM_BIN_CONCAT_PREFIX_14;  /* "spdm1.4 " */
    } else if (spdmVersion >= 0x13) {
        prefix = SPDM_BIN_CONCAT_PREFIX_13;  /* "spdm1.3 " */
    } else {
        prefix = SPDM_BIN_CONCAT_PREFIX_12;  /* "spdm1.2 " */
    }

    /* BinConcat format: Length (2 LE) || "spdmX.Y " || Label || Context
     * Note: SPDM spec references TLS 1.3 (BE), but Nuvoton uses LE.
     * The ResponderVerifyData match proves LE is correct for this TPM. */
    info[infoLen++] = (byte)(outSz & 0xFF);
    info[infoLen++] = (byte)((outSz >> 8) & 0xFF);

    XMEMCPY(info + infoLen, prefix, SPDM_BIN_CONCAT_PREFIX_LEN);
    infoLen += SPDM_BIN_CONCAT_PREFIX_LEN;

    XMEMCPY(info + infoLen, label, XSTRLEN(label));
    infoLen += (word32)XSTRLEN(label);

    if (context != NULL && contextSz > 0) {
        XMEMCPY(info + infoLen, context, contextSz);
        infoLen += contextSz;
    }

    rc = wc_HKDF_Expand(WC_SHA384, secret, secretSz, info, infoLen, out, outSz);

    return (rc == 0) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CRYPTO_FAIL;
}

int wolfSPDM_ComputeVerifyData(const byte* finishedKey, const byte* thHash,
    byte* verifyData)
{
    Hmac hmac;
    int rc;

    if (finishedKey == NULL || thHash == NULL || verifyData == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    rc = wc_HmacSetKey(&hmac, WC_SHA384, finishedKey, WOLFSPDM_HASH_SIZE);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    rc = wc_HmacUpdate(&hmac, thHash, WOLFSPDM_HASH_SIZE);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    rc = wc_HmacFinal(&hmac, verifyData);

    return (rc == 0) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CRYPTO_FAIL;
}

int wolfSPDM_DeriveHandshakeKeys(WOLFSPDM_CTX* ctx, const byte* th1Hash)
{
    byte salt[WOLFSPDM_HASH_SIZE];
    int rc;

    if (ctx == NULL || th1Hash == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    /* SPDM uses zero salt (unlike TLS 1.3 which uses Hash("")) */
    XMEMSET(salt, 0, sizeof(salt));

    /* HandshakeSecret = HKDF-Extract(zeros, sharedSecret) */
    rc = wc_HKDF_Extract(WC_SHA384, salt, sizeof(salt),
        ctx->sharedSecret, ctx->sharedSecretSz,
        ctx->handshakeSecret);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    wolfSPDM_DebugHex(ctx, "HandshakeSecret", ctx->handshakeSecret,
        WOLFSPDM_HASH_SIZE);
    wolfSPDM_DebugHex(ctx, "TH1 context for key derivation", th1Hash,
        WOLFSPDM_HASH_SIZE);

    /* reqHsSecret = HKDF-Expand(HS, "req hs data" || TH1, 48) */
    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->handshakeSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_REQ_HS_DATA, th1Hash, WOLFSPDM_HASH_SIZE,
        ctx->reqHsSecret, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    wolfSPDM_DebugHex(ctx, "reqHsSecret (intermediate)", ctx->reqHsSecret,
        WOLFSPDM_HASH_SIZE);

    /* rspHsSecret = HKDF-Expand(HS, "rsp hs data" || TH1, 48) */
    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->handshakeSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_RSP_HS_DATA, th1Hash, WOLFSPDM_HASH_SIZE,
        ctx->rspHsSecret, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    wolfSPDM_DebugHex(ctx, "rspHsSecret (intermediate)", ctx->rspHsSecret,
        WOLFSPDM_HASH_SIZE);

    /* Finished keys (used for VerifyData HMAC) */
    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->reqHsSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_FINISHED, NULL, 0,
        ctx->reqFinishedKey, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->rspHsSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_FINISHED, NULL, 0,
        ctx->rspFinishedKey, WOLFSPDM_HASH_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* Data encryption keys (AES-256-GCM) */
    wolfSPDM_DebugHex(ctx, "PRK for reqDataKey (reqHsSecret)", ctx->reqHsSecret,
        WOLFSPDM_HASH_SIZE);
    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->reqHsSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_KEY, NULL, 0,
        ctx->reqDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->rspHsSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_KEY, NULL, 0,
        ctx->rspDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    /* IVs */
    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->reqHsSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_IV, NULL, 0,
        ctx->reqDataIv, WOLFSPDM_AEAD_IV_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    rc = wolfSPDM_HkdfExpandLabel(ctx->spdmVersion, ctx->rspHsSecret,
        WOLFSPDM_HASH_SIZE, SPDM_LABEL_IV, NULL, 0,
        ctx->rspDataIv, WOLFSPDM_AEAD_IV_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugHex(ctx, "reqDataKey", ctx->reqDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    wolfSPDM_DebugHex(ctx, "reqDataIV", ctx->reqDataIv, WOLFSPDM_AEAD_IV_SIZE);
    wolfSPDM_DebugHex(ctx, "reqFinishedKey", ctx->reqFinishedKey, WOLFSPDM_HASH_SIZE);
    wolfSPDM_DebugHex(ctx, "rspFinishedKey", ctx->rspFinishedKey, WOLFSPDM_HASH_SIZE);

    return WOLFSPDM_SUCCESS;
}
