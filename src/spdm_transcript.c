/* spdm_transcript.c
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

/* ==========================================================================
 * Transcript Management
 *
 * SPDM uses transcript hashing for key derivation:
 *   VCA = GET_VERSION || VERSION || GET_CAPS || CAPS || NEG_ALGO || ALGO
 *   Ct  = Hash(certificate_chain)
 *   TH1 = Hash(VCA || Ct || KEY_EXCHANGE || KEY_EXCHANGE_RSP_partial || Signature)
 *   TH2 = Hash(VCA || Ct || message_k || FINISH_header)
 *
 * where message_k = KEY_EXCHANGE || KEY_EXCHANGE_RSP_partial || Signature || ResponderVerifyData
 * ========================================================================== */

void wolfSPDM_TranscriptReset(WOLFSPDM_CTX* ctx)
{
    if (ctx == NULL) {
        return;
    }

    XMEMSET(ctx->transcript, 0, sizeof(ctx->transcript));
    ctx->transcriptLen = 0;

    XMEMSET(ctx->certChain, 0, sizeof(ctx->certChain));
    ctx->certChainLen = 0;

    XMEMSET(ctx->certChainHash, 0, sizeof(ctx->certChainHash));
    XMEMSET(ctx->th1, 0, sizeof(ctx->th1));
    XMEMSET(ctx->th2, 0, sizeof(ctx->th2));
}

int wolfSPDM_TranscriptAdd(WOLFSPDM_CTX* ctx, const byte* data, word32 len)
{
    if (ctx == NULL || data == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->transcriptLen + len > WOLFSPDM_MAX_TRANSCRIPT) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    XMEMCPY(ctx->transcript + ctx->transcriptLen, data, len);
    ctx->transcriptLen += len;

    wolfSPDM_DebugPrint(ctx, "Transcript: added %u bytes, total=%u\n",
        len, ctx->transcriptLen);

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_CertChainAdd(WOLFSPDM_CTX* ctx, const byte* data, word32 len)
{
    if (ctx == NULL || data == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->certChainLen + len > WOLFSPDM_MAX_CERT_CHAIN) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    XMEMCPY(ctx->certChain + ctx->certChainLen, data, len);
    ctx->certChainLen += len;

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_TranscriptHash(WOLFSPDM_CTX* ctx, byte* hash)
{
    wc_Sha384 sha;
    int rc;

    if (ctx == NULL || hash == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    rc = wc_InitSha384(&sha);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    rc = wc_Sha384Update(&sha, ctx->transcript, ctx->transcriptLen);
    if (rc != 0) {
        wc_Sha384Free(&sha);
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    rc = wc_Sha384Final(&sha, hash);
    wc_Sha384Free(&sha);

    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    wolfSPDM_DebugHex(ctx, "Transcript Hash", hash, WOLFSPDM_HASH_SIZE);

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ComputeCertChainHash(WOLFSPDM_CTX* ctx)
{
    wc_Sha384 sha;
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->certChainLen == 0) {
        /* No certificate chain - Ct is zeros */
        XMEMSET(ctx->certChainHash, 0, sizeof(ctx->certChainHash));
        return WOLFSPDM_SUCCESS;
    }

    rc = wc_InitSha384(&sha);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    rc = wc_Sha384Update(&sha, ctx->certChain, ctx->certChainLen);
    if (rc != 0) {
        wc_Sha384Free(&sha);
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    rc = wc_Sha384Final(&sha, ctx->certChainHash);
    wc_Sha384Free(&sha);

    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    wolfSPDM_DebugPrint(ctx, "Ct = Hash(cert_chain[%u])\n", ctx->certChainLen);
    wolfSPDM_DebugHex(ctx, "Ct", ctx->certChainHash, WOLFSPDM_HASH_SIZE);

    return WOLFSPDM_SUCCESS;
}
