/* spdm_crypto.c
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

/* Left-pad a buffer in-place to targetSz with leading zeros.
 * Returns WOLFSPDM_E_CRYPTO_FAIL if currentSz exceeds targetSz - that
 * would indicate a wolfCrypt routine wrote more bytes than the protocol
 * allows (P-384 should never produce more than 48 raw bytes); silently
 * truncating would hide an internal-invariant violation. */
static int wolfSPDM_LeftPadToSize(byte* buf, word32 currentSz, word32 targetSz)
{
    if (currentSz > targetSz) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }
    if (currentSz < targetSz) {
        word32 padLen = targetSz - currentSz;
        XMEMMOVE(buf + padLen, buf, currentSz);
        XMEMSET(buf, 0, padLen);
    }
    return WOLFSPDM_SUCCESS;
}

/* --- Random Number Generation --- */

int wolfSPDM_GetRandom(WOLFSPDM_CTX* ctx, byte* out, word32 outSz)
{
    int rc;

    if (ctx == NULL || out == NULL || outSz == 0) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.rngInitialized) {
        return WOLFSPDM_E_BAD_STATE;
    }

    rc = wc_RNG_GenerateBlock(&ctx->rng, out, outSz);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    return WOLFSPDM_SUCCESS;
}

/* --- ECDHE Key Generation (P-384) --- */

int wolfSPDM_GenerateEphemeralKey(WOLFSPDM_CTX* ctx)
{
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.rngInitialized) {
        return WOLFSPDM_E_BAD_STATE;
    }

    /* Free existing key if any */
    if (ctx->flags.ephemeralKeyInit) {
        wc_ecc_free(&ctx->ephemeralKey);
        ctx->flags.ephemeralKeyInit = 0;
    }

    /* Initialize new key */
    rc = wc_ecc_init(&ctx->ephemeralKey);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    /* Generate P-384 key pair */
    rc = wc_ecc_make_key(&ctx->rng, WOLFSPDM_ECC_KEY_SIZE, &ctx->ephemeralKey);
    if (rc != 0) {
        wc_ecc_free(&ctx->ephemeralKey);
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    ctx->flags.ephemeralKeyInit = 1;
    wolfSPDM_DebugPrint(ctx, "Generated P-384 ephemeral key\n");

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_ExportEphemeralPubKey(WOLFSPDM_CTX* ctx,
    byte* pubKeyX, word32* pubKeyXSz,
    byte* pubKeyY, word32* pubKeyYSz)
{
    int rc;

    if (ctx == NULL || pubKeyX == NULL || pubKeyXSz == NULL ||
        pubKeyY == NULL || pubKeyYSz == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.ephemeralKeyInit) {
        return WOLFSPDM_E_BAD_STATE;
    }

    if (*pubKeyXSz < WOLFSPDM_ECC_KEY_SIZE ||
        *pubKeyYSz < WOLFSPDM_ECC_KEY_SIZE) {
        return WOLFSPDM_E_BUFFER_SMALL;
    }

    rc = wc_ecc_export_public_raw(&ctx->ephemeralKey,
        pubKeyX, pubKeyXSz, pubKeyY, pubKeyYSz);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }

    /* Left-pad coordinates to full size (wolfSSL may strip leading zeros) */
    rc = wolfSPDM_LeftPadToSize(pubKeyX, *pubKeyXSz, WOLFSPDM_ECC_KEY_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    *pubKeyXSz = WOLFSPDM_ECC_KEY_SIZE;
    rc = wolfSPDM_LeftPadToSize(pubKeyY, *pubKeyYSz, WOLFSPDM_ECC_KEY_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }
    *pubKeyYSz = WOLFSPDM_ECC_KEY_SIZE;

    return WOLFSPDM_SUCCESS;
}

/* --- ECDH Shared Secret Computation --- */

int wolfSPDM_ComputeSharedSecret(WOLFSPDM_CTX* ctx,
    const byte* peerPubKeyX, const byte* peerPubKeyY)
{
    ecc_key peerKey;
    int rc;
    int peerKeyInit = 0;

    if (ctx == NULL || peerPubKeyX == NULL || peerPubKeyY == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (!ctx->flags.ephemeralKeyInit) {
        return WOLFSPDM_E_BAD_STATE;
    }

    /* Initialize peer key structure */
    rc = wc_ecc_init(&peerKey);
    if (rc != 0) {
        return WOLFSPDM_E_CRYPTO_FAIL;
    }
    peerKeyInit = 1;

    /* Import peer's public key */
    rc = wc_ecc_import_unsigned(&peerKey,
        peerPubKeyX, peerPubKeyY,
        NULL,  /* No private key */
        ECC_SECP384R1);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "Failed to import peer public key: %d\n", rc);
        goto cleanup;
    }

    /* Compute ECDH shared secret */
    ctx->sharedSecretSz = sizeof(ctx->sharedSecret);
    rc = wc_ecc_shared_secret(&ctx->ephemeralKey, &peerKey,
        ctx->sharedSecret, &ctx->sharedSecretSz);
    if (rc != 0) {
        wolfSPDM_DebugPrint(ctx, "ECDH shared_secret failed: %d\n", rc);
        goto cleanup;
    }

    /* Zero-pad the X-coordinate to the full curve size in a way that does
     * not branch on the secret's leading-zero count: always touch every
     * byte of a scratch buffer so the memory-access pattern is independent
     * of how many high-order zero bytes wolfCrypt stripped. The underlying
     * wc_ecc_shared_secret length is itself a function of the secret X
     * coordinate; this routine just keeps the wolfSPDM-level work uniform. */
    {
        byte scratch[WOLFSPDM_ECC_KEY_SIZE];
        word32 retSz = ctx->sharedSecretSz;
        word32 pad;
        word32 i;
        if (retSz > WOLFSPDM_ECC_KEY_SIZE) {
            rc = WOLFSPDM_E_CRYPTO_FAIL;
            goto cleanup;
        }
        pad = WOLFSPDM_ECC_KEY_SIZE - retSz;
        for (i = 0; i < WOLFSPDM_ECC_KEY_SIZE; i++) {
            scratch[i] = (i < pad) ? (byte)0 : ctx->sharedSecret[i - pad];
        }
        XMEMCPY(ctx->sharedSecret, scratch, WOLFSPDM_ECC_KEY_SIZE);
        wc_ForceZero(scratch, sizeof(scratch));
        ctx->sharedSecretSz = WOLFSPDM_ECC_KEY_SIZE;
    }

    wolfSPDM_DebugPrint(ctx, "ECDH shared secret computed (%u bytes)\n",
        ctx->sharedSecretSz);

    rc = 0;

cleanup:
    if (peerKeyInit) {
        wc_ecc_free(&peerKey);
    }

    return (rc == 0) ? WOLFSPDM_SUCCESS : WOLFSPDM_E_CRYPTO_FAIL;
}
