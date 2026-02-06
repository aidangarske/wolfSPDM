/* unit_test.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Unit tests for wolfSPDM library functions.
 */

#include <wolfspdm/spdm.h>
#include "../src/spdm_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_testsPassed = 0;
static int g_testsFailed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        printf("  FAIL: %s (line %d)\n", msg, __LINE__); \
        g_testsFailed++; \
        return -1; \
    } \
} while(0)

#define TEST_PASS() do { \
    g_testsPassed++; \
    return 0; \
} while(0)

/* ========================================================================== */
/* Context Tests */
/* ========================================================================== */

static int test_context_new_free(void)
{
    WOLFSPDM_CTX* ctx;

    printf("test_context_new_free...\n");

    ctx = wolfSPDM_New();
    TEST_ASSERT(ctx != NULL, "wolfSPDM_New returned NULL");

    TEST_ASSERT(ctx->state == WOLFSPDM_STATE_INIT, "Initial state wrong");
    TEST_ASSERT(ctx->initialized == 0, "Should not be initialized yet");

    wolfSPDM_Free(ctx);

    /* Free NULL should not crash */
    wolfSPDM_Free(NULL);

    TEST_PASS();
}

static int test_context_init(void)
{
    WOLFSPDM_CTX* ctx;
    int rc;

    printf("test_context_init...\n");

    ctx = wolfSPDM_New();
    TEST_ASSERT(ctx != NULL, "wolfSPDM_New failed");

    rc = wolfSPDM_Init(ctx);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "wolfSPDM_Init failed");
    TEST_ASSERT(ctx->initialized == 1, "Not marked initialized");
    TEST_ASSERT(ctx->rngInitialized == 1, "RNG not initialized");
    TEST_ASSERT(ctx->reqCaps == WOLFSPDM_DEFAULT_REQ_CAPS, "Default caps wrong");

    /* Double init should fail */
    rc = wolfSPDM_Init(ctx);
    TEST_ASSERT(rc == WOLFSPDM_E_ALREADY_INIT, "Double init should fail");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_context_static_alloc(void)
{
    byte buffer[sizeof(WOLFSPDM_CTX) + 64];
    WOLFSPDM_CTX* ctx = (WOLFSPDM_CTX*)buffer;
    int rc;

    printf("test_context_static_alloc...\n");

    TEST_ASSERT(wolfSPDM_GetCtxSize() == (int)sizeof(WOLFSPDM_CTX),
        "GetCtxSize mismatch");

    rc = wolfSPDM_InitStatic(ctx, sizeof(buffer));
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "InitStatic failed");
    TEST_ASSERT(ctx->initialized == 1, "Static ctx not initialized");

    /* Too small buffer should fail */
    rc = wolfSPDM_InitStatic(ctx, 10);
    TEST_ASSERT(rc == WOLFSPDM_E_BUFFER_SMALL, "Should fail on small buffer");

    TEST_PASS();
}

static int test_context_set_io(void)
{
    WOLFSPDM_CTX* ctx;
    int rc;
    int dummy = 42;

    printf("test_context_set_io...\n");

    ctx = wolfSPDM_New();
    wolfSPDM_Init(ctx);

    /* Dummy callback for testing */
    rc = wolfSPDM_SetIO(ctx, (WOLFSPDM_IO_CB)0x12345678, &dummy);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "SetIO failed");
    TEST_ASSERT(ctx->ioCb == (WOLFSPDM_IO_CB)0x12345678, "IO callback not set");
    TEST_ASSERT(ctx->ioUserCtx == &dummy, "User context not set");

    /* NULL callback should fail */
    rc = wolfSPDM_SetIO(ctx, NULL, NULL);
    TEST_ASSERT(rc == WOLFSPDM_E_INVALID_ARG, "NULL callback should fail");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

/* ========================================================================== */
/* Transcript Tests */
/* ========================================================================== */

static int test_transcript_add_reset(void)
{
    WOLFSPDM_CTX* ctx;
    byte data1[] = {0x01, 0x02, 0x03, 0x04};
    byte data2[] = {0x05, 0x06, 0x07, 0x08};
    int rc;

    printf("test_transcript_add_reset...\n");

    ctx = wolfSPDM_New();
    wolfSPDM_Init(ctx);

    TEST_ASSERT(ctx->transcriptLen == 0, "Transcript should start empty");

    rc = wolfSPDM_TranscriptAdd(ctx, data1, sizeof(data1));
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "TranscriptAdd failed");
    TEST_ASSERT(ctx->transcriptLen == 4, "Length should be 4");
    TEST_ASSERT(memcmp(ctx->transcript, data1, 4) == 0, "Data mismatch");

    rc = wolfSPDM_TranscriptAdd(ctx, data2, sizeof(data2));
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "Second add failed");
    TEST_ASSERT(ctx->transcriptLen == 8, "Length should be 8");
    TEST_ASSERT(memcmp(ctx->transcript + 4, data2, 4) == 0, "Data2 mismatch");

    wolfSPDM_TranscriptReset(ctx);
    TEST_ASSERT(ctx->transcriptLen == 0, "Reset should clear length");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_transcript_hash(void)
{
    WOLFSPDM_CTX* ctx;
    byte data[] = "test data for hashing";
    byte hash[WOLFSPDM_HASH_SIZE];
    int rc;

    printf("test_transcript_hash...\n");

    ctx = wolfSPDM_New();
    wolfSPDM_Init(ctx);

    wolfSPDM_TranscriptAdd(ctx, data, sizeof(data) - 1);

    rc = wolfSPDM_TranscriptHash(ctx, hash);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "TranscriptHash failed");

    /* Verify hash is non-zero */
    int nonZero = 0;
    for (int i = 0; i < WOLFSPDM_HASH_SIZE; i++) {
        if (hash[i] != 0) nonZero = 1;
    }
    TEST_ASSERT(nonZero, "Hash should be non-zero");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_certchain_hash(void)
{
    WOLFSPDM_CTX* ctx;
    byte certData[] = {0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD};
    int rc;

    printf("test_certchain_hash...\n");

    ctx = wolfSPDM_New();
    wolfSPDM_Init(ctx);

    rc = wolfSPDM_CertChainAdd(ctx, certData, sizeof(certData));
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "CertChainAdd failed");
    TEST_ASSERT(ctx->certChainLen == sizeof(certData), "CertChain len wrong");

    rc = wolfSPDM_ComputeCertChainHash(ctx);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "ComputeCertChainHash failed");

    /* Verify Ct is non-zero */
    int nonZero = 0;
    for (int i = 0; i < WOLFSPDM_HASH_SIZE; i++) {
        if (ctx->certChainHash[i] != 0) nonZero = 1;
    }
    TEST_ASSERT(nonZero, "Ct should be non-zero");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

/* ========================================================================== */
/* Crypto Tests */
/* ========================================================================== */

static int test_random_generation(void)
{
    WOLFSPDM_CTX* ctx;
    byte buf1[32], buf2[32];
    int rc;

    printf("test_random_generation...\n");

    ctx = wolfSPDM_New();
    wolfSPDM_Init(ctx);

    rc = wolfSPDM_GetRandom(ctx, buf1, sizeof(buf1));
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "GetRandom failed");

    rc = wolfSPDM_GetRandom(ctx, buf2, sizeof(buf2));
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "Second GetRandom failed");

    /* Two random outputs should differ */
    TEST_ASSERT(memcmp(buf1, buf2, sizeof(buf1)) != 0,
        "Random outputs should differ");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_ephemeral_key_generation(void)
{
    WOLFSPDM_CTX* ctx;
    byte pubKeyX[WOLFSPDM_ECC_KEY_SIZE];
    byte pubKeyY[WOLFSPDM_ECC_KEY_SIZE];
    word32 xSz = sizeof(pubKeyX);
    word32 ySz = sizeof(pubKeyY);
    int rc;

    printf("test_ephemeral_key_generation...\n");

    ctx = wolfSPDM_New();
    wolfSPDM_Init(ctx);

    rc = wolfSPDM_GenerateEphemeralKey(ctx);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "GenerateEphemeralKey failed");
    TEST_ASSERT(ctx->ephemeralKeyInitialized == 1, "Key not marked initialized");

    rc = wolfSPDM_ExportEphemeralPubKey(ctx, pubKeyX, &xSz, pubKeyY, &ySz);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "ExportEphemeralPubKey failed");
    TEST_ASSERT(xSz == WOLFSPDM_ECC_KEY_SIZE, "X coordinate wrong size");
    TEST_ASSERT(ySz == WOLFSPDM_ECC_KEY_SIZE, "Y coordinate wrong size");

    /* Verify non-zero */
    int nonZero = 0;
    for (word32 i = 0; i < xSz; i++) {
        if (pubKeyX[i] != 0) nonZero = 1;
    }
    TEST_ASSERT(nonZero, "Public key X should be non-zero");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

/* ========================================================================== */
/* KDF Tests */
/* ========================================================================== */

static int test_hkdf_expand_label(void)
{
    byte secret[48];
    byte output[32];
    byte context[48];
    int rc;

    printf("test_hkdf_expand_label...\n");

    memset(secret, 0x5A, sizeof(secret));
    memset(context, 0x00, sizeof(context));

    rc = wolfSPDM_HkdfExpandLabel(0x13, secret, sizeof(secret),
        SPDM_LABEL_KEY, context, sizeof(context),
        output, sizeof(output));
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "HkdfExpandLabel failed");

    /* Verify non-zero output */
    int nonZero = 0;
    for (int i = 0; i < 32; i++) {
        if (output[i] != 0) nonZero = 1;
    }
    TEST_ASSERT(nonZero, "HKDF output should be non-zero");

    TEST_PASS();
}

static int test_compute_verify_data(void)
{
    byte finishedKey[WOLFSPDM_HASH_SIZE];
    byte thHash[WOLFSPDM_HASH_SIZE];
    byte verifyData[WOLFSPDM_HASH_SIZE];
    int rc;

    printf("test_compute_verify_data...\n");

    memset(finishedKey, 0xAB, sizeof(finishedKey));
    memset(thHash, 0xCD, sizeof(thHash));

    rc = wolfSPDM_ComputeVerifyData(finishedKey, thHash, verifyData);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "ComputeVerifyData failed");

    /* Verify it's an HMAC (non-zero) */
    int nonZero = 0;
    for (int i = 0; i < WOLFSPDM_HASH_SIZE; i++) {
        if (verifyData[i] != 0) nonZero = 1;
    }
    TEST_ASSERT(nonZero, "VerifyData should be non-zero");

    TEST_PASS();
}

/* ========================================================================== */
/* Message Builder Tests */
/* ========================================================================== */

static int test_build_get_version(void)
{
    byte buf[16];
    word32 bufSz = sizeof(buf);
    int rc;

    printf("test_build_get_version...\n");

    rc = wolfSPDM_BuildGetVersion(buf, &bufSz);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildGetVersion failed");
    TEST_ASSERT(bufSz == 4, "GET_VERSION should be 4 bytes");
    TEST_ASSERT(buf[0] == SPDM_VERSION_10, "Version should be 0x10");
    TEST_ASSERT(buf[1] == SPDM_GET_VERSION, "Code should be 0x84");
    TEST_ASSERT(buf[2] == 0x00, "Param1 should be 0");
    TEST_ASSERT(buf[3] == 0x00, "Param2 should be 0");

    /* Buffer too small */
    bufSz = 2;
    rc = wolfSPDM_BuildGetVersion(buf, &bufSz);
    TEST_ASSERT(rc == WOLFSPDM_E_BUFFER_SMALL, "Should fail on small buffer");

    TEST_PASS();
}

static int test_build_get_capabilities(void)
{
    byte buf[32];
    word32 bufSz = sizeof(buf);
    int rc;

    printf("test_build_get_capabilities...\n");

    rc = wolfSPDM_BuildGetCapabilities(buf, &bufSz, WOLFSPDM_DEFAULT_REQ_CAPS);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildGetCapabilities failed");
    TEST_ASSERT(bufSz == 20, "GET_CAPABILITIES should be 20 bytes");
    TEST_ASSERT(buf[0] == SPDM_VERSION_12, "Version should be 0x12");
    TEST_ASSERT(buf[1] == SPDM_GET_CAPABILITIES, "Code should be 0xE1");

    TEST_PASS();
}

static int test_build_negotiate_algorithms(void)
{
    byte buf[64];
    word32 bufSz = sizeof(buf);
    int rc;

    printf("test_build_negotiate_algorithms...\n");

    rc = wolfSPDM_BuildNegotiateAlgorithms(buf, &bufSz);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildNegotiateAlgorithms failed");
    TEST_ASSERT(bufSz == 48, "NEGOTIATE_ALGORITHMS should be 48 bytes");
    TEST_ASSERT(buf[0] == SPDM_VERSION_12, "Version should be 0x12");
    TEST_ASSERT(buf[1] == SPDM_NEGOTIATE_ALGORITHMS, "Code should be 0xE3");

    TEST_PASS();
}

static int test_build_get_digests(void)
{
    byte buf[16];
    word32 bufSz = sizeof(buf);
    int rc;

    printf("test_build_get_digests...\n");

    rc = wolfSPDM_BuildGetDigests(buf, &bufSz);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildGetDigests failed");
    TEST_ASSERT(bufSz == 4, "GET_DIGESTS should be 4 bytes");
    TEST_ASSERT(buf[1] == SPDM_GET_DIGESTS, "Code should be 0x81");

    TEST_PASS();
}

static int test_build_get_certificate(void)
{
    byte buf[16];
    word32 bufSz = sizeof(buf);
    int rc;

    printf("test_build_get_certificate...\n");

    rc = wolfSPDM_BuildGetCertificate(buf, &bufSz, 0, 0, 1024);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildGetCertificate failed");
    TEST_ASSERT(bufSz == 8, "GET_CERTIFICATE should be 8 bytes");
    TEST_ASSERT(buf[1] == SPDM_GET_CERTIFICATE, "Code should be 0x82");
    TEST_ASSERT(buf[2] == 0x00, "SlotID should be 0");
    TEST_ASSERT(buf[6] == 0x00 && buf[7] == 0x04, "Length should be 1024");

    TEST_PASS();
}

static int test_build_end_session(void)
{
    byte buf[16];
    word32 bufSz = sizeof(buf);
    int rc;

    printf("test_build_end_session...\n");

    rc = wolfSPDM_BuildEndSession(buf, &bufSz);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildEndSession failed");
    TEST_ASSERT(bufSz == 4, "END_SESSION should be 4 bytes");
    TEST_ASSERT(buf[1] == SPDM_END_SESSION, "Code should be 0xEA");

    TEST_PASS();
}

/* ========================================================================== */
/* Error Check Tests */
/* ========================================================================== */

static int test_check_error(void)
{
    byte errorMsg[] = {0x12, SPDM_ERROR, 0x06, 0x00};
    byte okMsg[] = {0x12, SPDM_VERSION, 0x00, 0x00};
    int errorCode = 0;

    printf("test_check_error...\n");

    TEST_ASSERT(wolfSPDM_CheckError(errorMsg, sizeof(errorMsg), &errorCode) == 1,
        "Should detect error");
    TEST_ASSERT(errorCode == SPDM_ERROR_DECRYPT_ERROR, "Error code wrong");

    TEST_ASSERT(wolfSPDM_CheckError(okMsg, sizeof(okMsg), NULL) == 0,
        "Should not detect error on OK message");

    TEST_PASS();
}

static int test_error_strings(void)
{
    printf("test_error_strings...\n");

    TEST_ASSERT(strcmp(wolfSPDM_GetErrorString(WOLFSPDM_SUCCESS), "Success") == 0,
        "SUCCESS string wrong");
    TEST_ASSERT(strcmp(wolfSPDM_GetErrorString(WOLFSPDM_E_INVALID_ARG),
        "Invalid argument") == 0, "INVALID_ARG string wrong");
    TEST_ASSERT(strcmp(wolfSPDM_GetErrorString(WOLFSPDM_E_CRYPTO_FAIL),
        "Crypto operation failed") == 0, "CRYPTO_FAIL string wrong");

    TEST_PASS();
}

/* ========================================================================== */
/* Session State Tests */
/* ========================================================================== */

static int test_session_state(void)
{
    WOLFSPDM_CTX* ctx;

    printf("test_session_state...\n");

    ctx = wolfSPDM_New();
    wolfSPDM_Init(ctx);

    TEST_ASSERT(wolfSPDM_IsConnected(ctx) == 0, "Should not be connected");
    TEST_ASSERT(wolfSPDM_GetSessionId(ctx) == 0, "SessionId should be 0");
    TEST_ASSERT(wolfSPDM_GetVersion_Negotiated(ctx) == 0, "Version should be 0");

    /* Simulate connected state */
    ctx->state = WOLFSPDM_STATE_CONNECTED;
    ctx->sessionId = 0xAABBCCDD;
    ctx->spdmVersion = SPDM_VERSION_12;

    TEST_ASSERT(wolfSPDM_IsConnected(ctx) == 1, "Should be connected");
    TEST_ASSERT(wolfSPDM_GetSessionId(ctx) == 0xAABBCCDD, "SessionId wrong");
    TEST_ASSERT(wolfSPDM_GetVersion_Negotiated(ctx) == SPDM_VERSION_12,
        "Version wrong");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

/* ========================================================================== */
/* Main */
/* ========================================================================== */

int main(void)
{
    printf("===========================================\n");
    printf("wolfSPDM Unit Tests\n");
    printf("===========================================\n\n");

    /* Context tests */
    test_context_new_free();
    test_context_init();
    test_context_static_alloc();
    test_context_set_io();

    /* Transcript tests */
    test_transcript_add_reset();
    test_transcript_hash();
    test_certchain_hash();

    /* Crypto tests */
    test_random_generation();
    test_ephemeral_key_generation();

    /* KDF tests */
    test_hkdf_expand_label();
    test_compute_verify_data();

    /* Message builder tests */
    test_build_get_version();
    test_build_get_capabilities();
    test_build_negotiate_algorithms();
    test_build_get_digests();
    test_build_get_certificate();
    test_build_end_session();

    /* Error tests */
    test_check_error();
    test_error_strings();

    /* Session state tests */
    test_session_state();

    printf("\n===========================================\n");
    printf("Results: %d passed, %d failed\n", g_testsPassed, g_testsFailed);
    printf("===========================================\n");

    return (g_testsFailed == 0) ? 0 : 1;
}
