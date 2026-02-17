/* unit_test.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * Unit tests for wolfSPDM library functions.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

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

/* Dummy I/O callback for testing */
static int dummy_io_cb(WOLFSPDM_CTX* ctx, const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz, void* userCtx)
{
    (void)ctx; (void)txBuf; (void)txSz;
    (void)rxBuf; (void)rxSz; (void)userCtx;
    return -1;
}

/* ========================================================================== */
/* Context Tests */
/* ========================================================================== */

#ifdef WOLFSPDM_DYNAMIC_MEMORY
static int test_context_new_free(void)
{
    WOLFSPDM_CTX* ctx;

    printf("test_context_new_free...\n");

    ctx = wolfSPDM_New();
    TEST_ASSERT(ctx != NULL, "wolfSPDM_New returned NULL");

    TEST_ASSERT(ctx->state == WOLFSPDM_STATE_INIT, "Initial state wrong");
    TEST_ASSERT(ctx->initialized == 1, "Should be initialized by New()");

    wolfSPDM_Free(ctx);

    /* Free NULL should not crash */
    wolfSPDM_Free(NULL);

    TEST_PASS();
}
#endif /* WOLFSPDM_DYNAMIC_MEMORY */

static int test_context_init(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    int rc;

    printf("test_context_init...\n");

    rc = wolfSPDM_Init(ctx);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "wolfSPDM_Init failed");
    TEST_ASSERT(ctx->initialized == 1, "Not marked initialized");
    TEST_ASSERT(ctx->rngInitialized == 1, "RNG not initialized");
    TEST_ASSERT(ctx->reqCaps == WOLFSPDM_DEFAULT_REQ_CAPS, "Default caps wrong");

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

    /* Too small buffer should fail */
    rc = wolfSPDM_InitStatic(ctx, 10);
    TEST_ASSERT(rc == WOLFSPDM_E_BUFFER_SMALL, "Should fail on small buffer");

    rc = wolfSPDM_InitStatic(ctx, sizeof(buffer));
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "InitStatic failed");
    TEST_ASSERT(ctx->initialized == 1, "Static ctx not initialized");

    wolfSPDM_Free(ctx);  /* Now safe — no XFREE on static ctx */

    TEST_PASS();
}

static int test_context_set_io(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    int rc;
    int dummy = 42;

    printf("test_context_set_io...\n");

    wolfSPDM_Init(ctx);

    /* Dummy callback for testing */
    rc = wolfSPDM_SetIO(ctx, dummy_io_cb, &dummy);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "SetIO failed");
    TEST_ASSERT(ctx->ioCb == dummy_io_cb, "IO callback not set");
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
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte data1[] = {0x01, 0x02, 0x03, 0x04};
    byte data2[] = {0x05, 0x06, 0x07, 0x08};
    int rc;

    printf("test_transcript_add_reset...\n");

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
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte data[] = "test data for hashing";
    byte hash[WOLFSPDM_HASH_SIZE];
    int rc;

    printf("test_transcript_hash...\n");

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
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte certData[] = {0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD};
    int rc;

    printf("test_certchain_hash...\n");

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
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte buf1[32], buf2[32];
    int rc;

    printf("test_random_generation...\n");

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
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte pubKeyX[WOLFSPDM_ECC_KEY_SIZE];
    byte pubKeyY[WOLFSPDM_ECC_KEY_SIZE];
    word32 xSz = sizeof(pubKeyX);
    word32 ySz = sizeof(pubKeyY);
    int rc;

    printf("test_ephemeral_key_generation...\n");

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
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte buf[32];
    word32 bufSz = sizeof(buf);
    int rc;

    printf("test_build_get_capabilities...\n");

    wolfSPDM_Init(ctx);
    ctx->spdmVersion = SPDM_VERSION_12;

    rc = wolfSPDM_BuildGetCapabilities(ctx, buf, &bufSz);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildGetCapabilities failed");
    TEST_ASSERT(bufSz == 20, "GET_CAPABILITIES should be 20 bytes");
    TEST_ASSERT(buf[0] == SPDM_VERSION_12, "Version should be 0x12");
    TEST_ASSERT(buf[1] == SPDM_GET_CAPABILITIES, "Code should be 0xE1");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_build_negotiate_algorithms(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte buf[64];
    word32 bufSz = sizeof(buf);
    int rc;

    printf("test_build_negotiate_algorithms...\n");

    wolfSPDM_Init(ctx);
    ctx->spdmVersion = SPDM_VERSION_12;

    rc = wolfSPDM_BuildNegotiateAlgorithms(ctx, buf, &bufSz);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildNegotiateAlgorithms failed");
    TEST_ASSERT(bufSz == 48, "NEGOTIATE_ALGORITHMS should be 48 bytes");
    TEST_ASSERT(buf[0] == SPDM_VERSION_12, "Version should be 0x12");
    TEST_ASSERT(buf[1] == SPDM_NEGOTIATE_ALGORITHMS, "Code should be 0xE3");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_build_get_digests(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte buf[16];
    word32 bufSz = sizeof(buf);
    int rc;

    printf("test_build_get_digests...\n");

    wolfSPDM_Init(ctx);
    ctx->spdmVersion = SPDM_VERSION_12;

    rc = wolfSPDM_BuildGetDigests(ctx, buf, &bufSz);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildGetDigests failed");
    TEST_ASSERT(bufSz == 4, "GET_DIGESTS should be 4 bytes");
    TEST_ASSERT(buf[1] == SPDM_GET_DIGESTS, "Code should be 0x81");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_build_get_certificate(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte buf[16];
    word32 bufSz = sizeof(buf);
    int rc;

    printf("test_build_get_certificate...\n");

    wolfSPDM_Init(ctx);
    ctx->spdmVersion = SPDM_VERSION_12;

    rc = wolfSPDM_BuildGetCertificate(ctx, buf, &bufSz, 0, 0, 1024);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildGetCertificate failed");
    TEST_ASSERT(bufSz == 8, "GET_CERTIFICATE should be 8 bytes");
    TEST_ASSERT(buf[1] == SPDM_GET_CERTIFICATE, "Code should be 0x82");
    TEST_ASSERT(buf[2] == 0x00, "SlotID should be 0");
    TEST_ASSERT(buf[6] == 0x00 && buf[7] == 0x04, "Length should be 1024");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_build_end_session(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte buf[16];
    word32 bufSz = sizeof(buf);
    int rc;

    printf("test_build_end_session...\n");

    wolfSPDM_Init(ctx);
    ctx->spdmVersion = SPDM_VERSION_12;

    rc = wolfSPDM_BuildEndSession(ctx, buf, &bufSz);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildEndSession failed");
    TEST_ASSERT(bufSz == 4, "END_SESSION should be 4 bytes");
    TEST_ASSERT(buf[1] == SPDM_END_SESSION, "Code should be 0xEA");

    wolfSPDM_Free(ctx);
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
/* Measurement Tests */
/* ========================================================================== */

#ifndef NO_WOLFSPDM_MEAS

static int test_build_get_measurements(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte buf[64];
    word32 bufSz;
    int rc;

    printf("test_build_get_measurements...\n");

    wolfSPDM_Init(ctx);
    ctx->spdmVersion = SPDM_VERSION_12;

    /* Build without signature */
    bufSz = sizeof(buf);
    rc = wolfSPDM_BuildGetMeasurements(ctx, buf, &bufSz,
        SPDM_MEAS_OPERATION_ALL, 0);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "Build without sig failed");
    TEST_ASSERT(bufSz == 4, "Without sig should be 4 bytes");
    TEST_ASSERT(buf[0] == SPDM_VERSION_12, "Version wrong");
    TEST_ASSERT(buf[1] == SPDM_GET_MEASUREMENTS, "Code should be 0xE0");
    TEST_ASSERT(buf[2] == 0x00, "Param1 should be 0 (no sig)");
    TEST_ASSERT(buf[3] == SPDM_MEAS_OPERATION_ALL, "Param2 should be 0xFF");

    /* Build with signature */
    bufSz = sizeof(buf);
    rc = wolfSPDM_BuildGetMeasurements(ctx, buf, &bufSz,
        SPDM_MEAS_OPERATION_ALL, 1);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "Build with sig failed");
    TEST_ASSERT(bufSz == 37, "With sig should be 37 bytes");
    TEST_ASSERT(buf[2] == SPDM_MEAS_REQUEST_SIG_BIT, "Sig bit should be set");

    /* Verify nonce was populated (non-zero) */
    {
        int nonZero = 0;
        int i;
        for (i = 4; i < 36; i++) {
            if (buf[i] != 0) nonZero = 1;
        }
        TEST_ASSERT(nonZero, "Nonce should be non-zero");
    }

    /* Verify nonce saved in context */
    TEST_ASSERT(memcmp(ctx->measNonce, &buf[4], 32) == 0,
        "Nonce should match context");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_measurement_accessors(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte measIdx, measType;
    byte value[64];
    word32 valueSz;
    int rc;

    printf("test_measurement_accessors...\n");

    wolfSPDM_Init(ctx);

    /* Before measurements: count should be 0 */
    TEST_ASSERT(wolfSPDM_GetMeasurementCount(ctx) == 0,
        "Count should be 0 before measurements");

    /* Manually populate 2 test blocks */
    ctx->hasMeasurements = 1;
    ctx->measBlockCount = 2;

    ctx->measBlocks[0].index = 1;
    ctx->measBlocks[0].dmtfType = SPDM_MEAS_VALUE_TYPE_IMMUTABLE_ROM;
    ctx->measBlocks[0].valueSize = 4;
    ctx->measBlocks[0].value[0] = 0xAA;
    ctx->measBlocks[0].value[1] = 0xBB;
    ctx->measBlocks[0].value[2] = 0xCC;
    ctx->measBlocks[0].value[3] = 0xDD;

    ctx->measBlocks[1].index = 2;
    ctx->measBlocks[1].dmtfType = SPDM_MEAS_VALUE_TYPE_MUTABLE_FW;
    ctx->measBlocks[1].valueSize = 2;
    ctx->measBlocks[1].value[0] = 0x11;
    ctx->measBlocks[1].value[1] = 0x22;

    TEST_ASSERT(wolfSPDM_GetMeasurementCount(ctx) == 2,
        "Count should be 2");

    /* Get block 0 */
    valueSz = sizeof(value);
    rc = wolfSPDM_GetMeasurementBlock(ctx, 0, &measIdx, &measType,
        value, &valueSz);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "GetMeasurementBlock(0) failed");
    TEST_ASSERT(measIdx == 1, "Block 0 index should be 1");
    TEST_ASSERT(measType == SPDM_MEAS_VALUE_TYPE_IMMUTABLE_ROM,
        "Block 0 type wrong");
    TEST_ASSERT(valueSz == 4, "Block 0 size wrong");
    TEST_ASSERT(value[0] == 0xAA, "Block 0 value wrong");

    /* Get block 1 */
    valueSz = sizeof(value);
    rc = wolfSPDM_GetMeasurementBlock(ctx, 1, &measIdx, &measType,
        value, &valueSz);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "GetMeasurementBlock(1) failed");
    TEST_ASSERT(measIdx == 2, "Block 1 index should be 2");
    TEST_ASSERT(valueSz == 2, "Block 1 size wrong");

    /* Out of range */
    valueSz = sizeof(value);
    rc = wolfSPDM_GetMeasurementBlock(ctx, 2, &measIdx, &measType,
        value, &valueSz);
    TEST_ASSERT(rc == WOLFSPDM_E_INVALID_ARG,
        "Out of range should return INVALID_ARG");

    rc = wolfSPDM_GetMeasurementBlock(ctx, -1, &measIdx, &measType,
        value, &valueSz);
    TEST_ASSERT(rc == WOLFSPDM_E_INVALID_ARG,
        "Negative index should return INVALID_ARG");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_parse_measurements(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    /* Construct a fake MEASUREMENTS response with 2 blocks:
     *
     * Header (8 bytes):
     *   [0] version=0x12 [1] code=0x60 [2] param1 [3] param2
     *   [4] numBlocks=2
     *   [5..7] recordLen (3 LE)
     *
     * Block 1 (4+7=11 bytes):
     *   Index=1, MeasSpec=1, MeasSize=7 (LE)
     *   DMTF: Type=0x00, ValueSize=4 (LE), Value=AA BB CC DD
     *
     * Block 2 (4+5=9 bytes):
     *   Index=2, MeasSpec=1, MeasSize=5 (LE)
     *   DMTF: Type=0x01, ValueSize=2 (LE), Value=11 22
     *
     * RecordLen = 11 + 9 = 20
     */
    byte rsp[] = {
        0x12, 0x60, 0x00, 0x00,   /* header */
        0x02,                       /* numBlocks */
        0x14, 0x00, 0x00,           /* recordLen = 20 LE */
        /* Block 1 */
        0x01,                       /* Index */
        0x01,                       /* MeasSpec (DMTF) */
        0x07, 0x00,                 /* MeasSize = 7 LE */
        0x00,                       /* DMTF Type: Immutable ROM */
        0x04, 0x00,                 /* ValueSize = 4 LE */
        0xAA, 0xBB, 0xCC, 0xDD,    /* Value */
        /* Block 2 */
        0x02,                       /* Index */
        0x01,                       /* MeasSpec (DMTF) */
        0x05, 0x00,                 /* MeasSize = 5 LE */
        0x01,                       /* DMTF Type: Mutable FW */
        0x02, 0x00,                 /* ValueSize = 2 LE */
        0x11, 0x22                  /* Value */
    };
    int rc;

    printf("test_parse_measurements...\n");

    wolfSPDM_Init(ctx);

    rc = wolfSPDM_ParseMeasurements(ctx, rsp, sizeof(rsp));
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "ParseMeasurements failed");
    TEST_ASSERT(ctx->measBlockCount == 2, "Should have 2 blocks");
    TEST_ASSERT(ctx->hasMeasurements == 1, "hasMeasurements should be set");

    /* Check block 0 */
    TEST_ASSERT(ctx->measBlocks[0].index == 1, "Block 0 index wrong");
    TEST_ASSERT(ctx->measBlocks[0].dmtfType == 0x00, "Block 0 type wrong");
    TEST_ASSERT(ctx->measBlocks[0].valueSize == 4, "Block 0 valueSize wrong");
    TEST_ASSERT(ctx->measBlocks[0].value[0] == 0xAA, "Block 0 value[0] wrong");
    TEST_ASSERT(ctx->measBlocks[0].value[3] == 0xDD, "Block 0 value[3] wrong");

    /* Check block 1 */
    TEST_ASSERT(ctx->measBlocks[1].index == 2, "Block 1 index wrong");
    TEST_ASSERT(ctx->measBlocks[1].dmtfType == 0x01, "Block 1 type wrong");
    TEST_ASSERT(ctx->measBlocks[1].valueSize == 2, "Block 1 valueSize wrong");
    TEST_ASSERT(ctx->measBlocks[1].value[0] == 0x11, "Block 1 value[0] wrong");

    /* Test truncated buffer */
    rc = wolfSPDM_ParseMeasurements(ctx, rsp, 5);
    TEST_ASSERT(rc == WOLFSPDM_E_MEASUREMENT,
        "Truncated should return MEASUREMENT error");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

#ifndef NO_WOLFSPDM_MEAS_VERIFY

static int test_measurement_sig_verification(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    ecc_key sigKey;
    WC_RNG rng;
    /* Construct a minimal GET_MEASUREMENTS request (L1) */
    byte reqMsg[] = {
        0x12, 0xE0, 0x01, 0xFF,    /* version, GET_MEASUREMENTS, sig bit, all */
        /* 32 bytes nonce */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        0x00  /* SlotID */
    };
    /* Construct a MEASUREMENTS response (L2) WITHOUT signature
     * We'll append signature after signing */
    byte rspBase[] = {
        0x12, 0x60, 0x00, 0x00,   /* header */
        0x01,                       /* numBlocks=1 */
        0x0B, 0x00, 0x00,           /* recordLen=11 */
        /* Block 1 */
        0x01, 0x01, 0x07, 0x00,    /* Index=1, Spec=1, Size=7 */
        0x00, 0x04, 0x00,           /* Type=0, ValueSize=4 */
        0xAA, 0xBB, 0xCC, 0xDD,    /* Value */
        /* Nonce (32 bytes) */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
        /* OpaqueDataLength = 0 */
        0x00, 0x00
    };
    byte rspBuf[256];  /* rspBase + 96 byte signature */
    word32 rspBufSz;
    wc_Sha384 sha, sha2;
    byte digest[WOLFSPDM_HASH_SIZE];
    byte derSig[256];
    word32 derSigSz = sizeof(derSig);
    byte rawR[WOLFSPDM_ECC_KEY_SIZE];
    byte rawS[WOLFSPDM_ECC_KEY_SIZE];
    word32 rSz = sizeof(rawR);
    word32 sSz = sizeof(rawS);
    int rc;

    printf("test_measurement_sig_verification...\n");

    wolfSPDM_Init(ctx);
    ctx->spdmVersion = SPDM_VERSION_12;

    /* Generate ECC P-384 keypair for testing */
    rc = wc_InitRng(&rng);
    TEST_ASSERT(rc == 0, "wc_InitRng failed");
    rc = wc_ecc_init(&sigKey);
    TEST_ASSERT(rc == 0, "wc_ecc_init failed");
    rc = wc_ecc_make_key(&rng, 48, &sigKey);
    TEST_ASSERT(rc == 0, "wc_ecc_make_key failed");

    /* Copy public key into context for verification */
    rc = wc_ecc_init(&ctx->responderPubKey);
    TEST_ASSERT(rc == 0, "wc_ecc_init responderPubKey failed");

    /* Export/import just the public key */
    {
        byte pubDer[256];
        word32 pubDerSz = sizeof(pubDer);
        word32 idx = 0;
        rc = wc_EccPublicKeyToDer(&sigKey, pubDer, pubDerSz, 1);
        TEST_ASSERT(rc > 0, "EccPublicKeyToDer failed");
        pubDerSz = (word32)rc;
        rc = wc_EccPublicKeyDecode(pubDer, &idx, &ctx->responderPubKey,
            pubDerSz);
        TEST_ASSERT(rc == 0, "EccPublicKeyDecode failed");
    }
    ctx->hasResponderPubKey = 1;

    /* Build the response buffer (rspBase + signature) */
    XMEMCPY(rspBuf, rspBase, sizeof(rspBase));
    rspBufSz = sizeof(rspBase);

    /* Compute Hash(L1||L2) where L2 = rspBase (before signature) */
    /* Then build M = prefix||pad||context||hash, then Hash(M) */
    {
        static const char context_str[] = "responder-measurements signing";
        #define TEST_PREFIX_SIZE 16
        #define TEST_CONTEXT_STR_SIZE 30  /* strlen, no null terminator */
        #define TEST_ZERO_PAD_SIZE (36 - TEST_CONTEXT_STR_SIZE)
        byte signMsg[200];
        word32 signMsgLen = 0;
        int i;

        /* L1||L2 hash */
        rc = wc_InitSha384(&sha);
        TEST_ASSERT(rc == 0, "InitSha384 failed");
        wc_Sha384Update(&sha, reqMsg, sizeof(reqMsg));
        wc_Sha384Update(&sha, rspBuf, rspBufSz);
        wc_Sha384Final(&sha, digest);
        wc_Sha384Free(&sha);

        /* Build M */
        for (i = 0; i < 4; i++) {
            XMEMCPY(&signMsg[signMsgLen], "dmtf-spdm-v1.2.*", TEST_PREFIX_SIZE);
            signMsgLen += TEST_PREFIX_SIZE;
        }
        XMEMSET(&signMsg[signMsgLen], 0x00, TEST_ZERO_PAD_SIZE);
        signMsgLen += TEST_ZERO_PAD_SIZE;
        XMEMCPY(&signMsg[signMsgLen], context_str, TEST_CONTEXT_STR_SIZE);
        signMsgLen += TEST_CONTEXT_STR_SIZE;
        XMEMCPY(&signMsg[signMsgLen], digest, WOLFSPDM_HASH_SIZE);
        signMsgLen += WOLFSPDM_HASH_SIZE;

        /* Hash(M) */
        rc = wc_InitSha384(&sha2);
        TEST_ASSERT(rc == 0, "InitSha384 for M failed");
        wc_Sha384Update(&sha2, signMsg, signMsgLen);
        wc_Sha384Final(&sha2, digest);
        wc_Sha384Free(&sha2);
    }

    /* Sign Hash(M) with our test key (DER format) */
    rc = wc_ecc_sign_hash(digest, WOLFSPDM_HASH_SIZE, derSig, &derSigSz,
        &rng, &sigKey);
    TEST_ASSERT(rc == 0, "ecc_sign_hash failed");

    /* Convert DER signature to raw r||s for SPDM */
    rc = wc_ecc_sig_to_rs(derSig, derSigSz, rawR, &rSz, rawS, &sSz);
    TEST_ASSERT(rc == 0, "ecc_sig_to_rs failed");

    /* Pad r and s to 48 bytes each (P-384) */
    {
        byte sigRaw[WOLFSPDM_ECC_SIG_SIZE];
        XMEMSET(sigRaw, 0, sizeof(sigRaw));
        /* Right-align r and s in their 48-byte fields */
        XMEMCPY(sigRaw + (48 - rSz), rawR, rSz);
        XMEMCPY(sigRaw + 48 + (48 - sSz), rawS, sSz);
        XMEMCPY(rspBuf + rspBufSz, sigRaw, WOLFSPDM_ECC_SIG_SIZE);
    }
    rspBufSz += WOLFSPDM_ECC_SIG_SIZE;

    /* Test 1: Valid signature should verify */
    rc = wolfSPDM_VerifyMeasurementSig(ctx, rspBuf, rspBufSz,
        reqMsg, sizeof(reqMsg));
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS,
        "Valid signature should verify");

    /* Test 2: Corrupt one signature byte -> should fail */
    rspBuf[rspBufSz - 10] ^= 0xFF;
    rc = wolfSPDM_VerifyMeasurementSig(ctx, rspBuf, rspBufSz,
        reqMsg, sizeof(reqMsg));
    TEST_ASSERT(rc == WOLFSPDM_E_MEAS_SIG_FAIL,
        "Corrupted sig should fail");
    rspBuf[rspBufSz - 10] ^= 0xFF;  /* Restore */

    /* Test 3: Corrupt one measurement byte -> should fail */
    rspBuf[15] ^= 0xFF;  /* Corrupt a measurement value byte */
    rc = wolfSPDM_VerifyMeasurementSig(ctx, rspBuf, rspBufSz,
        reqMsg, sizeof(reqMsg));
    TEST_ASSERT(rc == WOLFSPDM_E_MEAS_SIG_FAIL,
        "Corrupted measurement should fail");

    wc_ecc_free(&sigKey);
    wc_FreeRng(&rng);
    wolfSPDM_Free(ctx);
    TEST_PASS();
}

#endif /* !NO_WOLFSPDM_MEAS_VERIFY */
#endif /* !NO_WOLFSPDM_MEAS */

/* ========================================================================== */
/* Certificate Chain Validation Tests */
/* ========================================================================== */

static int test_set_trusted_cas(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte fakeCa[] = {0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD};
    int rc;

    printf("test_set_trusted_cas...\n");

    wolfSPDM_Init(ctx);

    /* NULL args should fail */
    rc = wolfSPDM_SetTrustedCAs(NULL, fakeCa, sizeof(fakeCa));
    TEST_ASSERT(rc == WOLFSPDM_E_INVALID_ARG, "NULL ctx should fail");

    rc = wolfSPDM_SetTrustedCAs(ctx, NULL, sizeof(fakeCa));
    TEST_ASSERT(rc == WOLFSPDM_E_INVALID_ARG, "NULL certs should fail");

    rc = wolfSPDM_SetTrustedCAs(ctx, fakeCa, 0);
    TEST_ASSERT(rc == WOLFSPDM_E_INVALID_ARG, "Zero size should fail");

    /* Valid call */
    rc = wolfSPDM_SetTrustedCAs(ctx, fakeCa, sizeof(fakeCa));
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "SetTrustedCAs failed");
    TEST_ASSERT(ctx->hasTrustedCAs == 1, "hasTrustedCAs not set");
    TEST_ASSERT(ctx->trustedCAsSz == sizeof(fakeCa), "Size mismatch");
    TEST_ASSERT(memcmp(ctx->trustedCAs, fakeCa, sizeof(fakeCa)) == 0,
        "Data mismatch");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_validate_cert_chain_no_cas(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    int rc;

    printf("test_validate_cert_chain_no_cas...\n");

    wolfSPDM_Init(ctx);

    /* No trusted CAs loaded — should return error */
    rc = wolfSPDM_ValidateCertChain(ctx);
    TEST_ASSERT(rc == WOLFSPDM_E_CERT_PARSE,
        "Should fail without trusted CAs");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

/* ========================================================================== */
/* Challenge Tests */
/* ========================================================================== */

#ifndef NO_WOLFSPDM_CHALLENGE

static int test_build_challenge(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte buf[64];
    word32 bufSz;
    int rc;

    printf("test_build_challenge...\n");

    wolfSPDM_Init(ctx);
    ctx->spdmVersion = SPDM_VERSION_12;

    bufSz = sizeof(buf);
    rc = wolfSPDM_BuildChallenge(ctx, buf, &bufSz, 0,
        SPDM_MEAS_SUMMARY_HASH_NONE);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildChallenge failed");
    TEST_ASSERT(bufSz == 36, "CHALLENGE should be 36 bytes");
    TEST_ASSERT(buf[0] == SPDM_VERSION_12, "Version wrong");
    TEST_ASSERT(buf[1] == SPDM_CHALLENGE, "Code should be 0x83");
    TEST_ASSERT(buf[2] == 0x00, "SlotID should be 0");
    TEST_ASSERT(buf[3] == SPDM_MEAS_SUMMARY_HASH_NONE, "MeasHashType wrong");

    /* Verify nonce is populated (non-zero) */
    {
        int nonZero = 0;
        int i;
        for (i = 4; i < 36; i++) {
            if (buf[i] != 0) nonZero = 1;
        }
        TEST_ASSERT(nonZero, "Nonce should be non-zero");
    }

    /* Verify nonce saved in context */
    TEST_ASSERT(memcmp(ctx->challengeNonce, &buf[4], 32) == 0,
        "Challenge nonce should match context");

    /* Test with different slot and meas hash type */
    bufSz = sizeof(buf);
    rc = wolfSPDM_BuildChallenge(ctx, buf, &bufSz, 3,
        SPDM_MEAS_SUMMARY_HASH_ALL);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildChallenge slot 3 failed");
    TEST_ASSERT(buf[2] == 0x03, "SlotID should be 3");
    TEST_ASSERT(buf[3] == 0xFF, "MeasHashType should be 0xFF");

    /* Buffer too small */
    bufSz = 10;
    rc = wolfSPDM_BuildChallenge(ctx, buf, &bufSz, 0,
        SPDM_MEAS_SUMMARY_HASH_NONE);
    TEST_ASSERT(rc == WOLFSPDM_E_BUFFER_SMALL, "Should fail on small buffer");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_parse_challenge_auth(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    /* Build a fake CHALLENGE_AUTH response (measHashType=NONE):
     * [0-3]   header: version=0x12, code=0x03, param1, param2
     * [4-51]  CertChainHash (48 bytes)
     * [52-83] Nonce (32 bytes per DSP0274)
     * (no MeasurementSummaryHash when type=NONE)
     * [84-85] OpaqueDataLength = 0
     * [86-181] Signature (96 bytes) */
    byte rsp[182];
    word32 sigOffset = 0;
    int rc;

    printf("test_parse_challenge_auth...\n");

    wolfSPDM_Init(ctx);
    ctx->spdmVersion = SPDM_VERSION_12;
    ctx->challengeMeasHashType = SPDM_MEAS_SUMMARY_HASH_NONE;

    XMEMSET(rsp, 0, sizeof(rsp));
    rsp[0] = SPDM_VERSION_12;
    rsp[1] = SPDM_CHALLENGE_AUTH;
    rsp[2] = 0x00;  /* Param1 */
    rsp[3] = 0x00;  /* Param2 */

    /* Fill CertChainHash with known pattern to match ctx */
    XMEMSET(&rsp[4], 0xAA, WOLFSPDM_HASH_SIZE);
    XMEMCPY(ctx->certChainHash, &rsp[4], WOLFSPDM_HASH_SIZE);

    /* Fill nonce (32 bytes) */
    XMEMSET(&rsp[52], 0xBB, 32);

    /* OpaqueDataLength = 0 (no MeasSummaryHash since type=NONE) */
    rsp[84] = 0x00;
    rsp[85] = 0x00;

    /* Fake signature (96 bytes) */
    XMEMSET(&rsp[86], 0xCC, WOLFSPDM_ECC_SIG_SIZE);

    rc = wolfSPDM_ParseChallengeAuth(ctx, rsp, sizeof(rsp), &sigOffset);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "ParseChallengeAuth failed");
    TEST_ASSERT(sigOffset == 86, "Signature offset should be 86");

    /* Test with wrong response code */
    rsp[1] = 0xFF;
    rc = wolfSPDM_ParseChallengeAuth(ctx, rsp, sizeof(rsp), &sigOffset);
    TEST_ASSERT(rc == WOLFSPDM_E_CHALLENGE, "Wrong code should fail");
    rsp[1] = SPDM_CHALLENGE_AUTH;

    /* Test with CertChainHash mismatch */
    ctx->certChainHash[0] = 0x00;  /* Change expected hash */
    rc = wolfSPDM_ParseChallengeAuth(ctx, rsp, sizeof(rsp), &sigOffset);
    TEST_ASSERT(rc == WOLFSPDM_E_CHALLENGE, "Hash mismatch should fail");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

#endif /* !NO_WOLFSPDM_CHALLENGE */

/* ========================================================================== */
/* Heartbeat Tests */
/* ========================================================================== */

static int test_build_heartbeat(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte buf[16];
    word32 bufSz;
    int rc;

    printf("test_build_heartbeat...\n");

    wolfSPDM_Init(ctx);
    ctx->spdmVersion = SPDM_VERSION_12;

    bufSz = sizeof(buf);
    rc = wolfSPDM_BuildHeartbeat(ctx, buf, &bufSz);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildHeartbeat failed");
    TEST_ASSERT(bufSz == 4, "HEARTBEAT should be 4 bytes");
    TEST_ASSERT(buf[0] == SPDM_VERSION_12, "Version wrong");
    TEST_ASSERT(buf[1] == SPDM_HEARTBEAT, "Code should be 0xE8");
    TEST_ASSERT(buf[2] == 0x00, "Param1 should be 0");
    TEST_ASSERT(buf[3] == 0x00, "Param2 should be 0");

    /* Buffer too small */
    bufSz = 2;
    rc = wolfSPDM_BuildHeartbeat(ctx, buf, &bufSz);
    TEST_ASSERT(rc == WOLFSPDM_E_BUFFER_SMALL, "Should fail on small buffer");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_parse_heartbeat_ack(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte ack[] = {0x12, SPDM_HEARTBEAT_ACK, 0x00, 0x00};
    byte err[] = {0x12, SPDM_ERROR, 0x01, 0x00};
    int rc;

    printf("test_parse_heartbeat_ack...\n");

    wolfSPDM_Init(ctx);

    /* Valid ACK */
    rc = wolfSPDM_ParseHeartbeatAck(ctx, ack, sizeof(ack));
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "Valid ACK should succeed");

    /* Error response */
    rc = wolfSPDM_ParseHeartbeatAck(ctx, err, sizeof(err));
    TEST_ASSERT(rc == WOLFSPDM_E_PEER_ERROR, "Error should return PEER_ERROR");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_heartbeat_state_check(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    int rc;

    printf("test_heartbeat_state_check...\n");

    wolfSPDM_Init(ctx);

    /* Not connected — should fail */
    rc = wolfSPDM_Heartbeat(ctx);
    TEST_ASSERT(rc == WOLFSPDM_E_NOT_CONNECTED,
        "Heartbeat should fail when not connected");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

/* ========================================================================== */
/* Key Update Tests */
/* ========================================================================== */

static int test_build_key_update(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte buf[16];
    word32 bufSz;
    byte tag = 0;
    int rc;

    printf("test_build_key_update...\n");

    wolfSPDM_Init(ctx);
    ctx->spdmVersion = SPDM_VERSION_12;

    bufSz = sizeof(buf);
    rc = wolfSPDM_BuildKeyUpdate(ctx, buf, &bufSz,
        SPDM_KEY_UPDATE_OP_UPDATE_ALL_KEYS, &tag);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "BuildKeyUpdate failed");
    TEST_ASSERT(bufSz == 4, "KEY_UPDATE should be 4 bytes");
    TEST_ASSERT(buf[0] == SPDM_VERSION_12, "Version wrong");
    TEST_ASSERT(buf[1] == SPDM_KEY_UPDATE, "Code should be 0xE9");
    TEST_ASSERT(buf[2] == SPDM_KEY_UPDATE_OP_UPDATE_ALL_KEYS,
        "Operation should be UpdateAllKeys");
    TEST_ASSERT(buf[3] == tag, "Tag should match returned value");

    /* Buffer too small */
    bufSz = 2;
    rc = wolfSPDM_BuildKeyUpdate(ctx, buf, &bufSz,
        SPDM_KEY_UPDATE_OP_UPDATE_KEY, &tag);
    TEST_ASSERT(rc == WOLFSPDM_E_BUFFER_SMALL, "Should fail on small buffer");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_parse_key_update_ack(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte ack[] = {0x12, SPDM_KEY_UPDATE_ACK, 0x02, 0x42};
    int rc;

    printf("test_parse_key_update_ack...\n");

    wolfSPDM_Init(ctx);

    /* Valid ACK with matching operation and tag */
    rc = wolfSPDM_ParseKeyUpdateAck(ctx, ack, sizeof(ack),
        SPDM_KEY_UPDATE_OP_UPDATE_ALL_KEYS, 0x42);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "Valid ACK should succeed");

    /* Mismatched tag */
    rc = wolfSPDM_ParseKeyUpdateAck(ctx, ack, sizeof(ack),
        SPDM_KEY_UPDATE_OP_UPDATE_ALL_KEYS, 0xFF);
    TEST_ASSERT(rc == WOLFSPDM_E_KEY_UPDATE, "Mismatched tag should fail");

    /* Mismatched operation */
    rc = wolfSPDM_ParseKeyUpdateAck(ctx, ack, sizeof(ack),
        SPDM_KEY_UPDATE_OP_UPDATE_KEY, 0x42);
    TEST_ASSERT(rc == WOLFSPDM_E_KEY_UPDATE, "Mismatched op should fail");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_derive_updated_keys(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    byte origReqKey[WOLFSPDM_AEAD_KEY_SIZE];
    byte origRspKey[WOLFSPDM_AEAD_KEY_SIZE];
    int rc;

    printf("test_derive_updated_keys...\n");

    wolfSPDM_Init(ctx);
    ctx->spdmVersion = SPDM_VERSION_12;

    /* Set up fake app secrets and keys */
    XMEMSET(ctx->reqAppSecret, 0x5A, WOLFSPDM_HASH_SIZE);
    XMEMSET(ctx->rspAppSecret, 0xA5, WOLFSPDM_HASH_SIZE);
    XMEMSET(ctx->reqDataKey, 0x11, WOLFSPDM_AEAD_KEY_SIZE);
    XMEMSET(ctx->rspDataKey, 0x22, WOLFSPDM_AEAD_KEY_SIZE);

    XMEMCPY(origReqKey, ctx->reqDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    XMEMCPY(origRspKey, ctx->rspDataKey, WOLFSPDM_AEAD_KEY_SIZE);

    /* Update all keys */
    rc = wolfSPDM_DeriveUpdatedKeys(ctx, 1);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "DeriveUpdatedKeys failed");

    /* Keys should have changed */
    TEST_ASSERT(memcmp(ctx->reqDataKey, origReqKey,
        WOLFSPDM_AEAD_KEY_SIZE) != 0, "Req key should change");
    TEST_ASSERT(memcmp(ctx->rspDataKey, origRspKey,
        WOLFSPDM_AEAD_KEY_SIZE) != 0, "Rsp key should change");

    /* Update requester only */
    XMEMCPY(origReqKey, ctx->reqDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    XMEMCPY(origRspKey, ctx->rspDataKey, WOLFSPDM_AEAD_KEY_SIZE);

    rc = wolfSPDM_DeriveUpdatedKeys(ctx, 0);
    TEST_ASSERT(rc == WOLFSPDM_SUCCESS, "DeriveUpdatedKeys (req only) failed");

    TEST_ASSERT(memcmp(ctx->reqDataKey, origReqKey,
        WOLFSPDM_AEAD_KEY_SIZE) != 0, "Req key should change");
    TEST_ASSERT(memcmp(ctx->rspDataKey, origRspKey,
        WOLFSPDM_AEAD_KEY_SIZE) == 0, "Rsp key should NOT change");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_key_update_state_check(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;
    int rc;

    printf("test_key_update_state_check...\n");

    wolfSPDM_Init(ctx);

    /* Not connected — should fail */
    rc = wolfSPDM_KeyUpdate(ctx, 1);
    TEST_ASSERT(rc == WOLFSPDM_E_NOT_CONNECTED,
        "KeyUpdate should fail when not connected");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

/* ========================================================================== */
/* Session State Tests */
/* ========================================================================== */

static int test_session_state(void)
{
    WOLFSPDM_CTX ctxBuf;
    WOLFSPDM_CTX* ctx = &ctxBuf;

    printf("test_session_state...\n");

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
#ifdef WOLFSPDM_DYNAMIC_MEMORY
    test_context_new_free();
#endif
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

    /* Measurement tests */
#ifndef NO_WOLFSPDM_MEAS
    test_build_get_measurements();
    test_measurement_accessors();
    test_parse_measurements();
#ifndef NO_WOLFSPDM_MEAS_VERIFY
    test_measurement_sig_verification();
#endif
#endif

    /* Certificate chain validation tests */
    test_set_trusted_cas();
    test_validate_cert_chain_no_cas();

    /* Challenge tests */
#ifndef NO_WOLFSPDM_CHALLENGE
    test_build_challenge();
    test_parse_challenge_auth();
#endif

    /* Heartbeat tests */
    test_build_heartbeat();
    test_parse_heartbeat_ack();
    test_heartbeat_state_check();

    /* Key update tests */
    test_build_key_update();
    test_parse_key_update_ack();
    test_derive_updated_keys();
    test_key_update_state_check();

    /* Session state tests */
    test_session_state();

    printf("\n===========================================\n");
    printf("Results: %d passed, %d failed\n", g_testsPassed, g_testsFailed);
    printf("===========================================\n");

    return (g_testsFailed == 0) ? 0 : 1;
}
