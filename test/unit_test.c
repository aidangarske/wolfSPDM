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

#define ASSERT_SUCCESS(expr) do { int _r = (expr); if (_r != 0) { \
    printf("  FAIL %s:%d: %s returned %d\n", __FILE__, __LINE__, #expr, _r); \
    g_testsFailed++; return -1; } } while(0)

#define ASSERT_FAIL(expr) do { int _r = (expr); if (_r == 0) { \
    printf("  FAIL %s:%d: %s should have failed\n", __FILE__, __LINE__, #expr); \
    g_testsFailed++; return -1; } } while(0)

#define ASSERT_EQ(a, b, msg) TEST_ASSERT((a) == (b), msg)
#define ASSERT_NE(a, b, msg) TEST_ASSERT((a) != (b), msg)

/* Test context setup/cleanup macros */
#define TEST_CTX_SETUP() \
    WOLFSPDM_CTX ctxBuf; \
    WOLFSPDM_CTX* ctx = &ctxBuf; \
    wolfSPDM_Init(ctx)

#define TEST_CTX_SETUP_V12() \
    TEST_CTX_SETUP(); \
    ctx->spdmVersion = SPDM_VERSION_12

#define TEST_CTX_FREE() \
    wolfSPDM_Free(ctx)

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
    ASSERT_EQ(ctx->state, WOLFSPDM_STATE_INIT, "Initial state wrong");
    ASSERT_EQ(ctx->flags.initialized, 1, "Should be initialized by New()");

    wolfSPDM_Free(ctx);
    wolfSPDM_Free(NULL); /* Should not crash */

    TEST_PASS();
}
#endif /* WOLFSPDM_DYNAMIC_MEMORY */

static int test_context_init(void)
{
    TEST_CTX_SETUP();

    printf("test_context_init...\n");
    ASSERT_EQ(ctx->flags.initialized, 1, "Not marked initialized");
    ASSERT_EQ(ctx->flags.rngInitialized, 1, "RNG not initialized");
    ASSERT_EQ(ctx->reqCaps, WOLFSPDM_DEFAULT_REQ_CAPS, "Default caps wrong");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_context_static_alloc(void)
{
    byte buffer[sizeof(WOLFSPDM_CTX) + 64];
    WOLFSPDM_CTX* ctx = (WOLFSPDM_CTX*)buffer;

    printf("test_context_static_alloc...\n");

    ASSERT_EQ(wolfSPDM_GetCtxSize(), (int)sizeof(WOLFSPDM_CTX), "GetCtxSize mismatch");
    ASSERT_EQ(wolfSPDM_InitStatic(ctx, 10), WOLFSPDM_E_BUFFER_SMALL, "Should fail on small buffer");
    ASSERT_SUCCESS(wolfSPDM_InitStatic(ctx, sizeof(buffer)));
    ASSERT_EQ(ctx->flags.initialized, 1, "Static ctx not initialized");

    wolfSPDM_Free(ctx);
    TEST_PASS();
}

static int test_context_set_io(void)
{
    int dummy = 42;
    TEST_CTX_SETUP();

    printf("test_context_set_io...\n");

    ASSERT_SUCCESS(wolfSPDM_SetIO(ctx, dummy_io_cb, &dummy));
    ASSERT_EQ(ctx->ioCb, dummy_io_cb, "IO callback not set");
    ASSERT_EQ(ctx->ioUserCtx, &dummy, "User context not set");
    ASSERT_EQ(wolfSPDM_SetIO(ctx, NULL, NULL), WOLFSPDM_E_INVALID_ARG, "NULL callback should fail");

    TEST_CTX_FREE();
    TEST_PASS();
}

/* ========================================================================== */
/* Transcript Tests */
/* ========================================================================== */

static int test_transcript_add_reset(void)
{
    byte data1[] = {0x01, 0x02, 0x03, 0x04};
    byte data2[] = {0x05, 0x06, 0x07, 0x08};
    TEST_CTX_SETUP();

    printf("test_transcript_add_reset...\n");
    ASSERT_EQ(ctx->transcriptLen, 0, "Transcript should start empty");

    ASSERT_SUCCESS(wolfSPDM_TranscriptAdd(ctx, data1, sizeof(data1)));
    ASSERT_EQ(ctx->transcriptLen, 4, "Length should be 4");
    ASSERT_EQ(memcmp(ctx->transcript, data1, 4), 0, "Data mismatch");

    ASSERT_SUCCESS(wolfSPDM_TranscriptAdd(ctx, data2, sizeof(data2)));
    ASSERT_EQ(ctx->transcriptLen, 8, "Length should be 8");
    ASSERT_EQ(memcmp(ctx->transcript + 4, data2, 4), 0, "Data2 mismatch");

    wolfSPDM_TranscriptReset(ctx);
    ASSERT_EQ(ctx->transcriptLen, 0, "Reset should clear length");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_transcript_hash(void)
{
    byte data[] = "test data for hashing";
    byte hash[WOLFSPDM_HASH_SIZE];
    byte zeros[WOLFSPDM_HASH_SIZE];
    TEST_CTX_SETUP();

    printf("test_transcript_hash...\n");
    wolfSPDM_TranscriptAdd(ctx, data, sizeof(data) - 1);
    ASSERT_SUCCESS(wolfSPDM_TranscriptHash(ctx, hash));
    XMEMSET(zeros, 0, sizeof(zeros));
    ASSERT_NE(memcmp(hash, zeros, WOLFSPDM_HASH_SIZE), 0, "Hash should be non-zero");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_certchain_hash(void)
{
    byte certData[] = {0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD};
    byte zeros[WOLFSPDM_HASH_SIZE];
    TEST_CTX_SETUP();

    printf("test_certchain_hash...\n");
    ASSERT_SUCCESS(wolfSPDM_CertChainAdd(ctx, certData, sizeof(certData)));
    ASSERT_EQ(ctx->certChainLen, sizeof(certData), "CertChain len wrong");
    ASSERT_SUCCESS(wolfSPDM_ComputeCertChainHash(ctx));
    XMEMSET(zeros, 0, sizeof(zeros));
    ASSERT_NE(memcmp(ctx->certChainHash, zeros, WOLFSPDM_HASH_SIZE), 0, "Ct should be non-zero");

    TEST_CTX_FREE();
    TEST_PASS();
}

/* ========================================================================== */
/* Crypto Tests */
/* ========================================================================== */

static int test_random_generation(void)
{
    byte buf1[32], buf2[32];
    TEST_CTX_SETUP();

    printf("test_random_generation...\n");
    ASSERT_SUCCESS(wolfSPDM_GetRandom(ctx, buf1, sizeof(buf1)));
    ASSERT_SUCCESS(wolfSPDM_GetRandom(ctx, buf2, sizeof(buf2)));
    ASSERT_NE(memcmp(buf1, buf2, sizeof(buf1)), 0, "Random outputs should differ");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_ephemeral_key_generation(void)
{
    byte pubKeyX[WOLFSPDM_ECC_KEY_SIZE];
    byte pubKeyY[WOLFSPDM_ECC_KEY_SIZE];
    byte zeros[WOLFSPDM_ECC_KEY_SIZE];
    word32 xSz = sizeof(pubKeyX);
    word32 ySz = sizeof(pubKeyY);
    TEST_CTX_SETUP();

    printf("test_ephemeral_key_generation...\n");
    ASSERT_SUCCESS(wolfSPDM_GenerateEphemeralKey(ctx));
    ASSERT_EQ(ctx->flags.ephemeralKeyInit, 1, "Key not marked initialized");
    ASSERT_SUCCESS(wolfSPDM_ExportEphemeralPubKey(ctx, pubKeyX, &xSz, pubKeyY, &ySz));
    ASSERT_EQ(xSz, WOLFSPDM_ECC_KEY_SIZE, "X coordinate wrong size");
    ASSERT_EQ(ySz, WOLFSPDM_ECC_KEY_SIZE, "Y coordinate wrong size");
    XMEMSET(zeros, 0, sizeof(zeros));
    ASSERT_NE(memcmp(pubKeyX, zeros, WOLFSPDM_ECC_KEY_SIZE), 0, "Public key X should be non-zero");

    TEST_CTX_FREE();
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
    byte zeros[32];

    printf("test_hkdf_expand_label...\n");

    memset(secret, 0x5A, sizeof(secret));
    memset(context, 0x00, sizeof(context));

    ASSERT_SUCCESS(wolfSPDM_HkdfExpandLabel(0x13, secret, sizeof(secret),
        SPDM_LABEL_KEY, context, sizeof(context), output, sizeof(output)));
    XMEMSET(zeros, 0, sizeof(zeros));
    ASSERT_NE(memcmp(output, zeros, sizeof(output)), 0, "HKDF output should be non-zero");

    TEST_PASS();
}

static int test_compute_verify_data(void)
{
    byte finishedKey[WOLFSPDM_HASH_SIZE];
    byte thHash[WOLFSPDM_HASH_SIZE];
    byte verifyData[WOLFSPDM_HASH_SIZE];
    byte zeros[WOLFSPDM_HASH_SIZE];

    printf("test_compute_verify_data...\n");

    memset(finishedKey, 0xAB, sizeof(finishedKey));
    memset(thHash, 0xCD, sizeof(thHash));

    ASSERT_SUCCESS(wolfSPDM_ComputeVerifyData(finishedKey, thHash, verifyData));
    XMEMSET(zeros, 0, sizeof(zeros));
    ASSERT_NE(memcmp(verifyData, zeros, WOLFSPDM_HASH_SIZE), 0, "VerifyData should be non-zero");

    TEST_PASS();
}

/* ========================================================================== */
/* Message Builder Tests */
/* ========================================================================== */

static int test_build_get_version(void)
{
    byte buf[16];
    word32 bufSz = sizeof(buf);

    printf("test_build_get_version...\n");

    ASSERT_SUCCESS(wolfSPDM_BuildGetVersion(buf, &bufSz));
    ASSERT_EQ(bufSz, 4, "GET_VERSION should be 4 bytes");
    ASSERT_EQ(buf[0], SPDM_VERSION_10, "Version should be 0x10");
    ASSERT_EQ(buf[1], SPDM_GET_VERSION, "Code should be 0x84");

    bufSz = 2;
    ASSERT_EQ(wolfSPDM_BuildGetVersion(buf, &bufSz), WOLFSPDM_E_BUFFER_SMALL, "Should fail on small buffer");

    TEST_PASS();
}

static int test_build_get_capabilities(void)
{
    byte buf[32];
    word32 bufSz = sizeof(buf);
    TEST_CTX_SETUP_V12();

    printf("test_build_get_capabilities...\n");
    ASSERT_SUCCESS(wolfSPDM_BuildGetCapabilities(ctx, buf, &bufSz));
    ASSERT_EQ(bufSz, 20, "GET_CAPABILITIES should be 20 bytes");
    ASSERT_EQ(buf[0], SPDM_VERSION_12, "Version should be 0x12");
    ASSERT_EQ(buf[1], SPDM_GET_CAPABILITIES, "Code should be 0xE1");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_build_negotiate_algorithms(void)
{
    byte buf[64];
    word32 bufSz = sizeof(buf);
    TEST_CTX_SETUP_V12();

    printf("test_build_negotiate_algorithms...\n");
    ASSERT_SUCCESS(wolfSPDM_BuildNegotiateAlgorithms(ctx, buf, &bufSz));
    ASSERT_EQ(bufSz, 48, "NEGOTIATE_ALGORITHMS should be 48 bytes");
    ASSERT_EQ(buf[1], SPDM_NEGOTIATE_ALGORITHMS, "Code should be 0xE3");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_parse_algorithms_set_b_enforcement(void)
{
    /* Synthesise a minimal ALGORITHMS response and verify each Set-B
     * constraint (BaseAsym=ECDSA-P384, BaseHash=SHA-384, DHE=SECP_384_R1,
     * AEAD=AES_256_GCM, KeySchedule=SPDM) is enforced. */
    byte rsp[64];
    TEST_CTX_SETUP_V12();

    printf("test_parse_algorithms_set_b_enforcement...\n");

    /* Build a response with Set-B selections. */
    XMEMSET(rsp, 0, sizeof(rsp));
    rsp[0] = SPDM_VERSION_12;
    rsp[1] = SPDM_ALGORITHMS;
    rsp[2] = 4;                  /* Param1 = AlgStructCount */
    /* BaseAsymSel = ECDSA_P384 (bit 7) at offset 12 */
    rsp[12] = SPDM_ASYM_ALGO_ECDSA_P384 & 0xFF;
    rsp[13] = (SPDM_ASYM_ALGO_ECDSA_P384 >> 8) & 0xFF;
    /* BaseHashSel = SHA_384 (bit 1) at offset 16 */
    rsp[16] = SPDM_HASH_ALGO_SHA_384;
    /* AlgStruct table starts at offset 36, each entry 4 bytes:
     *   AlgType(1) + AlgCount(1=0x20) + AlgSel(2 LE) */
    rsp[36] = 2; rsp[37] = 0x20; rsp[38] = 0x10; rsp[39] = 0x00;  /* DHE SECP_384_R1 */
    rsp[40] = 3; rsp[41] = 0x20; rsp[42] = 0x02; rsp[43] = 0x00;  /* AEAD AES_256_GCM */
    rsp[44] = 4; rsp[45] = 0x20; rsp[46] = 0x0F; rsp[47] = 0x00;  /* ReqBaseAsym */
    rsp[48] = 5; rsp[49] = 0x20; rsp[50] = 0x01; rsp[51] = 0x00;  /* KeySchedule SPDM */

    ASSERT_SUCCESS(wolfSPDM_ParseAlgorithms(ctx, rsp, 52));

    /* Tamper AEAD selection to AES_128_GCM (bit 0) - must be rejected. */
    rsp[42] = 0x01;
    ASSERT_EQ(wolfSPDM_ParseAlgorithms(ctx, rsp, 52),
        WOLFSPDM_E_ALGO_MISMATCH, "Non-AES-256-GCM AEAD must fail Set-B");
    rsp[42] = 0x02;

    /* Tamper DHE to SECP_256_R1 (bit 3) - must be rejected. */
    rsp[38] = 0x08;
    ASSERT_EQ(wolfSPDM_ParseAlgorithms(ctx, rsp, 52),
        WOLFSPDM_E_ALGO_MISMATCH, "Non-SECP_384_R1 DHE must fail Set-B");
    rsp[38] = 0x10;

    /* Tamper KeySchedule to 0 - must be rejected. */
    rsp[50] = 0x00;
    ASSERT_EQ(wolfSPDM_ParseAlgorithms(ctx, rsp, 52),
        WOLFSPDM_E_ALGO_MISMATCH, "Non-SPDM KeySchedule must fail Set-B");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_build_get_digests(void)
{
    byte buf[16];
    word32 bufSz = sizeof(buf);
    TEST_CTX_SETUP_V12();

    printf("test_build_get_digests...\n");
    ASSERT_SUCCESS(wolfSPDM_BuildGetDigests(ctx, buf, &bufSz));
    ASSERT_EQ(bufSz, 4, "GET_DIGESTS should be 4 bytes");
    ASSERT_EQ(buf[1], SPDM_GET_DIGESTS, "Code should be 0x81");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_build_get_certificate(void)
{
    byte buf[16];
    word32 bufSz = sizeof(buf);
    TEST_CTX_SETUP_V12();

    printf("test_build_get_certificate...\n");
    ASSERT_SUCCESS(wolfSPDM_BuildGetCertificate(ctx, buf, &bufSz, 0, 0, 1024));
    ASSERT_EQ(bufSz, 8, "GET_CERTIFICATE should be 8 bytes");
    ASSERT_EQ(buf[1], SPDM_GET_CERTIFICATE, "Code should be 0x82");
    ASSERT_EQ(buf[2], 0x00, "SlotID should be 0");
    TEST_ASSERT(buf[6] == 0x00 && buf[7] == 0x04, "Length should be 1024");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_build_end_session(void)
{
    byte buf[16];
    word32 bufSz = sizeof(buf);
    TEST_CTX_SETUP_V12();

    printf("test_build_end_session...\n");
    ASSERT_SUCCESS(wolfSPDM_BuildEndSession(ctx, buf, &bufSz));
    ASSERT_EQ(bufSz, 4, "END_SESSION should be 4 bytes");
    ASSERT_EQ(buf[1], SPDM_END_SESSION, "Code should be 0xEA");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_parse_finish_rsp_14_opaque_length(void)
{
    /* SPDM 1.4 FINISH_RSP: header(4) + OpaqueLength(2 LE) + OpaqueData(var).
     * Exercise both the happy path (correctly consuming the variable-length
     * tail into the transcript) and the size-guard (truncated buffer must
     * return BUFFER_SMALL). */
    byte rsp[64];
    word32 startTranscriptLen;
    TEST_CTX_SETUP();

    printf("test_parse_finish_rsp_14_opaque_length...\n");

    ctx->spdmVersion = SPDM_VERSION_14;

    /* Empty OpaqueData (opaqueLen=0): rspMsgLen=6, fits in 4-byte header
     * tail. The transcript should advance by 6 bytes. */
    XMEMSET(rsp, 0, sizeof(rsp));
    rsp[0] = SPDM_VERSION_14;
    rsp[1] = SPDM_FINISH_RSP;
    /* OpaqueLength = 0 at offset 4..5 (already zeroed). */
    startTranscriptLen = ctx->transcriptLen;
    ASSERT_SUCCESS(wolfSPDM_ParseFinishRsp(ctx, rsp, 6));
    ASSERT_EQ(ctx->transcriptLen - startTranscriptLen, (word32)6,
        "Transcript should grow by 6 (hdr+OpaqueLen) for empty opaque");

    /* Non-zero OpaqueData (5 bytes) - rspMsgLen = 4+2+5 = 11. */
    ctx->transcriptLen = 0;
    rsp[4] = 0x05; rsp[5] = 0x00;
    rsp[6] = 'h'; rsp[7] = 'e'; rsp[8] = 'l'; rsp[9] = 'l'; rsp[10] = 'o';
    ctx->state = WOLFSPDM_STATE_FINISH; /* reset for re-parse */
    ASSERT_SUCCESS(wolfSPDM_ParseFinishRsp(ctx, rsp, 11));
    ASSERT_EQ(ctx->transcriptLen, (word32)11,
        "Transcript should grow by hdr+OpaqueLen+OpaqueData = 11");

    /* Truncated: 5 bytes (header + 1 byte of OpaqueLength) must fail. */
    ASSERT_EQ(wolfSPDM_ParseFinishRsp(ctx, rsp, 5), WOLFSPDM_E_BUFFER_SMALL,
        "1.4 FINISH_RSP with truncated OpaqueLength must fail");

    /* Truncated: 9 bytes (claimed opaqueLen=5 but only 3 bytes follow). */
    ASSERT_EQ(wolfSPDM_ParseFinishRsp(ctx, rsp, 9), WOLFSPDM_E_BUFFER_SMALL,
        "1.4 FINISH_RSP with truncated OpaqueData must fail");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_build_finish_opaque_length_14(void)
{
    /* SPDM 1.4 adds OpaqueLength(2) to FINISH at offset 4. Verify both the
     * grown size requirement and that the field is actually written. */
    byte buf[128];
    word32 bufSz;
    int i;
    TEST_CTX_SETUP_V12();

    printf("test_build_finish_opaque_length_14...\n");

    /* Populate reqFinishedKey so the HMAC step doesn't fault. The HMAC
     * value itself isn't validated here - we're checking the header. */
    for (i = 0; i < WOLFSPDM_HASH_SIZE; i++) {
        ctx->reqFinishedKey[i] = (byte)i;
    }

    /* 1.4: header(4) + OpaqueLen(2) = 0x0000 + HMAC(48) = 54 bytes. */
    ctx->spdmVersion = SPDM_VERSION_14;
    bufSz = sizeof(buf);
    ASSERT_SUCCESS(wolfSPDM_BuildFinish(ctx, buf, &bufSz));
    ASSERT_EQ(bufSz, 54, "1.4 FINISH should be 54 bytes");
    ASSERT_EQ(buf[1], SPDM_FINISH, "Code should be SPDM_FINISH");
    ASSERT_EQ(buf[4], 0x00, "OpaqueLength byte 0 should be 0");
    ASSERT_EQ(buf[5], 0x00, "OpaqueLength byte 1 should be 0");

    /* 1.4 size guard: 53 bytes must be refused. */
    {
        byte tinyBuf[53];
        word32 tinySz = sizeof(tinyBuf);
        ASSERT_EQ(wolfSPDM_BuildFinish(ctx, tinyBuf, &tinySz),
            WOLFSPDM_E_BUFFER_SMALL,
            "1.4 FINISH should refuse 53 bytes (needs 54)");
    }

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_build_key_exchange_opaque_data(void)
{
    /* OpaqueData carries the SecuredMessage version negotiation. DSP0277
     * only defines versions 1.0, 1.1, 1.2, so the block is the same length
     * regardless of the negotiated SPDM control version. */
    byte buf[256];
    word32 bufSz;
    word16 opaqueLen;
    word32 opaqueOffset = 4 + 2 + 1 + 1 + 32 + 96; /* hdr + ResSI + pol + res + RND + ExchData */
    TEST_CTX_SETUP_V12();

    printf("test_build_key_exchange_opaque_data...\n");

    bufSz = sizeof(buf);
    ASSERT_SUCCESS(wolfSPDM_BuildKeyExchange(ctx, buf, &bufSz));
    opaqueLen = (word16)(buf[opaqueOffset] | ((word16)buf[opaqueOffset + 1] << 8));
    ASSERT_EQ(opaqueLen, 20, "OpaqueLength should be 20 bytes");
    /* SecuredMessageVersions block at offset+12: 0x10 0x00 0x11 0x00 0x12 0x00 */
    ASSERT_EQ(buf[opaqueOffset + 14], 0x10, "Version[0] should be 0x10 (1.0)");
    ASSERT_EQ(buf[opaqueOffset + 16], 0x11, "Version[1] should be 0x11 (1.1)");
    ASSERT_EQ(buf[opaqueOffset + 18], 0x12, "Version[2] should be 0x12 (1.2)");

    /* SPDM 1.4 reuses the same 1.2 secured-message format. */
    ctx->spdmVersion = SPDM_VERSION_14;
    bufSz = sizeof(buf);
    ASSERT_SUCCESS(wolfSPDM_BuildKeyExchange(ctx, buf, &bufSz));
    opaqueLen = (word16)(buf[opaqueOffset] | ((word16)buf[opaqueOffset + 1] << 8));
    ASSERT_EQ(opaqueLen, 20, "1.4 OpaqueLength should still be 20");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_key_exchange_requires_cert(void)
{
    /* wolfSPDM_KeyExchange must refuse to proceed without an extracted
     * responder public key (signature verification would otherwise be
     * skipped, regressing MITM resistance to HMAC-only). */
    TEST_CTX_SETUP_V12();

    printf("test_key_exchange_requires_cert...\n");

    /* hasResponderPubKey is 0 by default; KeyExchange must reject. */
    ASSERT_EQ(wolfSPDM_KeyExchange(ctx), WOLFSPDM_E_BAD_STATE,
        "KeyExchange without cert must return BAD_STATE");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_parse_key_exchange_rsp_mutual_auth_refused(void)
{
    /* Responder sets MutAuthRequested (offset 6) - the parser must refuse
     * before committing ctx->sessionId so a rejected handshake doesn't
     * leak partial state. */
    byte rsp[240];  /* full KEY_EXCHANGE_RSP minimum + sig + hmac */
    TEST_CTX_SETUP_V12();

    printf("test_parse_key_exchange_rsp_mutual_auth_refused...\n");

    XMEMSET(rsp, 0, sizeof(rsp));
    rsp[0] = SPDM_VERSION_12;
    rsp[1] = SPDM_KEY_EXCHANGE_RSP;
    rsp[6] = 0x01;  /* MutAuthRequested - we don't support it */
    ASSERT_EQ(wc_ecc_init(&ctx->responderPubKey), 0, "ecc_init");
    ctx->flags.hasResponderPubKey = 1;
    ctx->sessionId = 0;
    ASSERT_EQ(wolfSPDM_ParseKeyExchangeRsp(ctx, rsp, sizeof(rsp)),
        WOLFSPDM_E_KEY_EXCHANGE, "MutAuthRequested must be refused");
    ASSERT_EQ(ctx->sessionId, (word32)0,
        "sessionId must not be committed on mutual-auth refusal");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_parse_key_exchange_rsp_too_short(void)
{
    /* Verify ParseKeyExchangeRsp's size guard runs before the signature
     * verification path. A truncated response (no room for the 96-byte
     * signature) must be rejected up front rather than reaching the
     * verifier with garbage bytes. The actual signature-verify failure
     * path is exercised end-to-end by the integration tests against
     * spdm-emu (a bad signature there returns WOLFSPDM_E_BAD_SIGNATURE). */
    byte rsp[140];  /* below the sigOffset(138) + sig(96) minimum */
    int rc;
    TEST_CTX_SETUP_V12();

    printf("test_parse_key_exchange_rsp_too_short...\n");

    XMEMSET(rsp, 0, sizeof(rsp));
    rsp[0] = SPDM_VERSION_12;
    rsp[1] = SPDM_KEY_EXCHANGE_RSP;
    /* Properly init the ecc_key the flag references; wolfSPDM_Free's
     * wc_ecc_free should run against a wolfCrypt-initialized state, not
     * a zeroed-but-never-initialized struct. */
    ASSERT_EQ(wc_ecc_init(&ctx->responderPubKey), 0, "ecc_init");
    ctx->flags.hasResponderPubKey = 1;
    rc = wolfSPDM_ParseKeyExchangeRsp(ctx, rsp, sizeof(rsp));
    ASSERT_NE(rc, WOLFSPDM_SUCCESS,
        "Truncated KEY_EXCHANGE_RSP must not succeed");

    TEST_CTX_FREE();
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
    byte buf[64];
    byte zeros[32];
    word32 bufSz;
    TEST_CTX_SETUP_V12();

    printf("test_build_get_measurements...\n");

    /* Build without signature */
    bufSz = sizeof(buf);
    ASSERT_SUCCESS(wolfSPDM_BuildGetMeasurements(ctx, buf, &bufSz, SPDM_MEAS_OPERATION_ALL, 0));
    ASSERT_EQ(bufSz, 4, "Without sig should be 4 bytes");
    ASSERT_EQ(buf[1], SPDM_GET_MEASUREMENTS, "Code should be 0xE0");
    ASSERT_EQ(buf[2], 0x00, "Param1 should be 0 (no sig)");

    /* Build with signature */
    bufSz = sizeof(buf);
    ASSERT_SUCCESS(wolfSPDM_BuildGetMeasurements(ctx, buf, &bufSz, SPDM_MEAS_OPERATION_ALL, 1));
    ASSERT_EQ(bufSz, 37, "With sig should be 37 bytes");
    ASSERT_EQ(buf[2], SPDM_MEAS_REQUEST_SIG_BIT, "Sig bit should be set");
    XMEMSET(zeros, 0, sizeof(zeros));
    ASSERT_NE(memcmp(&buf[4], zeros, 32), 0, "Nonce should be non-zero");
    ASSERT_EQ(memcmp(ctx->measNonce, &buf[4], 32), 0, "Nonce should match context");

    /* DSP0274 v1.3.0 Table 50 / v1.4.0 Table 49: RequesterContext is
     * appended for 1.3+ regardless of whether signature was requested. */
    ctx->spdmVersion = SPDM_VERSION_13;
    bufSz = sizeof(buf);
    ASSERT_SUCCESS(wolfSPDM_BuildGetMeasurements(ctx, buf, &bufSz, SPDM_MEAS_OPERATION_ALL, 0));
    ASSERT_EQ(bufSz, 12, "1.3 unsigned should be 4 + 8 = 12 bytes");

    bufSz = sizeof(buf);
    ASSERT_SUCCESS(wolfSPDM_BuildGetMeasurements(ctx, buf, &bufSz, SPDM_MEAS_OPERATION_ALL, 1));
    ASSERT_EQ(bufSz, 45, "1.3 signed should be 4 + 32 + 1 + 8 = 45 bytes");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_measurement_accessors(void)
{
    byte measIdx, measType;
    byte value[64];
    word32 valueSz;
    TEST_CTX_SETUP();

    printf("test_measurement_accessors...\n");
    ASSERT_EQ(wolfSPDM_GetMeasurementCount(ctx), 0, "Count should be 0 before measurements");

    /* Manually populate 2 test blocks */
    ctx->flags.hasMeasurements = 1;
    ctx->measBlockCount = 2;
    ctx->measBlocks[0].index = 1;
    ctx->measBlocks[0].dmtfType = SPDM_MEAS_VALUE_TYPE_IMMUTABLE_ROM;
    ctx->measBlocks[0].valueSize = 4;
    ctx->measBlocks[0].value[0] = 0xAA; ctx->measBlocks[0].value[1] = 0xBB;
    ctx->measBlocks[0].value[2] = 0xCC; ctx->measBlocks[0].value[3] = 0xDD;
    ctx->measBlocks[1].index = 2;
    ctx->measBlocks[1].dmtfType = SPDM_MEAS_VALUE_TYPE_MUTABLE_FW;
    ctx->measBlocks[1].valueSize = 2;
    ctx->measBlocks[1].value[0] = 0x11; ctx->measBlocks[1].value[1] = 0x22;

    ASSERT_EQ(wolfSPDM_GetMeasurementCount(ctx), 2, "Count should be 2");

    /* Get block 0 */
    valueSz = sizeof(value);
    ASSERT_SUCCESS(wolfSPDM_GetMeasurementBlock(ctx, 0, &measIdx, &measType, value, &valueSz));
    ASSERT_EQ(measIdx, 1, "Block 0 index should be 1");
    ASSERT_EQ(measType, SPDM_MEAS_VALUE_TYPE_IMMUTABLE_ROM, "Block 0 type wrong");
    ASSERT_EQ(valueSz, 4, "Block 0 size wrong");
    ASSERT_EQ(value[0], 0xAA, "Block 0 value wrong");

    /* Get block 1 */
    valueSz = sizeof(value);
    ASSERT_SUCCESS(wolfSPDM_GetMeasurementBlock(ctx, 1, &measIdx, &measType, value, &valueSz));
    ASSERT_EQ(measIdx, 2, "Block 1 index should be 2");

    /* Out of range */
    valueSz = sizeof(value);
    ASSERT_FAIL(wolfSPDM_GetMeasurementBlock(ctx, 2, &measIdx, &measType, value, &valueSz));
    ASSERT_FAIL(wolfSPDM_GetMeasurementBlock(ctx, -1, &measIdx, &measType, value, &valueSz));

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_parse_measurements(void)
{
    TEST_CTX_SETUP();
    /* Fake MEASUREMENTS response: 2 blocks, recordLen=20 */
    byte rsp[] = {
        0x12, 0x60, 0x00, 0x00,   /* header */
        0x02,                       /* numBlocks */
        0x14, 0x00, 0x00,           /* recordLen = 20 LE */
        /* Block 1: Index=1, Spec=1, Size=7, DMTF Type=0x00, ValSize=4 */
        0x01, 0x01, 0x07, 0x00, 0x00, 0x04, 0x00, 0xAA, 0xBB, 0xCC, 0xDD,
        /* Block 2: Index=2, Spec=1, Size=5, DMTF Type=0x01, ValSize=2 */
        0x02, 0x01, 0x05, 0x00, 0x01, 0x02, 0x00, 0x11, 0x22
    };

    printf("test_parse_measurements...\n");

    ASSERT_SUCCESS(wolfSPDM_ParseMeasurements(ctx, rsp, sizeof(rsp)));
    ASSERT_EQ(ctx->measBlockCount, 2, "Should have 2 blocks");
    ASSERT_EQ(ctx->flags.hasMeasurements, 1, "hasMeasurements should be set");
    ASSERT_EQ(ctx->measBlocks[0].index, 1, "Block 0 index wrong");
    ASSERT_EQ(ctx->measBlocks[0].dmtfType, 0x00, "Block 0 type wrong");
    ASSERT_EQ(ctx->measBlocks[0].valueSize, 4, "Block 0 valueSize wrong");
    ASSERT_EQ(ctx->measBlocks[0].value[0], 0xAA, "Block 0 value[0] wrong");
    ASSERT_EQ(ctx->measBlocks[1].index, 2, "Block 1 index wrong");
    ASSERT_EQ(ctx->measBlocks[1].valueSize, 2, "Block 1 valueSize wrong");

    /* Test truncated buffer */
    ASSERT_FAIL(wolfSPDM_ParseMeasurements(ctx, rsp, 5));

    TEST_CTX_FREE();
    TEST_PASS();
}

#ifndef NO_WOLFSPDM_MEAS_VERIFY

static int test_measurement_sig_verification(void)
{
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
    TEST_CTX_SETUP_V12();

    printf("test_measurement_sig_verification...\n");

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
    ctx->flags.hasResponderPubKey = 1;

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
    TEST_CTX_FREE();
    TEST_PASS();
}

#endif /* !NO_WOLFSPDM_MEAS_VERIFY */
#endif /* !NO_WOLFSPDM_MEAS */

/* ========================================================================== */
/* Certificate Chain Validation Tests */
/* ========================================================================== */

static int test_set_trusted_cas(void)
{
    byte fakeCa[] = {0x30, 0x82, 0x01, 0x00, 0xAA, 0xBB, 0xCC, 0xDD};
    TEST_CTX_SETUP();

    printf("test_set_trusted_cas...\n");
    ASSERT_FAIL(wolfSPDM_SetTrustedCAs(NULL, fakeCa, sizeof(fakeCa)));
    ASSERT_FAIL(wolfSPDM_SetTrustedCAs(ctx, NULL, sizeof(fakeCa)));
    ASSERT_FAIL(wolfSPDM_SetTrustedCAs(ctx, fakeCa, 0));
    ASSERT_SUCCESS(wolfSPDM_SetTrustedCAs(ctx, fakeCa, sizeof(fakeCa)));
    ASSERT_EQ(ctx->flags.hasTrustedCAs, 1, "hasTrustedCAs not set");
    ASSERT_EQ(ctx->trustedCAsSz, sizeof(fakeCa), "Size mismatch");
    ASSERT_EQ(memcmp(ctx->trustedCAs, fakeCa, sizeof(fakeCa)), 0, "Data mismatch");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_validate_cert_chain_no_cas(void)
{
    TEST_CTX_SETUP();

    printf("test_validate_cert_chain_no_cas...\n");

    ASSERT_EQ(wolfSPDM_ValidateCertChain(ctx), WOLFSPDM_E_CERT_PARSE, "Should fail without trusted CAs");

    TEST_CTX_FREE();
    TEST_PASS();
}

/* ========================================================================== */
/* Challenge Tests */
/* ========================================================================== */

#ifndef NO_WOLFSPDM_CHALLENGE

static int test_build_challenge(void)
{
    byte buf[64];
    byte zeros[32];
    word32 bufSz;
    TEST_CTX_SETUP_V12();

    printf("test_build_challenge...\n");

    bufSz = sizeof(buf);
    ASSERT_SUCCESS(wolfSPDM_BuildChallenge(ctx, buf, &bufSz, 0, SPDM_MEAS_SUMMARY_HASH_NONE));
    ASSERT_EQ(bufSz, 36, "CHALLENGE should be 36 bytes");
    ASSERT_EQ(buf[1], SPDM_CHALLENGE, "Code should be 0x83");
    ASSERT_EQ(buf[3], SPDM_MEAS_SUMMARY_HASH_NONE, "MeasHashType wrong");
    XMEMSET(zeros, 0, sizeof(zeros));
    ASSERT_NE(memcmp(&buf[4], zeros, 32), 0, "Nonce should be non-zero");
    ASSERT_EQ(memcmp(ctx->challengeNonce, &buf[4], 32), 0, "Nonce should match context");

    /* Test with different slot and meas hash type */
    bufSz = sizeof(buf);
    ASSERT_SUCCESS(wolfSPDM_BuildChallenge(ctx, buf, &bufSz, 3, SPDM_MEAS_SUMMARY_HASH_ALL));
    ASSERT_EQ(buf[2], 0x03, "SlotID should be 3");

    /* SPDM 1.3+ adds an 8-byte RequesterContext at the end. */
    ctx->spdmVersion = SPDM_VERSION_13;
    bufSz = sizeof(buf);
    ASSERT_SUCCESS(wolfSPDM_BuildChallenge(ctx, buf, &bufSz, 0, SPDM_MEAS_SUMMARY_HASH_NONE));
    ASSERT_EQ(bufSz, 44, "1.3 CHALLENGE should be 36 + 8 = 44 bytes");
    ASSERT_EQ(memcmp(ctx->challengeReqCtx, &buf[36], 8), 0,
        "ReqCtx should follow nonce");

    /* Buffer too small */
    ctx->spdmVersion = SPDM_VERSION_12;
    bufSz = 10;
    ASSERT_EQ(wolfSPDM_BuildChallenge(ctx, buf, &bufSz, 0, SPDM_MEAS_SUMMARY_HASH_NONE),
        WOLFSPDM_E_BUFFER_SMALL, "Should fail on small buffer");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_parse_challenge_auth(void)
{
    /* Fake CHALLENGE_AUTH: hdr(4) + CertHash(48) + Nonce(32) + OpaqueLen(2) + Sig(96) = 182 */
    byte rsp[182];
    word32 sigOffset = 0;
    TEST_CTX_SETUP_V12();

    printf("test_parse_challenge_auth...\n");

    ctx->challengeMeasHashType = SPDM_MEAS_SUMMARY_HASH_NONE;

    XMEMSET(rsp, 0, sizeof(rsp));
    rsp[0] = SPDM_VERSION_12;
    rsp[1] = SPDM_CHALLENGE_AUTH;
    XMEMSET(&rsp[4], 0xAA, WOLFSPDM_HASH_SIZE);
    XMEMCPY(ctx->certChainHash, &rsp[4], WOLFSPDM_HASH_SIZE);
    XMEMSET(&rsp[52], 0xBB, 32);
    XMEMSET(&rsp[86], 0xCC, WOLFSPDM_ECC_SIG_SIZE);

    ASSERT_SUCCESS(wolfSPDM_ParseChallengeAuth(ctx, rsp, sizeof(rsp), &sigOffset));
    ASSERT_EQ(sigOffset, 86, "Signature offset should be 86");

    /* Wrong response code */
    rsp[1] = 0xFF;
    ASSERT_EQ(wolfSPDM_ParseChallengeAuth(ctx, rsp, sizeof(rsp), &sigOffset),
        WOLFSPDM_E_CHALLENGE, "Wrong code should fail");
    rsp[1] = SPDM_CHALLENGE_AUTH;

    /* CertChainHash mismatch */
    ctx->certChainHash[0] = 0x00;
    ASSERT_EQ(wolfSPDM_ParseChallengeAuth(ctx, rsp, sizeof(rsp), &sigOffset),
        WOLFSPDM_E_CHALLENGE, "Hash mismatch should fail");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_parse_challenge_auth_reqctx_echo(void)
{
    /* SPDM 1.3+: CHALLENGE_AUTH carries an 8-byte echo of the
     * RequesterContext from the request. wolfSPDM_ParseChallengeAuth
     * must compare it against ctx->challengeReqCtx and reject mismatches. */
    byte rsp[190]; /* 1.3 layout: hdr(4) + cert(48) + nonce(32) + opaqueLen(2) + reqCtx(8) + sig(96) */
    word32 sigOffset = 0;
    int i;
    TEST_CTX_SETUP();

    printf("test_parse_challenge_auth_reqctx_echo...\n");

    ctx->spdmVersion = SPDM_VERSION_13;
    ctx->challengeMeasHashType = SPDM_MEAS_SUMMARY_HASH_NONE;

    XMEMSET(rsp, 0, sizeof(rsp));
    rsp[0] = SPDM_VERSION_13;
    rsp[1] = SPDM_CHALLENGE_AUTH;
    XMEMSET(&rsp[4], 0xAA, WOLFSPDM_HASH_SIZE);  /* CertHash */
    XMEMCPY(ctx->certChainHash, &rsp[4], WOLFSPDM_HASH_SIZE);
    XMEMSET(&rsp[52], 0xBB, 32);                 /* Nonce */
    /* OpaqueLen at offset 84..85 = 0 (already memset) */
    /* RequesterContext echo at offset 86..93 */
    for (i = 0; i < 8; i++) {
        rsp[86 + i] = (byte)(0xE0 + i);
        ctx->challengeReqCtx[i] = (byte)(0xE0 + i);
    }
    /* Signature at offset 94..189 */
    XMEMSET(&rsp[94], 0xCC, WOLFSPDM_ECC_SIG_SIZE);

    ASSERT_SUCCESS(
        wolfSPDM_ParseChallengeAuth(ctx, rsp, sizeof(rsp), &sigOffset));
    ASSERT_EQ(sigOffset, 94, "Signature offset should be 94 (1.3+)");

    /* Flip a single echo byte; parser must reject. */
    rsp[86] ^= 0x01;
    ASSERT_EQ(
        wolfSPDM_ParseChallengeAuth(ctx, rsp, sizeof(rsp), &sigOffset),
        WOLFSPDM_E_CHALLENGE, "Tampered ReqCtx echo must be refused");

    TEST_CTX_FREE();
    TEST_PASS();
}

#endif /* !NO_WOLFSPDM_CHALLENGE */

/* ========================================================================== */
/* Heartbeat Tests */
/* ========================================================================== */

static int test_build_heartbeat(void)
{
    byte buf[16];
    word32 bufSz;
    TEST_CTX_SETUP_V12();

    printf("test_build_heartbeat...\n");
    bufSz = sizeof(buf);
    ASSERT_SUCCESS(wolfSPDM_BuildHeartbeat(ctx, buf, &bufSz));
    ASSERT_EQ(bufSz, 4, "HEARTBEAT should be 4 bytes");
    ASSERT_EQ(buf[1], SPDM_HEARTBEAT, "Code should be 0xE8");

    bufSz = 2;
    ASSERT_EQ(wolfSPDM_BuildHeartbeat(ctx, buf, &bufSz), WOLFSPDM_E_BUFFER_SMALL, "Should fail on small buffer");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_parse_heartbeat_ack(void)
{
    byte ack[] = {0x12, SPDM_HEARTBEAT_ACK, 0x00, 0x00};
    byte err[] = {0x12, SPDM_ERROR, 0x01, 0x00};
    TEST_CTX_SETUP();

    printf("test_parse_heartbeat_ack...\n");
    ASSERT_SUCCESS(wolfSPDM_ParseHeartbeatAck(ctx, ack, sizeof(ack)));
    ASSERT_EQ(wolfSPDM_ParseHeartbeatAck(ctx, err, sizeof(err)), WOLFSPDM_E_PEER_ERROR, "Error should return PEER_ERROR");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_heartbeat_state_check(void)
{
    TEST_CTX_SETUP();

    printf("test_heartbeat_state_check...\n");
    ASSERT_EQ(wolfSPDM_Heartbeat(ctx), WOLFSPDM_E_NOT_CONNECTED, "Heartbeat should fail when not connected");

    TEST_CTX_FREE();
    TEST_PASS();
}

/* ========================================================================== */
/* Key Update Tests */
/* ========================================================================== */

static int test_build_key_update(void)
{
    byte buf[16];
    word32 bufSz;
    byte tag = 0;
    TEST_CTX_SETUP_V12();

    printf("test_build_key_update...\n");
    bufSz = sizeof(buf);
    ASSERT_SUCCESS(wolfSPDM_BuildKeyUpdate(ctx, buf, &bufSz, SPDM_KEY_UPDATE_OP_UPDATE_ALL_KEYS, &tag));
    ASSERT_EQ(bufSz, 4, "KEY_UPDATE should be 4 bytes");
    ASSERT_EQ(buf[1], SPDM_KEY_UPDATE, "Code should be 0xE9");
    ASSERT_EQ(buf[2], SPDM_KEY_UPDATE_OP_UPDATE_ALL_KEYS, "Operation should be UpdateAllKeys");
    ASSERT_EQ(buf[3], tag, "Tag should match returned value");

    bufSz = 2;
    ASSERT_EQ(wolfSPDM_BuildKeyUpdate(ctx, buf, &bufSz, SPDM_KEY_UPDATE_OP_UPDATE_KEY, &tag),
        WOLFSPDM_E_BUFFER_SMALL, "Should fail on small buffer");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_parse_key_update_ack(void)
{
    byte ack[] = {0x12, SPDM_KEY_UPDATE_ACK, 0x02, 0x42};
    TEST_CTX_SETUP();

    printf("test_parse_key_update_ack...\n");
    ASSERT_SUCCESS(wolfSPDM_ParseKeyUpdateAck(ctx, ack, sizeof(ack), SPDM_KEY_UPDATE_OP_UPDATE_ALL_KEYS, 0x42));
    ASSERT_EQ(wolfSPDM_ParseKeyUpdateAck(ctx, ack, sizeof(ack), SPDM_KEY_UPDATE_OP_UPDATE_ALL_KEYS, 0xFF),
        WOLFSPDM_E_KEY_UPDATE, "Mismatched tag should fail");
    ASSERT_EQ(wolfSPDM_ParseKeyUpdateAck(ctx, ack, sizeof(ack), SPDM_KEY_UPDATE_OP_UPDATE_KEY, 0x42),
        WOLFSPDM_E_KEY_UPDATE, "Mismatched op should fail");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_derive_updated_keys(void)
{
    byte origReqKey[WOLFSPDM_AEAD_KEY_SIZE];
    byte origRspKey[WOLFSPDM_AEAD_KEY_SIZE];
    TEST_CTX_SETUP_V12();

    printf("test_derive_updated_keys...\n");
    XMEMSET(ctx->reqAppSecret, 0x5A, WOLFSPDM_HASH_SIZE);
    XMEMSET(ctx->rspAppSecret, 0xA5, WOLFSPDM_HASH_SIZE);
    XMEMSET(ctx->reqDataKey, 0x11, WOLFSPDM_AEAD_KEY_SIZE);
    XMEMSET(ctx->rspDataKey, 0x22, WOLFSPDM_AEAD_KEY_SIZE);
    XMEMCPY(origReqKey, ctx->reqDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    XMEMCPY(origRspKey, ctx->rspDataKey, WOLFSPDM_AEAD_KEY_SIZE);

    /* Update all keys */
    ASSERT_SUCCESS(wolfSPDM_DeriveUpdatedKeys(ctx, 1));
    ASSERT_NE(memcmp(ctx->reqDataKey, origReqKey, WOLFSPDM_AEAD_KEY_SIZE), 0, "Req key should change");
    ASSERT_NE(memcmp(ctx->rspDataKey, origRspKey, WOLFSPDM_AEAD_KEY_SIZE), 0, "Rsp key should change");

    /* Update requester only */
    XMEMCPY(origReqKey, ctx->reqDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    XMEMCPY(origRspKey, ctx->rspDataKey, WOLFSPDM_AEAD_KEY_SIZE);
    ASSERT_SUCCESS(wolfSPDM_DeriveUpdatedKeys(ctx, 0));
    ASSERT_NE(memcmp(ctx->reqDataKey, origReqKey, WOLFSPDM_AEAD_KEY_SIZE), 0, "Req key should change");
    ASSERT_EQ(memcmp(ctx->rspDataKey, origRspKey, WOLFSPDM_AEAD_KEY_SIZE), 0, "Rsp key should NOT change");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_key_update_state_check(void)
{
    TEST_CTX_SETUP();

    printf("test_key_update_state_check...\n");
    ASSERT_EQ(wolfSPDM_KeyUpdate(ctx, 1), WOLFSPDM_E_NOT_CONNECTED, "KeyUpdate should fail when not connected");

    TEST_CTX_FREE();
    TEST_PASS();
}

/* ========================================================================== */
/* Multi-Version Tests */
/* ========================================================================== */

static int test_kdf_version_prefix(void)
{
    byte secret[48];
    byte context[48];
    byte out12[32], out13[32], out14[32];

    printf("test_kdf_version_prefix...\n");

    memset(secret, 0x5A, sizeof(secret));
    memset(context, 0x00, sizeof(context));

    ASSERT_SUCCESS(wolfSPDM_HkdfExpandLabel(SPDM_VERSION_12, secret,
        sizeof(secret), SPDM_LABEL_KEY, context, sizeof(context),
        out12, sizeof(out12)));
    ASSERT_SUCCESS(wolfSPDM_HkdfExpandLabel(SPDM_VERSION_13, secret,
        sizeof(secret), SPDM_LABEL_KEY, context, sizeof(context),
        out13, sizeof(out13)));
    ASSERT_SUCCESS(wolfSPDM_HkdfExpandLabel(SPDM_VERSION_14, secret,
        sizeof(secret), SPDM_LABEL_KEY, context, sizeof(context),
        out14, sizeof(out14)));

    /* All three outputs should differ due to different BinConcat prefixes */
    ASSERT_NE(memcmp(out12, out13, sizeof(out12)), 0,
        "1.2 and 1.3 outputs should differ");
    ASSERT_NE(memcmp(out13, out14, sizeof(out13)), 0,
        "1.3 and 1.4 outputs should differ");
    ASSERT_NE(memcmp(out12, out14, sizeof(out12)), 0,
        "1.2 and 1.4 outputs should differ");

    TEST_PASS();
}

static int test_hmac_mismatch_negative(void)
{
    byte finishedKeyA[WOLFSPDM_HASH_SIZE];
    byte finishedKeyB[WOLFSPDM_HASH_SIZE];
    byte thHash[WOLFSPDM_HASH_SIZE];
    byte verifyA[WOLFSPDM_HASH_SIZE];
    byte verifyB[WOLFSPDM_HASH_SIZE];

    printf("test_hmac_mismatch_negative...\n");

    memset(finishedKeyA, 0xAB, sizeof(finishedKeyA));
    memset(finishedKeyB, 0xAC, sizeof(finishedKeyB));  /* Differs by 1 bit */
    memset(thHash, 0xCD, sizeof(thHash));

    ASSERT_SUCCESS(wolfSPDM_ComputeVerifyData(finishedKeyA, thHash, verifyA));
    ASSERT_SUCCESS(wolfSPDM_ComputeVerifyData(finishedKeyB, thHash, verifyB));

    /* Single-bit change in key must produce different verify data */
    ASSERT_NE(memcmp(verifyA, verifyB, WOLFSPDM_HASH_SIZE), 0,
        "Different keys should produce different verify data");

    TEST_PASS();
}

static int test_transcript_overflow(void)
{
    byte chunk[256];
    word32 i, needed;
    TEST_CTX_SETUP();

    printf("test_transcript_overflow...\n");

    memset(chunk, 0x42, sizeof(chunk));

    /* Fill transcript to capacity */
    needed = WOLFSPDM_MAX_TRANSCRIPT / sizeof(chunk);
    for (i = 0; i < needed; i++) {
        ASSERT_SUCCESS(wolfSPDM_TranscriptAdd(ctx, chunk, sizeof(chunk)));
    }
    ASSERT_EQ(ctx->transcriptLen, (word32)(needed * sizeof(chunk)),
        "Transcript should be full");

    /* Next add should fail with BUFFER_SMALL */
    ASSERT_EQ(wolfSPDM_TranscriptAdd(ctx, chunk, sizeof(chunk)),
        WOLFSPDM_E_BUFFER_SMALL, "Overflow should return BUFFER_SMALL");

    TEST_CTX_FREE();
    TEST_PASS();
}

#ifndef NO_WOLFSPDM_MEAS

/* Mock I/O callback that returns a fixed SPDM_ERROR response. */
static int error_io_cb(WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz, void* userCtx)
{
    (void)ctx; (void)txBuf; (void)txSz; (void)userCtx;
    if (*rxSz < 4) return -1;
    rxBuf[0] = SPDM_VERSION_12;
    rxBuf[1] = SPDM_ERROR;
    rxBuf[2] = SPDM_ERROR_INVALID_REQUEST;  /* param1 = error code */
    rxBuf[3] = 0x00;                         /* param2 */
    *rxSz = 4;
    return 0;
}

/* Captures the txBuf the wolfSPDM_SecuredExchange layer hands us, so a
 * test can prove the encrypt path ran (txBuf will start with the
 * sessionId, not an SPDM version byte). Returns "session terminated"
 * via a peer error so the caller doesn't try to parse a bogus response. */
typedef struct { byte first; int hit; } SECURED_PROBE;
static int secured_probe_io_cb(WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz, void* userCtx)
{
    SECURED_PROBE* p = (SECURED_PROBE*)userCtx;
    (void)ctx;
    if (p != NULL && txSz > 0 && txBuf != NULL) {
        p->first = txBuf[0];
        p->hit = 1;
    }
    /* Respond with a 4-byte SPDM_ERROR so the caller surfaces PEER_ERROR. */
    if (*rxSz < 4) return -1;
    rxBuf[0] = SPDM_VERSION_12;
    rxBuf[1] = SPDM_ERROR;
    rxBuf[2] = SPDM_ERROR_INVALID_REQUEST;
    rxBuf[3] = 0x00;
    *rxSz = 4;
    return 0;
}

static int test_get_measurements_uses_secured_when_measured(void)
{
    /* After the first GetMeasurements completes, ctx->state advances to
     * WOLFSPDM_STATE_MEASURED. The dispatch must keep using the encrypted
     * (SecuredExchange) path on subsequent calls rather than falling back
     * to cleartext. We assert this by capturing the first txBuf byte:
     *   - plain SPDM:  version byte (0x10-0x1F)
     *   - secured:     low byte of sessionId (we plant 0xAB) */
    SECURED_PROBE probe = { 0, 0 };
    int i;
    TEST_CTX_SETUP_V12();

    printf("test_get_measurements_uses_secured_when_measured...\n");

    ctx->state = WOLFSPDM_STATE_MEASURED;
    ctx->sessionId = 0xCAFEBAAB;  /* LSB = 0xAB, distinct from 0x10..0x1F */
    for (i = 0; i < WOLFSPDM_AEAD_KEY_SIZE; i++) {
        ctx->reqDataKey[i] = (byte)(i + 7);
        ctx->rspDataKey[i] = (byte)(i + 7);
    }
    for (i = 0; i < WOLFSPDM_AEAD_IV_SIZE; i++) {
        ctx->reqDataIv[i] = (byte)(0x60 + i);
        ctx->rspDataIv[i] = (byte)(0x60 + i);
    }
    ASSERT_SUCCESS(wolfSPDM_SetIO(ctx, secured_probe_io_cb, &probe));

    /* Drive GetMeasurements. The mocked I/O returns SPDM_ERROR, which is
     * fine - we only care that the secured path was taken. */
    (void)wolfSPDM_GetMeasurements(ctx, SPDM_MEAS_OPERATION_ALL, 0);
    ASSERT_EQ(probe.hit, 1, "I/O callback should have been invoked");
    ASSERT_EQ(probe.first, 0xAB,
        "STATE_MEASURED dispatch must use SecuredExchange (sessionId byte)");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_get_measurements_peer_error(void)
{
    TEST_CTX_SETUP_V12();

    printf("test_get_measurements_peer_error...\n");

    /* Drive GetMeasurements through a callback that returns SPDM_ERROR -
     * exercises the new wolfSPDM_CheckError branch before ParseMeasurements. */
    ctx->state = WOLFSPDM_STATE_ALGO;
    ASSERT_SUCCESS(wolfSPDM_SetIO(ctx, error_io_cb, NULL));

    ASSERT_EQ(
        wolfSPDM_GetMeasurements(ctx, SPDM_MEAS_OPERATION_ALL, 0),
        WOLFSPDM_E_PEER_ERROR,
        "SPDM_ERROR response should surface as PEER_ERROR");
    /* Side-effect: the responder's error code must be reachable via
     * the public accessor so callers can branch on BUSY vs UNSUPPORTED. */
    ASSERT_EQ(wolfSPDM_GetLastPeerError(ctx), SPDM_ERROR_INVALID_REQUEST,
        "Peer error code should be captured for retrieval");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_parse_measurements_13_requester_context(void)
{
    /* Exercise the SPDM 1.3+ branch in ParseMeasurements that requires
     * the 8-byte RequesterContext echo between OpaqueData and Signature.
     *
     * Layout for SIGNED 1.3+: hdr(4) + NumBlocks(1) + RecLen(3) + Record(N)
     *                        + Nonce(32) + OpaqueLen(2) + RequesterContext(8)
     *                        + Signature(96).
     * We use a 0-block record (8 hdr) so the parser jumps straight to the
     * post-record tail. */
    byte rsp[8 + 32 + 2 + 8 + WOLFSPDM_ECC_SIG_SIZE];
    byte rspShort[8 + 32 + 2 + 4]; /* truncated: ReqCtx missing */
    TEST_CTX_SETUP();

    printf("test_parse_measurements_13_requester_context...\n");

    ctx->spdmVersion = SPDM_VERSION_13;

    /* Valid response: 0 blocks, RecLen=0, Nonce(32), OpaqueLen=0, ReqCtx(8), Sig(96). */
    XMEMSET(rsp, 0, sizeof(rsp));
    rsp[0] = SPDM_VERSION_13;
    rsp[1] = SPDM_MEASUREMENTS;
    /* NumBlocks=0 at buf[4]; RecLen=0 at buf[5..7]; nothing else needs writing. */
    ASSERT_SUCCESS(wolfSPDM_ParseMeasurements(ctx, rsp, sizeof(rsp)));
    ASSERT_EQ(ctx->measSignatureSize, WOLFSPDM_ECC_SIG_SIZE,
        "Signature should be captured");

    /* Missing RequesterContext (only 4 bytes after OpaqueLen) - must fail. */
    XMEMSET(rspShort, 0, sizeof(rspShort));
    rspShort[0] = SPDM_VERSION_13;
    rspShort[1] = SPDM_MEASUREMENTS;
    ASSERT_EQ(wolfSPDM_ParseMeasurements(ctx, rspShort, sizeof(rspShort)),
        WOLFSPDM_E_MEASUREMENT,
        "1.3+ response missing RequesterContext must be refused");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_parse_measurements_negative(void)
{
    byte truncated[] = {0x12, 0x60, 0x00, 0x00, 0x01};
    byte wrongCode[] = {0x12, 0xFF, 0x00, 0x00, 0x01, 0x04, 0x00, 0x00};
    TEST_CTX_SETUP();

    printf("test_parse_measurements_negative...\n");

    /* Truncated buffer */
    ASSERT_FAIL(wolfSPDM_ParseMeasurements(ctx, truncated, sizeof(truncated)));

    /* Wrong response code */
    ASSERT_FAIL(wolfSPDM_ParseMeasurements(ctx, wrongCode, sizeof(wrongCode)));

    /* NULL inputs */
    ASSERT_FAIL(wolfSPDM_ParseMeasurements(NULL, truncated, sizeof(truncated)));
    ASSERT_FAIL(wolfSPDM_ParseMeasurements(ctx, NULL, sizeof(truncated)));

    /* Zero length */
    ASSERT_FAIL(wolfSPDM_ParseMeasurements(ctx, truncated, 0));

    TEST_CTX_FREE();
    TEST_PASS();
}
#endif /* !NO_WOLFSPDM_MEAS */

static int test_version_fallback(void)
{
    /* Fake VERSION response with versions 1.0, 1.1, 1.2, 1.3 */
    byte rsp[] = {
        0x10, SPDM_VERSION, 0x00, 0x00,    /* header */
        0x04, 0x00,                          /* entryCount = 4 */
        0x00, 0x10,                          /* 1.0 */
        0x00, 0x11,                          /* 1.1 */
        0x00, 0x12,                          /* 1.2 */
        0x00, 0x13                           /* 1.3 */
    };
    TEST_CTX_SETUP();

    printf("test_version_fallback...\n");

    /* With no maxVersion set, should select 1.3 (highest mutual) */
    ASSERT_SUCCESS(wolfSPDM_ParseVersion(ctx, rsp, sizeof(rsp)));
    ASSERT_EQ(ctx->spdmVersion, SPDM_VERSION_13,
        "Should select 1.3 as highest mutual");

    /* Reset state and set maxVersion to 1.2 */
    ctx->state = WOLFSPDM_STATE_INIT;
    ctx->spdmVersion = 0;
    ctx->maxVersion = SPDM_VERSION_12;
    ASSERT_SUCCESS(wolfSPDM_ParseVersion(ctx, rsp, sizeof(rsp)));
    ASSERT_EQ(ctx->spdmVersion, SPDM_VERSION_12,
        "Should fall back to 1.2 with maxVersion cap");

    /* A responder advertising 1.4 should be selected when we allow it. */
    {
        byte rsp14[] = {
            0x10, SPDM_VERSION, 0x00, 0x00,
            0x05, 0x00,
            0x00, 0x10,
            0x00, 0x11,
            0x00, 0x12,
            0x00, 0x13,
            0x00, 0x14
        };
        ctx->state = WOLFSPDM_STATE_INIT;
        ctx->spdmVersion = 0;
        ctx->maxVersion = 0;  /* compile-time default = 1.4 */
        ASSERT_SUCCESS(wolfSPDM_ParseVersion(ctx, rsp14, sizeof(rsp14)));
        ASSERT_EQ(ctx->spdmVersion, SPDM_VERSION_14,
            "Should select 1.4 when offered and allowed");
    }

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_set_max_version(void)
{
    TEST_CTX_SETUP();

    printf("test_set_max_version...\n");

    /* Valid versions */
    ASSERT_SUCCESS(wolfSPDM_SetMaxVersion(ctx, SPDM_VERSION_12));
    ASSERT_EQ(ctx->maxVersion, SPDM_VERSION_12, "maxVersion should be 0x12");
    ASSERT_SUCCESS(wolfSPDM_SetMaxVersion(ctx, SPDM_VERSION_14));
    ASSERT_EQ(ctx->maxVersion, SPDM_VERSION_14, "maxVersion should be 0x14");

    /* Reset to default */
    ASSERT_SUCCESS(wolfSPDM_SetMaxVersion(ctx, 0));
    ASSERT_EQ(ctx->maxVersion, 0, "maxVersion should be 0 (default)");

    /* Invalid: too low */
    ASSERT_FAIL(wolfSPDM_SetMaxVersion(ctx, 0x11));
    /* Invalid: too high */
    ASSERT_FAIL(wolfSPDM_SetMaxVersion(ctx, 0x15));
    /* NULL ctx */
    ASSERT_FAIL(wolfSPDM_SetMaxVersion(NULL, SPDM_VERSION_12));

    TEST_CTX_FREE();
    TEST_PASS();
}

/* ========================================================================== */
/* Sequence Number Wrap Tests */
/* ========================================================================== */

static int test_sequence_number_mismatch(void)
{
    /* DSP0277 Sec. 11 mandates strict monotonic sequence numbers on the
     * receive side. Plant a record whose wire seqNum doesn't match the
     * locally expected counter and confirm DecryptInternal refuses it. */
    byte plain[] = "hello-spdm";
    byte enc[256];
    byte dec[256];
    word32 encSz = sizeof(enc);
    word32 decSz = sizeof(dec);
    int i;
    TEST_CTX_SETUP_V12();

    printf("test_sequence_number_mismatch...\n");

    ctx->state = WOLFSPDM_STATE_CONNECTED;
    ctx->sessionId = 0xCAFEBABE;
    for (i = 0; i < WOLFSPDM_AEAD_KEY_SIZE; i++) {
        ctx->reqDataKey[i] = (byte)(i + 1);
        ctx->rspDataKey[i] = (byte)(i + 1);
    }
    for (i = 0; i < WOLFSPDM_AEAD_IV_SIZE; i++) {
        ctx->reqDataIv[i] = (byte)(0x40 + i);
        ctx->rspDataIv[i] = (byte)(0x40 + i);
    }

    /* Encrypt at req seq = 5 (wire seqNum encoded as 5). */
    ctx->reqSeqNum = 5;
    ASSERT_SUCCESS(wolfSPDM_EncryptInternal(ctx, plain, sizeof(plain),
        enc, &encSz));

    /* Decrypt-side expects seq = 7, not 5 - must reject. */
    ctx->rspSeqNum = 7;
    ASSERT_EQ(wolfSPDM_DecryptInternal(ctx, enc, encSz, dec, &decSz),
        WOLFSPDM_E_SEQUENCE, "seqNum mismatch must return SEQUENCE error");

    /* Sanity: when seq matches, decrypt succeeds. */
    ctx->rspSeqNum = 5;
    decSz = sizeof(dec);
    ASSERT_SUCCESS(wolfSPDM_DecryptInternal(ctx, enc, encSz, dec, &decSz));
    ASSERT_EQ(memcmp(dec, plain, sizeof(plain)), 0, "Decrypt payload mismatch");

    TEST_CTX_FREE();
    TEST_PASS();
}

static int test_sequence_number_wrap(void)
{
    byte plain[] = "hello-spdm";
    byte enc[256];
    word32 encSz = sizeof(enc);
    int i;
    TEST_CTX_SETUP_V12();

    printf("test_sequence_number_wrap...\n");

    /* Zero the encrypt buffer so a future change that reads before the
     * seq-check fails would be visible rather than reading stack garbage. */
    XMEMSET(enc, 0, sizeof(enc));

    /* Set up a fake session: loopback (req keys == rsp keys). */
    ctx->state = WOLFSPDM_STATE_CONNECTED;
    ctx->sessionId = 0xDEADBEEF;
    for (i = 0; i < WOLFSPDM_AEAD_KEY_SIZE; i++) {
        ctx->reqDataKey[i] = (byte)i;
        ctx->rspDataKey[i] = (byte)i;
    }
    for (i = 0; i < WOLFSPDM_AEAD_IV_SIZE; i++) {
        ctx->reqDataIv[i] = (byte)(0x20 + i);
        ctx->rspDataIv[i] = (byte)(0x20 + i);
    }

    /* DSP0277 Sec. 11.3: wire seqNum is 16-bit and shall not wrap. wolfSPDM_BuildIV
     * mixes only the low 16 bits into the AES-GCM IV, so any wrap would reuse
     * an IV under the same key. Encrypt/decrypt must refuse to proceed past
     * the 16-bit boundary; caller is expected to wolfSPDM_KeyUpdate first. */

    /* Counter planted just past the 16-bit wire boundary: encrypt must
     * refuse rather than reuse an IV. */
    ctx->reqSeqNum = 0x10000;
    encSz = sizeof(enc);
    ASSERT_EQ(wolfSPDM_EncryptInternal(ctx, plain, sizeof(plain), enc, &encSz),
        WOLFSPDM_E_SEQUENCE, "Encrypt past seq=0xFFFF must be refused");

    /* Decrypt-side cap mirrors the encrypt side. Use a separate output
     * buffer so a future change that writes before checking seqNum would
     * be caught instead of silently corrupting the input. */
    ctx->rspSeqNum = 0x10000;
    {
        byte dec[256];
        word32 decSz = sizeof(dec);
        ASSERT_EQ(wolfSPDM_DecryptInternal(ctx, enc, sizeof(enc), dec, &decSz),
            WOLFSPDM_E_SEQUENCE, "Decrypt past seq=0xFFFF must be refused");
    }

    /* A counter just inside the limit still works. */
    ctx->reqSeqNum = 0xFFFF;
    encSz = sizeof(enc);
    ASSERT_SUCCESS(wolfSPDM_EncryptInternal(ctx, plain, sizeof(plain),
        enc, &encSz));

    TEST_CTX_FREE();
    TEST_PASS();
}

/* ========================================================================== */
/* Session State Tests */
/* ========================================================================== */

static int test_session_state(void)
{
    TEST_CTX_SETUP();

    printf("test_session_state...\n");
    ASSERT_EQ(wolfSPDM_IsConnected(ctx), 0, "Should not be connected");
    ASSERT_EQ(wolfSPDM_GetSessionId(ctx), 0, "SessionId should be 0");

    /* Mid-handshake (KEY_EXCHANGE done, FINISH pending): IsConnected is
     * still 0 but sessionId IS available so the I/O callback can tag
     * the encrypted FINISH record. */
    ctx->state = WOLFSPDM_STATE_KEY_EX;
    ctx->sessionId = 0x12345678;
    ASSERT_EQ(wolfSPDM_IsConnected(ctx), 0,
        "IsConnected should remain 0 mid-handshake");
    ASSERT_EQ(wolfSPDM_GetSessionId(ctx), (word32)0x12345678,
        "GetSessionId must return value before STATE_CONNECTED");

    /* Simulate connected state */
    ctx->state = WOLFSPDM_STATE_CONNECTED;
    ctx->sessionId = 0xAABBCCDD;
    ctx->spdmVersion = SPDM_VERSION_12;
    ASSERT_EQ(wolfSPDM_IsConnected(ctx), 1, "Should be connected");
    ASSERT_EQ(wolfSPDM_GetSessionId(ctx), (word32)0xAABBCCDD, "SessionId wrong");
    ASSERT_EQ(wolfSPDM_GetNegotiatedVersion(ctx), SPDM_VERSION_12, "Version wrong");

    TEST_CTX_FREE();
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
    test_parse_algorithms_set_b_enforcement();
    test_build_get_digests();
    test_build_get_certificate();
    test_build_key_exchange_opaque_data();
    test_build_finish_opaque_length_14();
    test_parse_finish_rsp_14_opaque_length();
    test_key_exchange_requires_cert();
    test_parse_key_exchange_rsp_too_short();
    test_parse_key_exchange_rsp_mutual_auth_refused();
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
    test_parse_challenge_auth_reqctx_echo();
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

    /* Multi-version tests */
    test_kdf_version_prefix();
    test_hmac_mismatch_negative();
    test_transcript_overflow();
#ifndef NO_WOLFSPDM_MEAS
    test_parse_measurements_negative();
    test_parse_measurements_13_requester_context();
    test_get_measurements_peer_error();
    test_get_measurements_uses_secured_when_measured();
#endif
    test_version_fallback();
    test_set_max_version();
    test_sequence_number_wrap();
    test_sequence_number_mismatch();

    /* Session state tests */
    test_session_state();

    printf("\n===========================================\n");
    printf("Results: %d passed, %d failed\n", g_testsPassed, g_testsFailed);
    printf("===========================================\n");

    return (g_testsFailed == 0) ? 0 : 1;
}
