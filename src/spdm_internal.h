/* spdm_internal.h
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

#ifndef WOLFSPDM_INTERNAL_H
#define WOLFSPDM_INTERNAL_H

/* Include autoconf generated config.h for feature detection */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* wolfSSL options MUST be included first */
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#include <wolfspdm/spdm.h>
#include <wolfspdm/spdm_types.h>
#include <wolfspdm/spdm_error.h>

/* wolfCrypt includes */
#include <wolfssl/version.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#ifdef WOLFSPDM_HAVE_MLDSA
    #include <wolfssl/wolfcrypt/wc_mldsa.h>
#endif
#ifdef WOLFSPDM_HAVE_MLKEM
    #include <wolfssl/wolfcrypt/wc_mlkem.h>
#endif

#if defined(LIBWOLFSSL_VERSION_HEX) && LIBWOLFSSL_VERSION_HEX < 0x05008004
/* wc_ForceZero added in wolfSSL v5.8.4; provide a stub for older releases. */
static WC_INLINE void wc_ForceZero(void* mem, word32 len)
{
    volatile byte* z = (volatile byte*)mem;
    while (len--) {
        *z++ = 0;
    }
}
#endif

/* Constant-time byte comparison: returns 0 iff a==b for the full length.
 * Used for MAC/HMAC equality so we don't leak match position via timing. */
static WC_INLINE int wolfSPDM_ConstCompare(const byte* a, const byte* b,
    word32 len)
{
    byte diff = 0;
    word32 i;
    for (i = 0; i < len; i++) {
        diff |= (byte)(a[i] ^ b[i]);
    }
    return diff;
}

#ifdef __cplusplus
extern "C" {
#endif

/* --- State Machine Constants --- */

#define WOLFSPDM_STATE_INIT         0   /* Initial state */
#define WOLFSPDM_STATE_VERSION      1   /* GET_VERSION complete */
#define WOLFSPDM_STATE_CAPS         2   /* GET_CAPABILITIES complete */
#define WOLFSPDM_STATE_ALGO         3   /* NEGOTIATE_ALGORITHMS complete */
#define WOLFSPDM_STATE_DIGESTS      4   /* GET_DIGESTS complete */
#define WOLFSPDM_STATE_CERT         5   /* GET_CERTIFICATE complete */
#define WOLFSPDM_STATE_KEY_EX       6   /* KEY_EXCHANGE complete */
#define WOLFSPDM_STATE_FINISH       7   /* FINISH complete */
#define WOLFSPDM_STATE_CONNECTED    8   /* Session established */
#define WOLFSPDM_STATE_ERROR        9   /* Error state */
#ifndef NO_WOLFSPDM_MEAS
#define WOLFSPDM_STATE_MEASURED     10  /* Measurements retrieved */
#endif

/* SPDM version bounds. Override with -DWOLFSPDM_MIN/MAX_SPDM_VERSION at
 * compile time. The runtime wolfSPDM_SetMaxVersion clamps against these. */
#ifndef WOLFSPDM_MAX_SPDM_VERSION
#define WOLFSPDM_MAX_SPDM_VERSION  SPDM_VERSION_14
#endif
#ifndef WOLFSPDM_MIN_SPDM_VERSION
#define WOLFSPDM_MIN_SPDM_VERSION  SPDM_VERSION_12
#endif

/* --- Measurement Block Structure --- */

#ifndef NO_WOLFSPDM_MEAS
typedef struct WOLFSPDM_MEAS_BLOCK {
    byte   index;                                   /* SPDM measurement index (1-based) */
    byte   measurementSpec;                         /* Measurement specification (1=DMTF) */
    byte   dmtfType;                                /* DMTFSpecMeasurementValueType */
    word16 valueSize;                               /* Actual value size in bytes */
    byte   value[WOLFSPDM_MAX_MEAS_VALUE_SIZE];     /* Measurement value (digest/raw) */
} WOLFSPDM_MEAS_BLOCK;
#endif /* !NO_WOLFSPDM_MEAS */

/* --- Internal Context Structure --- */

struct WOLFSPDM_CTX {
    /* State machine */
    int state;

    /* Boolean flags - packed into a small bit-field struct (one 4-byte
     * unsigned int holding 9 booleans, vs. 9 separate ints = 36 bytes).
     * Use unsigned int (not byte) since C11 Sec. 6.7.2.1 only guarantees
     * bit-field support for _Bool, signed int, and unsigned int - this
     * keeps the struct portable under -Wpedantic -Werror. */
    struct {
        unsigned int debug              : 1;
        unsigned int initialized        : 1;
        unsigned int isDynamic          : 1;  /* Set by wolfSPDM_New(), checked by Free */
        unsigned int rngInitialized     : 1;
        unsigned int ephemeralKeyInit   : 1;
        unsigned int hasMeasurements    : 1;
        unsigned int hasResponderPubKey : 1;
        unsigned int hasTrustedCAs      : 1;
        unsigned int m1m2HashInit       : 1;
        unsigned int allowUntrustedCert : 1;  /* Explicit opt-in for missing trust anchor */
    } flags;

    /* I/O callback */
    WOLFSPDM_IO_CB ioCb;
    void* ioUserCtx;

    /* Random number generator */
    WC_RNG rng;

    /* Negotiated parameters */
    byte maxVersion;            /* Runtime max version cap (0 = use compile-time default) */
    byte spdmVersion;           /* Negotiated SPDM version */
    byte lastPeerErrorCode;     /* Last SPDM_ERROR Param1 from responder (0 = none) */
    word32 rspCaps;             /* Responder capabilities */
    word32 reqCaps;             /* Our (requester) capabilities */
    byte   ctExponent;          /* DSP0274 Table 12: CT = 2^CTExponent us */
    word32 dataTransferSize;    /* SPDM 1.2+ max per-fragment payload */
    word32 maxSpdmMsgSize;      /* SPDM 1.2+ max full SPDM message size */
    byte   slotMask;            /* DIGESTS Param1: bit i = slot i populated */
    byte   currentSlotId;       /* Slot the most recent GET_CERTIFICATE used */

    /* Ephemeral key generated for KEY_EXCHANGE. kexType records the negotiated
     * key-exchange method; only one union member is ever live. The ML-KEM key
     * also holds the decapsulation key dk between request and response. */
    byte kexType;                       /* WOLFSPDM_KEX_ECDHE|_MLKEM */
    word16 kemAlgSel;                   /* Selected SPDM_KEM_ALGO_* (0 if ECDHE) */
    byte kexAdvDhe;                     /* Advertise the DHE group (default 1) */
    word16 kexAdvKem;                   /* ML-KEM mask to advertise (0 = none) */
    union {
        ecc_key     ecc;                /* ECDHE secp384r1 (Algorithm Set B) */
#ifdef WOLFSPDM_HAVE_MLKEM
        MlKemKey    mlkem;              /* ML-KEM (DSP0274 1.4) */
#endif
    } ephemeralKey;

    /* Key-exchange shared secret: ECDH P-384 X-coordinate (48 bytes) or an
     * ML-KEM decapsulated shared secret (32 bytes); sharedSecretSz tracks which. */
    byte sharedSecret[WOLFSPDM_ECC_KEY_SIZE];
    word32 sharedSecretSz;

    /* Transcript hash for TH1/TH2 computation */
    byte transcript[WOLFSPDM_MAX_TRANSCRIPT];
    word32 transcriptLen;
    word32 vcaLen;  /* VCA transcript size (after ALGORITHMS, used by measurement sig) */

    /* Certificate chain buffer for Ct computation */
    byte certChain[WOLFSPDM_MAX_CERT_CHAIN];
    word32 certChainLen;

    /* Computed hashes */
    byte certChainHash[WOLFSPDM_HASH_SIZE]; /* Ct = Hash(cert_chain) */
    byte th1[WOLFSPDM_HASH_SIZE];           /* TH1 after KEY_EXCHANGE_RSP */

    /* Derived keys */
    byte handshakeSecret[WOLFSPDM_HASH_SIZE];
    byte reqHsSecret[WOLFSPDM_HASH_SIZE];
    byte rspHsSecret[WOLFSPDM_HASH_SIZE];
    byte reqFinishedKey[WOLFSPDM_HASH_SIZE];
    byte rspFinishedKey[WOLFSPDM_HASH_SIZE];

    /* Session encryption keys (AES-256-GCM) */
    byte reqDataKey[WOLFSPDM_AEAD_KEY_SIZE];   /* Outgoing encryption key */
    byte rspDataKey[WOLFSPDM_AEAD_KEY_SIZE];   /* Incoming decryption key */
    byte reqDataIv[WOLFSPDM_AEAD_IV_SIZE];     /* Base IV for outgoing */
    byte rspDataIv[WOLFSPDM_AEAD_IV_SIZE];     /* Base IV for incoming */

    /* Sequence numbers for IV generation */
    word64 reqSeqNum;           /* Outgoing message sequence */
    word64 rspSeqNum;           /* Incoming message sequence (expected) */

    /* Session IDs */
    word16 reqSessionId;        /* Our session ID (chosen by us) */
    word16 rspSessionId;        /* Responder's session ID */
    word32 sessionId;           /* Combined: reqSessionId | (rspSessionId << 16) */

#ifndef NO_WOLFSPDM_MEAS
    /* Measurement data */
    WOLFSPDM_MEAS_BLOCK measBlocks[WOLFSPDM_MAX_MEAS_BLOCKS];
    word32 measBlockCount;
    byte   measNonce[32];                           /* Nonce for signed measurements */
    byte   measSummaryHash[WOLFSPDM_HASH_SIZE];     /* Summary hash from response */
    byte   measSignature[WOLFSPDM_MAX_SIG_SIZE];    /* Captured signature (ECDSA/ML-DSA) */
    word32 measSignatureSize;                       /* 0 if unsigned, else SigLen */

#ifndef NO_WOLFSPDM_MEAS_VERIFY
    /* Saved GET_MEASUREMENTS request for L1/L2 transcript */
    byte            measReqMsg[48];                 /* Saved request (max 37 bytes) */
    word32          measReqMsgSz;
#endif /* !NO_WOLFSPDM_MEAS_VERIFY */
#endif /* !NO_WOLFSPDM_MEAS */

    /* Responder identity for signature verification (measurements + challenge).
     * asymType records which family the responder selected during
     * NEGOTIATE_ALGORITHMS; only one key in the union is ever live. */
    byte            asymType;                       /* WOLFSPDM_ASYM_ECDSA|_MLDSA */
    word32          pqcAsymSel;                     /* Selected PqcAsymSel (0=ECDSA) */
    union {
        ecc_key     ecc;                            /* ECDSA P-384 (Algorithm Set B) */
#ifdef WOLFSPDM_HAVE_MLDSA
        MlDsaKey    mldsa;                          /* ML-DSA (DSP0274 1.4) */
#endif
    } responderPubKey;                              /* Extracted from cert chain leaf */

    /* Certificate chain validation */
    byte   trustedCAs[WOLFSPDM_MAX_TRUSTED_CA];    /* DER-encoded root CA */
    word32 trustedCAsSz;

#ifndef NO_WOLFSPDM_CHALLENGE
    /* Challenge authentication */
    byte   challengeNonce[32];                      /* Saved nonce from CHALLENGE request */
    byte   challengeReqCtx[8];                      /* RequesterContext sent (1.3+) */
    byte   challengeMeasHashType;                   /* MeasurementSummaryHashType from req */
    byte   challengeSlotId;                         /* SlotID sent (for echo verification) */

    /* Running M1/M2 hash for CHALLENGE_AUTH signature verification.
     * Per DSP0274, M1/M2 = A || B || C where:
     *   A = VCA (GET_VERSION..ALGORITHMS)
     *   B = GET_DIGESTS + DIGESTS + GET_CERTIFICATE + CERTIFICATE (all chunks)
     *   C = CHALLENGE + CHALLENGE_AUTH (before sig)
     * This hash accumulates A+B during NegAlgo/GetDigests/GetCertificate,
     * then C is added in VerifyChallengeAuthSig. */
    wc_Sha384 m1m2Hash;
#endif

    /* Key update state - app secrets for re-derivation */
    byte   reqAppSecret[WOLFSPDM_HASH_SIZE];        /* 48 bytes */
    byte   rspAppSecret[WOLFSPDM_HASH_SIZE];        /* 48 bytes */

#ifdef WOLFSPDM_HAVE_CHUNK
    /* Single reused transport buffer for CHUNK_GET/CHUNK_RESPONSE (the MTU).
     * Zero-allocation: one fixed buffer holds one CHUNK_RESPONSE message. */
    byte   chunkBuf[WOLFSPDM_CHUNK_BUF_SIZE];
#endif
};

/* Free whichever responder verify key is live (union member by asymType). */
static WC_INLINE void wolfSPDM_FreeResponderPubKey(WOLFSPDM_CTX* ctx)
{
#ifdef WOLFSPDM_HAVE_MLDSA
    if (ctx->asymType == WOLFSPDM_ASYM_MLDSA) {
        wc_MlDsaKey_Free(&ctx->responderPubKey.mldsa);
        return;
    }
#endif
    wc_ecc_free(&ctx->responderPubKey.ecc);
}

/* Free whichever ephemeral key is live (union member by kexType). */
static WC_INLINE void wolfSPDM_FreeEphemeralKey(WOLFSPDM_CTX* ctx)
{
#ifdef WOLFSPDM_HAVE_MLKEM
    if (ctx->kexType == WOLFSPDM_KEX_MLKEM) {
        wc_MlKemKey_Free(&ctx->ephemeralKey.mlkem);
        return;
    }
#endif
    wc_ecc_free(&ctx->ephemeralKey.ecc);
}

/* --- Byte-Order Helpers --- */

static WC_INLINE void SPDM_Set16LE(byte* buf, word16 val) {
    buf[0] = (byte)(val & 0xFF); buf[1] = (byte)(val >> 8);
}
static WC_INLINE word16 SPDM_Get16LE(const byte* buf) {
    return (word16)(buf[0] | (buf[1] << 8));
}
static WC_INLINE void SPDM_Set16BE(byte* buf, word16 val) {
    buf[0] = (byte)(val >> 8); buf[1] = (byte)(val & 0xFF);
}
static WC_INLINE word16 SPDM_Get16BE(const byte* buf) {
    return (word16)((buf[0] << 8) | buf[1]);
}
static WC_INLINE void SPDM_Set32LE(byte* buf, word32 val) {
    buf[0] = (byte)(val & 0xFF);       buf[1] = (byte)((val >> 8) & 0xFF);
    buf[2] = (byte)((val >> 16) & 0xFF); buf[3] = (byte)((val >> 24) & 0xFF);
}
static WC_INLINE word32 SPDM_Get32LE(const byte* buf) {
    return (word32)buf[0] | ((word32)buf[1] << 8) |
           ((word32)buf[2] << 16) | ((word32)buf[3] << 24);
}
static WC_INLINE void SPDM_Set32BE(byte* buf, word32 val) {
    buf[0] = (byte)(val >> 24);         buf[1] = (byte)((val >> 16) & 0xFF);
    buf[2] = (byte)((val >> 8) & 0xFF); buf[3] = (byte)(val & 0xFF);
}
static WC_INLINE word32 SPDM_Get32BE(const byte* buf) {
    return ((word32)buf[0] << 24) | ((word32)buf[1] << 16) |
           ((word32)buf[2] << 8) | (word32)buf[3];
}
static WC_INLINE void SPDM_Set64LE(byte* buf, word64 val) {
    buf[0] = (byte)(val & 0xFF);         buf[1] = (byte)((val >> 8) & 0xFF);
    buf[2] = (byte)((val >> 16) & 0xFF); buf[3] = (byte)((val >> 24) & 0xFF);
    buf[4] = (byte)((val >> 32) & 0xFF); buf[5] = (byte)((val >> 40) & 0xFF);
    buf[6] = (byte)((val >> 48) & 0xFF); buf[7] = (byte)((val >> 56) & 0xFF);
}
static WC_INLINE word64 SPDM_Get64LE(const byte* buf) {
    return (word64)buf[0] | ((word64)buf[1] << 8) |
           ((word64)buf[2] << 16) | ((word64)buf[3] << 24) |
           ((word64)buf[4] << 32) | ((word64)buf[5] << 40) |
           ((word64)buf[6] << 48) | ((word64)buf[7] << 56);
}

/* Build IV: BaseIV XOR zero-extended sequence number (DSP0277) */
static WC_INLINE void wolfSPDM_BuildIV(byte* iv, const byte* baseIv,
    word64 seqNum)
{
    XMEMCPY(iv, baseIv, WOLFSPDM_AEAD_IV_SIZE);
    iv[0] ^= (byte)(seqNum & 0xFF);
    iv[1] ^= (byte)((seqNum >> 8) & 0xFF);
}

/* --- Connect Step Macro --- */

#define SPDM_CONNECT_STEP(ctx, msg, func) do { \
    wolfSPDM_DebugPrint(ctx, msg); \
    rc = func; \
    if (rc != WOLFSPDM_SUCCESS) { ctx->state = WOLFSPDM_STATE_ERROR; return rc; } \
} while (0)

/* --- Argument Validation Macros --- */

#define SPDM_CHECK_BUILD_ARGS(ctx, buf, bufSz, minSz) \
    do { \
        if ((ctx) == NULL || (buf) == NULL || (bufSz) == NULL) \
            return WOLFSPDM_E_INVALID_ARG; \
        if (*(bufSz) < (minSz)) \
            return WOLFSPDM_E_BUFFER_SMALL; \
    } while (0)

/* Validate parser inputs. The 4-byte SPDM header (version + code + Param1 +
 * Param2) must always be present. A response shorter than minSz that turns
 * out to be SPDM_ERROR is *not* rejected here so the matching
 * SPDM_CHECK_RESPONSE call can surface it as WOLFSPDM_E_PEER_ERROR. */
#define SPDM_CHECK_PARSE_OR_ERROR_ARGS(ctx, buf, bufSz, minSz) \
    do { \
        if ((ctx) == NULL || (buf) == NULL) \
            return WOLFSPDM_E_INVALID_ARG; \
        if ((bufSz) < 4) \
            return WOLFSPDM_E_INVALID_ARG; \
        if ((bufSz) < (minSz) && (buf)[1] != SPDM_ERROR) \
            return WOLFSPDM_E_INVALID_ARG; \
    } while (0)

/* --- Response Code Check Macro --- */

#define SPDM_CHECK_RESPONSE(ctx, buf, bufSz, expected, fallbackErr) \
    do { \
        if ((buf)[1] != (expected)) { \
            int _ec; \
            if (wolfSPDM_CheckError((buf), (bufSz), &_ec)) { \
                (ctx)->lastPeerErrorCode = (byte)_ec; \
                wolfSPDM_DebugPrint((ctx), "SPDM error: 0x%02x\n", _ec); \
                return WOLFSPDM_E_PEER_ERROR; \
            } \
            return (fallbackErr); \
        } \
    } while (0)

/* --- Internal Function Declarations - Transcript --- */

/* Reset transcript buffer */
void wolfSPDM_TranscriptReset(WOLFSPDM_CTX* ctx);

/* Add data to transcript */
int wolfSPDM_TranscriptAdd(WOLFSPDM_CTX* ctx, const byte* data, word32 len);

/* Add data to certificate chain buffer */
int wolfSPDM_CertChainAdd(WOLFSPDM_CTX* ctx, const byte* data, word32 len);

/* Compute hash of current transcript */
int wolfSPDM_TranscriptHash(WOLFSPDM_CTX* ctx, byte* hash);

/* Compute Ct = Hash(certificate_chain) */
int wolfSPDM_ComputeCertChainHash(WOLFSPDM_CTX* ctx);

/* SHA-384 hash helper: Hash(d1 || d2 || d3), pass NULL/0 for unused buffers */
int wolfSPDM_Sha384Hash(byte* out,
    const byte* d1, word32 d1Sz,
    const byte* d2, word32 d2Sz,
    const byte* d3, word32 d3Sz);

/* --- Internal Function Declarations - Crypto --- */

/* Generate ephemeral P-384 key for ECDHE */
int wolfSPDM_GenerateEphemeralKey(WOLFSPDM_CTX* ctx);

/* Export ephemeral public key (X||Y) */
int wolfSPDM_ExportEphemeralPubKey(WOLFSPDM_CTX* ctx,
    byte* pubKeyX, word32* pubKeyXSz,
    byte* pubKeyY, word32* pubKeyYSz);

/* Compute ECDH shared secret from responder's public key */
int wolfSPDM_ComputeSharedSecret(WOLFSPDM_CTX* ctx,
    const byte* peerPubKeyX, const byte* peerPubKeyY);

#ifdef WOLFSPDM_HAVE_MLKEM
/* Generate the ephemeral ML-KEM key pair and export the encapsulation key ek */
int wolfSPDM_GenerateMlKemKey(WOLFSPDM_CTX* ctx, byte* ekOut, word32* ekOutSz);

/* Decapsulate the responder's ciphertext c into ctx->sharedSecret (K') */
int wolfSPDM_MlKemDecapsulate(WOLFSPDM_CTX* ctx, const byte* ct, word32 ctSz);
#endif

/* Generate random bytes */
int wolfSPDM_GetRandom(WOLFSPDM_CTX* ctx, byte* out, word32 outSz);

/* --- Internal Function Declarations - Key Derivation --- */

/* Derive all keys from shared secret and TH1 */
int wolfSPDM_DeriveHandshakeKeys(WOLFSPDM_CTX* ctx, const byte* th1Hash);

/* Derive application data keys from MasterSecret and TH2_final */
int wolfSPDM_DeriveAppDataKeys(WOLFSPDM_CTX* ctx);

/* HKDF-Expand with SPDM BinConcat format (uses version-specific prefix) */
int wolfSPDM_HkdfExpandLabel(byte spdmVersion, const byte* secret, word32 secretSz,
    const char* label, const byte* context, word32 contextSz,
    byte* out, word32 outSz);

/* Compute HMAC for VerifyData */
int wolfSPDM_ComputeVerifyData(const byte* finishedKey, const byte* thHash,
    byte* verifyData);

/* --- Internal Function Declarations - Message Building --- */

/* Build GET_VERSION request */
int wolfSPDM_BuildGetVersion(byte* buf, word32* bufSz);

/* Build GET_CAPABILITIES request */
int wolfSPDM_BuildGetCapabilities(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* Build NEGOTIATE_ALGORITHMS request */
int wolfSPDM_BuildNegotiateAlgorithms(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* Build GET_DIGESTS request */
int wolfSPDM_BuildGetDigests(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* Build GET_CERTIFICATE request */
int wolfSPDM_BuildGetCertificate(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    int slotId, word16 offset, word16 length);

/* Build KEY_EXCHANGE request */
int wolfSPDM_BuildKeyExchange(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* Build FINISH request */
int wolfSPDM_BuildFinish(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* Build END_SESSION request */
int wolfSPDM_BuildEndSession(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* --- Internal Function Declarations - Message Parsing --- */

/* Parse VERSION response */
int wolfSPDM_ParseVersion(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);

/* Parse CAPABILITIES response */
int wolfSPDM_ParseCapabilities(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);

/* Parse ALGORITHMS response */
int wolfSPDM_ParseAlgorithms(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);

/* Parse DIGESTS response */
int wolfSPDM_ParseDigests(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);

/* Parse CERTIFICATE response */
int wolfSPDM_ParseCertificate(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz,
    word16* portionLen, word16* remainderLen);

/* Parse KEY_EXCHANGE_RSP */
int wolfSPDM_ParseKeyExchangeRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);

/* Parse FINISH_RSP (after decryption) */
int wolfSPDM_ParseFinishRsp(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);

/* Check for ERROR response */
int wolfSPDM_CheckError(const byte* buf, word32 bufSz, int* errorCode);

/* --- Internal Function Declarations - Secured Messaging --- */

/* Encrypt plaintext using session keys */
int wolfSPDM_EncryptInternal(WOLFSPDM_CTX* ctx,
    const byte* plain, word32 plainSz,
    byte* enc, word32* encSz);

/* Decrypt ciphertext using session keys */
int wolfSPDM_DecryptInternal(WOLFSPDM_CTX* ctx,
    const byte* enc, word32 encSz,
    byte* plain, word32* plainSz);

/* --- Internal Utility Functions --- */

/* Send message via I/O callback and receive response. SendReceive transparently
 * reassembles a chunked (LargeResponse) reply; SendReceiveRaw is the bare
 * callback used by the chunk loop and the secured transport to avoid re-entry. */
int wolfSPDM_SendReceiveRaw(WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz);
int wolfSPDM_SendReceive(WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz);

#ifdef WOLFSPDM_HAVE_CHUNK
/* True if buf is an ERROR(LargeResponse); writes the 1-byte Handle. */
static WC_INLINE int wolfSPDM_IsLargeResponse(const byte* buf, word32 bufSz,
    byte* handle)
{
    if (buf == NULL || bufSz < 5) {
        return 0;
    }
    if (buf[1] == SPDM_ERROR && buf[2] == SPDM_ERROR_LARGE_RESPONSE) {
        if (handle != NULL) {
            *handle = buf[4];  /* ExtendedErrorData byte 0 = Handle (Table 68) */
        }
        return 1;
    }
    return 0;
}

/* Build a CHUNK_GET request for (handle, seqNo). */
int wolfSPDM_BuildChunkGet(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    byte handle, word32 seqNo);

/* Reassemble a large response the responder split. The triggering
 * ERROR(LargeResponse) was already received; this drives the CHUNK_GET loop and
 * fills outBuf with the logical message. secured selects the encrypted
 * (session) transport. */
int wolfSPDM_ReassembleLargeResponse(WOLFSPDM_CTX* ctx, int secured,
    byte handle, byte* outBuf, word32 outBufSz, word32* outSz);
#endif /* WOLFSPDM_HAVE_CHUNK */

/* Debug print (if enabled) */
void wolfSPDM_DebugPrint(WOLFSPDM_CTX* ctx, const char* fmt, ...)
#ifdef __GNUC__
    __attribute__((format(printf, 2, 3)))
#endif
    ;

/* Hex dump for debugging */
void wolfSPDM_DebugHex(WOLFSPDM_CTX* ctx, const char* label,
    const byte* data, word32 len);

/* --- Internal Function Declarations - Measurements --- */

#ifndef NO_WOLFSPDM_MEAS
/* Build GET_MEASUREMENTS request */
int wolfSPDM_BuildGetMeasurements(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    byte operation, byte requestSig);

/* Parse MEASUREMENTS response */
int wolfSPDM_ParseMeasurements(WOLFSPDM_CTX* ctx, const byte* buf, word32 bufSz);

#ifndef NO_WOLFSPDM_MEAS_VERIFY
/* Verify measurement signature (L1/L2 transcript) */
int wolfSPDM_VerifyMeasurementSig(WOLFSPDM_CTX* ctx,
    const byte* rspBuf, word32 rspBufSz,
    const byte* reqMsg, word32 reqMsgSz);
#endif /* !NO_WOLFSPDM_MEAS_VERIFY */
#endif /* !NO_WOLFSPDM_MEAS */

/* --- Internal Function Declarations - Certificate Chain Validation --- */

/* Extract responder's public key from certificate chain leaf cert */
int wolfSPDM_ExtractResponderPubKey(WOLFSPDM_CTX* ctx);

/* Validate certificate chain using trusted CAs and extract public key */
int wolfSPDM_ValidateCertChain(WOLFSPDM_CTX* ctx);

/* --- Internal Function Declarations - Challenge --- */

#ifndef NO_WOLFSPDM_CHALLENGE
/* Build CHALLENGE request */
int wolfSPDM_BuildChallenge(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    int slotId, byte measHashType);

/* Parse CHALLENGE_AUTH response */
int wolfSPDM_ParseChallengeAuth(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz, word32* sigOffset);

/* Verify CHALLENGE_AUTH signature */
int wolfSPDM_VerifyChallengeAuthSig(WOLFSPDM_CTX* ctx,
    const byte* rspBuf, word32 rspBufSz,
    const byte* reqMsg, word32 reqMsgSz, word32 sigOffset);
#endif /* !NO_WOLFSPDM_CHALLENGE */

/* --- Internal Function Declarations - Heartbeat --- */

/* Build HEARTBEAT request */
int wolfSPDM_BuildHeartbeat(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* Parse HEARTBEAT_ACK response */
int wolfSPDM_ParseHeartbeatAck(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz);

/* --- Internal Function Declarations - Key Update --- */

/* Build KEY_UPDATE request */
int wolfSPDM_BuildKeyUpdate(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz,
    byte operation, byte* tag);

/* Parse KEY_UPDATE_ACK response */
int wolfSPDM_ParseKeyUpdateAck(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz, byte operation, byte tag);

/* Derive updated keys from saved app secrets */
int wolfSPDM_DeriveUpdatedKeys(WOLFSPDM_CTX* ctx, int updateAll);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSPDM_INTERNAL_H */
