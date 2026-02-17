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
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/memory.h>
#include <wolfssl/wolfcrypt/asn_public.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ==========================================================================
 * State Machine Constants
 * ========================================================================== */

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

/* ==========================================================================
 * Measurement Block Structure
 * ========================================================================== */

#ifndef NO_WOLFSPDM_MEAS
typedef struct WOLFSPDM_MEAS_BLOCK {
    byte   index;                                   /* SPDM measurement index (1-based) */
    byte   measurementSpec;                         /* Measurement specification (1=DMTF) */
    byte   dmtfType;                                /* DMTFSpecMeasurementValueType */
    word16 valueSize;                               /* Actual value size in bytes */
    byte   value[WOLFSPDM_MAX_MEAS_VALUE_SIZE];     /* Measurement value (digest/raw) */
} WOLFSPDM_MEAS_BLOCK;
#endif /* !NO_WOLFSPDM_MEAS */

/* ==========================================================================
 * Internal Context Structure
 * ========================================================================== */

struct WOLFSPDM_CTX {
    /* State machine */
    int state;

    /* Configuration flags */
    int debug;
    int initialized;
    int isDynamic;          /* Set by wolfSPDM_New(), checked by wolfSPDM_Free() */

    /* Protocol mode (standard SPDM or Nuvoton) */
    WOLFSPDM_MODE mode;

    /* I/O callback */
    WOLFSPDM_IO_CB ioCb;
    void* ioUserCtx;

#ifdef WOLFSPDM_NUVOTON
    /* Nuvoton-specific: TCG binding fields */
    word32 connectionHandle;    /* Connection handle (usually 0) */
    word16 fipsIndicator;       /* FIPS service indicator */

    /* Nuvoton-specific: Host's public key in TPMT_PUBLIC format */
    byte reqPubKeyTPMT[128];    /* TPMT_PUBLIC serialized (~120 bytes) */
    word32 reqPubKeyTPMTLen;
#endif

    /* Random number generator */
    WC_RNG rng;
    int rngInitialized;

    /* Negotiated parameters */
    byte spdmVersion;           /* Negotiated SPDM version */
    word32 rspCaps;             /* Responder capabilities */
    word32 reqCaps;             /* Our (requester) capabilities */
    byte mutAuthRequested;      /* MutAuthRequested from KEY_EXCHANGE_RSP (offset 6) */
    byte reqSlotId;             /* ReqSlotIDParam from KEY_EXCHANGE_RSP (offset 7) */

    /* Ephemeral ECDHE key (generated for KEY_EXCHANGE) */
    ecc_key ephemeralKey;
    int ephemeralKeyInitialized;

    /* ECDH shared secret (P-384 X-coordinate = 48 bytes) */
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
    byte th2[WOLFSPDM_HASH_SIZE];           /* TH2 after FINISH */

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

    /* Responder's identity public key (for cert-less mode like Nuvoton) */
    byte rspPubKey[128];  /* TPMT_PUBLIC (120 bytes for P-384) or raw X||Y (96) */
    word32 rspPubKeyLen;
    int hasRspPubKey;

    /* Requester's identity key pair (for mutual auth) */
    byte reqPrivKey[WOLFSPDM_ECC_KEY_SIZE];
    word32 reqPrivKeyLen;
    byte reqPubKey[WOLFSPDM_ECC_POINT_SIZE];
    word32 reqPubKeyLen;
    int hasReqKeyPair;

    /* Message buffers */
    byte sendBuf[WOLFSPDM_MAX_MSG_SIZE + WOLFSPDM_AEAD_TAG_SIZE];
    byte recvBuf[WOLFSPDM_MAX_MSG_SIZE + WOLFSPDM_AEAD_TAG_SIZE];

#ifndef NO_WOLFSPDM_MEAS
    /* Measurement data */
    WOLFSPDM_MEAS_BLOCK measBlocks[WOLFSPDM_MAX_MEAS_BLOCKS];
    word32 measBlockCount;
    byte   measNonce[32];                           /* Nonce for signed measurements */
    byte   measSummaryHash[WOLFSPDM_HASH_SIZE];     /* Summary hash from response */
    byte   measSignature[WOLFSPDM_ECC_SIG_SIZE];    /* Captured signature (96 bytes P-384) */
    word32 measSignatureSize;                       /* 0 if unsigned, 96 if signed */
    int    hasMeasurements;

#ifndef NO_WOLFSPDM_MEAS_VERIFY
    /* Saved GET_MEASUREMENTS request for L1/L2 transcript */
    byte            measReqMsg[48];                 /* Saved request (max 37 bytes) */
    word32          measReqMsgSz;
#endif /* !NO_WOLFSPDM_MEAS_VERIFY */
#endif /* !NO_WOLFSPDM_MEAS */

    /* Responder identity for signature verification (measurements + challenge) */
    ecc_key         responderPubKey;                /* Extracted from cert chain leaf */
    int             hasResponderPubKey;             /* 1 if key extracted successfully */

    /* Certificate chain validation */
    byte   trustedCAs[WOLFSPDM_MAX_CERT_CHAIN];    /* DER-encoded root CAs */
    word32 trustedCAsSz;
    int    hasTrustedCAs;                           /* 1 if CAs loaded */

#ifndef NO_WOLFSPDM_CHALLENGE
    /* Challenge authentication */
    byte   challengeNonce[32];                      /* Saved nonce from CHALLENGE request */
    byte   challengeMeasHashType;                   /* MeasurementSummaryHashType from req */

    /* Running M1/M2 hash for CHALLENGE_AUTH signature verification.
     * Per DSP0274, M1/M2 = A || B || C where:
     *   A = VCA (GET_VERSION..ALGORITHMS)
     *   B = GET_DIGESTS + DIGESTS + GET_CERTIFICATE + CERTIFICATE (all chunks)
     *   C = CHALLENGE + CHALLENGE_AUTH (before sig)
     * This hash accumulates A+B during NegAlgo/GetDigests/GetCertificate,
     * then C is added in VerifyChallengeAuthSig. */
    wc_Sha384 m1m2Hash;
    int       m1m2HashInit;                         /* 1 if m1m2Hash is initialized */
#endif

    /* Key update state — app secrets for re-derivation */
    byte   reqAppSecret[WOLFSPDM_HASH_SIZE];        /* 48 bytes */
    byte   rspAppSecret[WOLFSPDM_HASH_SIZE];        /* 48 bytes */
};

/* ==========================================================================
 * Internal Function Declarations - Transcript
 * ========================================================================== */

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

/* ==========================================================================
 * Internal Function Declarations - Crypto
 * ========================================================================== */

/* Generate ephemeral P-384 key for ECDHE */
int wolfSPDM_GenerateEphemeralKey(WOLFSPDM_CTX* ctx);

/* Export ephemeral public key (X||Y) */
int wolfSPDM_ExportEphemeralPubKey(WOLFSPDM_CTX* ctx,
    byte* pubKeyX, word32* pubKeyXSz,
    byte* pubKeyY, word32* pubKeyYSz);

/* Compute ECDH shared secret from responder's public key */
int wolfSPDM_ComputeSharedSecret(WOLFSPDM_CTX* ctx,
    const byte* peerPubKeyX, const byte* peerPubKeyY);

/* Generate random bytes */
int wolfSPDM_GetRandom(WOLFSPDM_CTX* ctx, byte* out, word32 outSz);

/* Sign hash with requester's private key (for mutual auth FINISH) */
int wolfSPDM_SignHash(WOLFSPDM_CTX* ctx, const byte* hash, word32 hashSz,
    byte* sig, word32* sigSz);

/* ==========================================================================
 * Internal Function Declarations - Key Derivation
 * ========================================================================== */

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

/* ==========================================================================
 * Internal Function Declarations - Message Building
 * ========================================================================== */

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

/* ==========================================================================
 * Internal Function Declarations - Message Parsing
 * ========================================================================== */

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

/* ==========================================================================
 * Internal Function Declarations - Secured Messaging
 * ========================================================================== */

/* Encrypt plaintext using session keys */
int wolfSPDM_EncryptInternal(WOLFSPDM_CTX* ctx,
    const byte* plain, word32 plainSz,
    byte* enc, word32* encSz);

/* Decrypt ciphertext using session keys */
int wolfSPDM_DecryptInternal(WOLFSPDM_CTX* ctx,
    const byte* enc, word32 encSz,
    byte* plain, word32* plainSz);

/* ==========================================================================
 * Internal Utility Functions
 * ========================================================================== */

/* Send message via I/O callback and receive response */
int wolfSPDM_SendReceive(WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz);

/* Debug print (if enabled) */
void wolfSPDM_DebugPrint(WOLFSPDM_CTX* ctx, const char* fmt, ...);

/* Hex dump for debugging */
void wolfSPDM_DebugHex(WOLFSPDM_CTX* ctx, const char* label,
    const byte* data, word32 len);

/* ==========================================================================
 * Internal Function Declarations - Measurements
 * ========================================================================== */

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

/* ==========================================================================
 * Internal Function Declarations - Certificate Chain Validation
 * ========================================================================== */

/* Extract responder's public key from certificate chain leaf cert */
int wolfSPDM_ExtractResponderPubKey(WOLFSPDM_CTX* ctx);

/* Validate certificate chain using trusted CAs and extract public key */
int wolfSPDM_ValidateCertChain(WOLFSPDM_CTX* ctx);

/* ==========================================================================
 * Internal Function Declarations - Challenge
 * ========================================================================== */

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

/* ==========================================================================
 * Internal Function Declarations - Heartbeat
 * ========================================================================== */

/* Build HEARTBEAT request */
int wolfSPDM_BuildHeartbeat(WOLFSPDM_CTX* ctx, byte* buf, word32* bufSz);

/* Parse HEARTBEAT_ACK response */
int wolfSPDM_ParseHeartbeatAck(WOLFSPDM_CTX* ctx, const byte* buf,
    word32 bufSz);

/* ==========================================================================
 * Internal Function Declarations - Key Update
 * ========================================================================== */

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
