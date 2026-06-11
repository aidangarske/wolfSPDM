/* spdm_types.h
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

#ifndef WOLFSPDM_TYPES_H
#define WOLFSPDM_TYPES_H

/* wolfSSL options MUST be included first */
#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

/* Visibility: when built as part of wolfTPM, use WOLFTPM_API for export */
#ifdef BUILDING_WOLFTPM
    #include <wolftpm/visibility.h>
    #define WOLFSPDM_API WOLFTPM_API
#else
    #ifndef WOLFSPDM_API
    #define WOLFSPDM_API
    #endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Include wolfSSL types */
#ifndef WOLFSSL_TYPES
    #include <wolfssl/wolfcrypt/types.h>
#endif

/* ML-DSA (FIPS 204) support follows wolfSSL: auto-on when the linked wolfSSL
 * reports WOLFSSL_HAVE_MLDSA. Define WOLFSPDM_NO_MLDSA to force it off.
 * wolfSPDM's configure capability-tests for the wc_MlDsaKey context API and
 * defines WOLFSPDM_NO_MLDSA when only the legacy ML-DSA interface is present.
 * Non-autoconf consumers (e.g. wolfTPM embedding) linking a pre-context-API
 * wolfSSL that still reports WOLFSSL_HAVE_MLDSA must define WOLFSPDM_NO_MLDSA
 * themselves to avoid a compile break. */
#if defined(WOLFSSL_HAVE_MLDSA) && !defined(WOLFSPDM_NO_MLDSA)
    #ifndef WOLFSPDM_HAVE_MLDSA
        #define WOLFSPDM_HAVE_MLDSA
    #endif
#endif

/* --- SPDM Protocol Constants (DMTF DSP0274 / DSP0277) --- */

/* SPDM Version Numbers */
#define SPDM_VERSION_10             0x10    /* SPDM 1.0 (for GET_VERSION) */
#define SPDM_VERSION_11             0x11    /* SPDM 1.1 */
#define SPDM_VERSION_12             0x12    /* SPDM 1.2 */
#define SPDM_VERSION_13             0x13    /* SPDM 1.3 */
#define SPDM_VERSION_14             0x14    /* SPDM 1.4 */

/* SPDM Message Header Size */
#define SPDM_HEADER_SIZE            4       /* Version + Code + Param1 + Param2 */

/* SPDM Request Codes (sent by requester) */
#define SPDM_GET_VERSION            0x84
#define SPDM_GET_CAPABILITIES       0xE1
#define SPDM_NEGOTIATE_ALGORITHMS   0xE3
#define SPDM_GET_DIGESTS            0x81
#define SPDM_GET_CERTIFICATE        0x82
#define SPDM_CHALLENGE              0x83
#define SPDM_GET_MEASUREMENTS       0xE0
#define SPDM_KEY_EXCHANGE           0xE4
#define SPDM_FINISH                 0xE5
#define SPDM_PSK_EXCHANGE           0xE6
#define SPDM_PSK_FINISH             0xE7
#define SPDM_HEARTBEAT              0xE8
#define SPDM_KEY_UPDATE             0xE9
#ifndef SPDM_END_SESSION
#define SPDM_END_SESSION            0xEA
#endif
#define SPDM_CHUNK_SEND             0x85    /* Large request chunking (unused) */
#define SPDM_CHUNK_GET             0x86    /* Large response chunking (CHUNK_GET) */
#define SPDM_VENDOR_DEFINED         0xFF

/* SPDM Response Codes (sent by responder) */
#define SPDM_VERSION                0x04
#define SPDM_CAPABILITIES           0x61
#define SPDM_ALGORITHMS             0x63
#define SPDM_DIGESTS                0x01
#define SPDM_CERTIFICATE            0x02
#define SPDM_CHALLENGE_AUTH         0x03
#define SPDM_MEASUREMENTS           0x60
#define SPDM_KEY_EXCHANGE_RSP       0x64
#define SPDM_FINISH_RSP             0x65
#define SPDM_PSK_EXCHANGE_RSP       0x66
#define SPDM_PSK_FINISH_RSP         0x67
#define SPDM_HEARTBEAT_ACK          0x68
#define SPDM_KEY_UPDATE_ACK         0x69
#ifndef SPDM_END_SESSION_ACK
#define SPDM_END_SESSION_ACK        0x6A
#endif
#define SPDM_CHUNK_SEND_ACK         0x05    /* CHUNK_SEND response (unused) */
#define SPDM_CHUNK_RESPONSE         0x06    /* CHUNK_GET response (DSP0274 10.27.2) */
#define SPDM_VENDOR_DEFINED_RSP     0x7E
#define SPDM_ERROR                  0x7F

/* CHUNK_RESPONSE Param1 (Response Attributes) bit (DSP0274 Table 102) */
#define SPDM_CHUNK_LAST_CHUNK       0x01    /* This chunk is the last one */

/* SPDM Error Codes (in Param1 of ERROR response) */
#define SPDM_ERROR_INVALID_REQUEST      0x01
#define SPDM_ERROR_BUSY                 0x03
#define SPDM_ERROR_UNEXPECTED_REQUEST   0x04
#define SPDM_ERROR_UNSPECIFIED          0x05
#define SPDM_ERROR_DECRYPT_ERROR        0x06
#define SPDM_ERROR_UNSUPPORTED_REQUEST  0x07
#define SPDM_ERROR_REQUEST_IN_FLIGHT    0x08
#define SPDM_ERROR_INVALID_RESPONSE     0x09
#define SPDM_ERROR_SESSION_LIMIT        0x0A
#define SPDM_ERROR_SESSION_REQUIRED     0x0B
#define SPDM_ERROR_RESET_REQUIRED       0x0C
#define SPDM_ERROR_RESPONSE_TOO_LARGE   0x0D
#define SPDM_ERROR_REQUEST_TOO_LARGE    0x0E
#define SPDM_ERROR_LARGE_RESPONSE       0x0F
#define SPDM_ERROR_MSG_LOST             0x10
#define SPDM_ERROR_MAJOR_VERSION_MISMATCH 0x41
#define SPDM_ERROR_RESPONSE_NOT_READY   0x42
#define SPDM_ERROR_REQUEST_RESYNCH      0x43

/* --- Algorithm Set B (FIPS 140-3 Level 3 compliant) ---
 * This implementation ONLY supports Algorithm Set B for simplicity. */

/* Hash Algorithms */
#define SPDM_HASH_ALGO_SHA_384      0x00000002  /* TPM_ALG_SHA384 */

/* Asymmetric Signature Algorithms */
#define SPDM_ASYM_ALGO_ECDSA_P384   0x00000080  /* ECDSA-ECC_NIST_P384 */

/* PQC Asymmetric Signature Algorithms (DSP0274 1.4 Table 19 PqcAsymAlgo /
 * Table 20 PqcAsymSel). Byte 0 bit mask; one selected, mutually exclusive
 * with BaseAsymSel. */
#define SPDM_PQC_ASYM_ALGO_ML_DSA_44 0x00000001  /* ML-DSA-44, SigLen 2420 */
#define SPDM_PQC_ASYM_ALGO_ML_DSA_65 0x00000002  /* ML-DSA-65, SigLen 3309 */
#define SPDM_PQC_ASYM_ALGO_ML_DSA_87 0x00000004  /* ML-DSA-87, SigLen 4627 */

/* DHE (Diffie-Hellman Ephemeral) Algorithms */
#define SPDM_DHE_ALGO_SECP384R1     0x0010      /* secp384r1 */

/* AEAD Algorithms */
#define SPDM_AEAD_ALGO_AES_256_GCM  0x0002      /* AES-256-GCM */

/* Key Schedule (SPDM 1.2) */
#define SPDM_KEY_SCHEDULE_SPDM      0x0001      /* Standard SPDM key schedule */

/* ALGORITHMS AlgStruct AlgType values (DSP0274 Sec. 10.4 Table 16) */
#define SPDM_ALG_TYPE_DHE           2
#define SPDM_ALG_TYPE_AEAD          3
#define SPDM_ALG_TYPE_REQ_BASE_ASYM 4
#define SPDM_ALG_TYPE_KEY_SCHEDULE  5
#define SPDM_ALG_TYPE_REQ_PQC_ASYM  6  /* DSP0274 1.4 Table 21 ReqPqcAsymAlg */
#define SPDM_ALG_TYPE_KEM           7  /* DSP0274 1.4 KEM (ML-KEM) */

/* Which asymmetric family the responder selected (ctx->asymType) */
#define WOLFSPDM_ASYM_ECDSA         0  /* BaseAsymSel = ECDSA P-384 */
#define WOLFSPDM_ASYM_MLDSA         1  /* PqcAsymSel  = ML-DSA */

/* Algorithm Set B Fixed Parameters */
#define WOLFSPDM_HASH_SIZE          48  /* SHA-384 output size */
#define WOLFSPDM_ECC_KEY_SIZE       48  /* P-384 coordinate size */
#define WOLFSPDM_ECC_POINT_SIZE     (2 * WOLFSPDM_ECC_KEY_SIZE)  /* P-384 X||Y */
#define WOLFSPDM_ECC_SIG_SIZE       (2 * WOLFSPDM_ECC_KEY_SIZE)  /* ECDSA r||s */
#define WOLFSPDM_AEAD_KEY_SIZE      32  /* AES-256 key size */
#define WOLFSPDM_AEAD_IV_SIZE       12  /* AES-GCM IV size */
#define WOLFSPDM_AEAD_TAG_SIZE      16  /* AES-GCM tag size */
#define WOLFSPDM_HMAC_SIZE          48  /* HMAC-SHA384 output size */

#ifdef WOLFSPDM_HAVE_MLDSA
/* ML-DSA signature sizes (DSP0274 1.4 Table 19; FIPS 204). The largest sig we
 * may need to verify bounds receive/transcript buffers below. */
#define WOLFSPDM_MLDSA44_SIG_SIZE   2420
#define WOLFSPDM_MLDSA65_SIG_SIZE   3309
#define WOLFSPDM_MLDSA87_SIG_SIZE   4627
#define WOLFSPDM_MAX_SIG_SIZE       WOLFSPDM_MLDSA87_SIG_SIZE
#else
#define WOLFSPDM_MAX_SIG_SIZE       WOLFSPDM_ECC_SIG_SIZE
#endif

/* Receive-buffer size for the signature-bearing responses (KEY_EXCHANGE_RSP,
 * CHALLENGE_AUTH). Sized for fixed fields + a small OpaqueData block + the
 * negotiated SigLen + HMAC, NOT the full advertised DataTransferSize: like the
 * pre-ML-DSA design (4096 advertised vs a 384-byte buffer), this assumes real
 * responders keep OpaqueData in these two responses small. These are on-stack
 * buffers in wolfSPDM_KeyExchange / wolfSPDM_Challenge, so the ML-DSA value
 * (~5.3 KB) is the per-call stack cost on constrained targets. */
#ifdef WOLFSPDM_HAVE_MLDSA
#define WOLFSPDM_SIG_RSP_BUF        (640 + WOLFSPDM_MAX_SIG_SIZE)
#else
#define WOLFSPDM_SIG_RSP_BUF        512
#endif

/* --- Capability Flags (per DSP0274) --- */

/* Requester Capabilities (GET_CAPABILITIES flags) */
#define SPDM_CAP_CERT_CAP           0x00000002  /* Certificate support */
#define SPDM_CAP_CHAL_CAP           0x00000004  /* Challenge support */
#define SPDM_CAP_MEAS_CAP_NO_SIG    0x00000008  /* Measurements without sig */
#define SPDM_CAP_MEAS_CAP_SIG       0x00000010  /* Measurements with sig */
#define SPDM_CAP_MEAS_FRESH_CAP     0x00000020  /* Fresh measurements */
#define SPDM_CAP_ENCRYPT_CAP        0x00000040  /* Encryption support */
#define SPDM_CAP_MAC_CAP            0x00000080  /* MAC support */
#define SPDM_CAP_MUT_AUTH_CAP       0x00000100  /* Mutual auth support */
#define SPDM_CAP_KEY_EX_CAP         0x00000200  /* Key exchange support */
#define SPDM_CAP_PSK_CAP_NOHB       0x00000400  /* PSK without heartbeat */
#define SPDM_CAP_PSK_CAP_HB         0x00000800  /* PSK with heartbeat */
#define SPDM_CAP_ENCAP_CAP          0x00001000  /* Encapsulated request */
#define SPDM_CAP_HBEAT_CAP          0x00002000  /* Heartbeat support */
#define SPDM_CAP_KEY_UPD_CAP        0x00004000  /* Key update support */
#define SPDM_CAP_HANDSHAKE_ITC      0x00008000  /* Handshake in the clear */
#define SPDM_CAP_PUB_KEY_ID_CAP     0x00010000  /* Public key ID */
#define SPDM_CAP_CHUNK_CAP          0x00020000  /* Large SPDM message chunking */

/* Chunking (DSP0274 Sec. 10.27): CHUNK_GET reassembly of large responses.
 * Pure-wolfSPDM (no wolfSSL dependency), default on; WOLFSPDM_NO_CHUNK (or
 * --disable-chunking) compiles it out entirely. */
#if !defined(WOLFSPDM_NO_CHUNK) && !defined(WOLFSPDM_HAVE_CHUNK)
    #define WOLFSPDM_HAVE_CHUNK
#endif
#ifdef WOLFSPDM_HAVE_CHUNK
/* MTU: advertised DataTransferSize and size of the single reused transport
 * buffer. Lower it for constrained devices (smaller buffer, more round-trips). */
#ifndef WOLFSPDM_CHUNK_BUF_SIZE
#define WOLFSPDM_CHUNK_BUF_SIZE     4096
#endif
/* Must hold a CHUNK_RESPONSE header (16 B) plus useful payload. */
#if WOLFSPDM_CHUNK_BUF_SIZE < 64
#error "WOLFSPDM_CHUNK_BUF_SIZE must be at least 64"
#endif
/* Reassembly loop guard (max chunks per large message). */
#ifndef WOLFSPDM_CHUNK_MAX_CHUNKS
#define WOLFSPDM_CHUNK_MAX_CHUNKS   64
#endif
#define WOLFSPDM_CHUNK_CAP_BIT      SPDM_CAP_CHUNK_CAP
#else
#define WOLFSPDM_CHUNK_CAP_BIT      0
#endif

/* Default requester capabilities for Algorithm Set B session */
/* DSP0274 Table 11: CERT_CAP and CHAL_CAP are responder-only bits.
 * wolfSPDM is a pure requester and never serves certs or challenges, so
 * those bits are intentionally absent from the default. */
#define WOLFSPDM_DEFAULT_REQ_CAPS   (SPDM_CAP_ENCRYPT_CAP | SPDM_CAP_MAC_CAP | \
                                     SPDM_CAP_KEY_EX_CAP | SPDM_CAP_HBEAT_CAP | \
                                     SPDM_CAP_KEY_UPD_CAP | WOLFSPDM_CHUNK_CAP_BIT)

/* --- Buffer/Message Size Limits --- */

/* ML-DSA payloads (multi-KB sigs, pubkeys, cert chains) need larger buffers
 * than Algorithm Set B. Defaults grow when ML-DSA is built in so ML-DSA-65
 * fits a single message; all three are overridable with -D. ML-DSA-87 and
 * very large chains rely on the (future) chunking engine. */
#ifndef WOLFSPDM_MAX_MSG_SIZE
#ifdef WOLFSPDM_HAVE_MLDSA
#define WOLFSPDM_MAX_MSG_SIZE       8192    /* Maximum SPDM message size */
#else
#define WOLFSPDM_MAX_MSG_SIZE       4096
#endif
#endif
#ifndef WOLFSPDM_MAX_CERT_CHAIN
#ifdef WOLFSPDM_HAVE_MLDSA
/* A full ML-DSA-65 responder cert chain (spdm-emu) is ~16.8 KB; ML-DSA-87 and
 * alias chains run larger. 24 KB fits the common chains in one buffer. */
#define WOLFSPDM_MAX_CERT_CHAIN     24576   /* Maximum certificate chain size */
#else
#define WOLFSPDM_MAX_CERT_CHAIN     4096
#endif
#endif
/* trustedCAs holds a single root CA cert, not a full chain, so it stays small
 * even when ML-DSA grows the chain buffer. */
#ifndef WOLFSPDM_MAX_TRUSTED_CA
#ifdef WOLFSPDM_HAVE_MLDSA
#define WOLFSPDM_MAX_TRUSTED_CA     8192
#else
#define WOLFSPDM_MAX_TRUSTED_CA     4096
#endif
#endif
#ifndef WOLFSPDM_MAX_TRANSCRIPT
#ifdef WOLFSPDM_HAVE_MLDSA
#define WOLFSPDM_MAX_TRANSCRIPT     16384   /* Maximum transcript buffer */
#else
#define WOLFSPDM_MAX_TRANSCRIPT     4096
#endif
#endif
#define WOLFSPDM_RANDOM_SIZE        32      /* Random data in KEY_EXCHANGE */

/* --- MCTP Transport Constants (for TCP/socket transport) --- */

#define MCTP_MESSAGE_TYPE_SPDM      0x05    /* SPDM over MCTP */
#define MCTP_MESSAGE_TYPE_SECURED   0x06    /* Secured SPDM over MCTP */

/* Socket protocol for libspdm emulator */
#ifndef SOCKET_TRANSPORT_TYPE_MCTP
#define SOCKET_TRANSPORT_TYPE_MCTP  0x00000001
#endif
#ifndef SOCKET_TRANSPORT_TYPE_TCP
#define SOCKET_TRANSPORT_TYPE_TCP   0x00000003
#endif
#ifndef SOCKET_SPDM_COMMAND_NORMAL
#define SOCKET_SPDM_COMMAND_NORMAL  0x00000001
#endif

#ifndef NO_WOLFSPDM_MEAS
/* --- Measurement Constants (DSP0274 Section 10.11) --- */

/* MeasurementSummaryHashType (Param1 of GET_MEASUREMENTS) */
#define SPDM_MEAS_SUMMARY_HASH_NONE     0x00
#define SPDM_MEAS_SUMMARY_HASH_TCB      0x01
#define SPDM_MEAS_SUMMARY_HASH_ALL      0xFF

/* MeasurementOperation (Param2 of GET_MEASUREMENTS) */
#define SPDM_MEAS_OPERATION_TOTAL_NUMBER 0x00
#define SPDM_MEAS_OPERATION_ALL          0xFF

/* Request signature bit in Param1 */
#define SPDM_MEAS_REQUEST_SIG_BIT       0x01

/* DMTFSpecMeasurementValueType (DSP0274 Table 22) */
#define SPDM_MEAS_VALUE_TYPE_IMMUTABLE_ROM   0x00
#define SPDM_MEAS_VALUE_TYPE_MUTABLE_FW      0x01
#define SPDM_MEAS_VALUE_TYPE_HW_CONFIG       0x02
#define SPDM_MEAS_VALUE_TYPE_FW_CONFIG       0x03
#define SPDM_MEAS_VALUE_TYPE_MEAS_MANIFEST   0x04
#define SPDM_MEAS_VALUE_TYPE_VERSION         0x05
#define SPDM_MEAS_VALUE_TYPE_RAW_BIT         0x80  /* Bit 7: raw vs digest */

/* Configurable limits (override with -D at compile time) */
#ifndef WOLFSPDM_MAX_MEAS_BLOCKS
#define WOLFSPDM_MAX_MEAS_BLOCKS        16
#endif
#ifndef WOLFSPDM_MAX_MEAS_VALUE_SIZE
#define WOLFSPDM_MAX_MEAS_VALUE_SIZE    64  /* Fits SHA-512; SHA-384 uses 48 */
#endif

#define WOLFSPDM_MEAS_BLOCK_HDR_SIZE    4   /* Index(1) + MeasSpec(1) + Size(2 LE) */
#endif /* !NO_WOLFSPDM_MEAS */

/* --- Key Derivation Labels (SPDM 1.2 per DSP0277) --- */

#define SPDM_BIN_CONCAT_PREFIX_12   "spdm1.2 "
#define SPDM_BIN_CONCAT_PREFIX_13   "spdm1.3 "
#define SPDM_BIN_CONCAT_PREFIX_14   "spdm1.4 "
#define SPDM_BIN_CONCAT_PREFIX_LEN  8

#define SPDM_LABEL_REQ_HS_DATA      "req hs data"
#define SPDM_LABEL_RSP_HS_DATA      "rsp hs data"
#define SPDM_LABEL_REQ_DATA         "req app data"
#define SPDM_LABEL_RSP_DATA         "rsp app data"
#define SPDM_LABEL_FINISHED         "finished"
#define SPDM_LABEL_KEY              "key"
#define SPDM_LABEL_IV               "iv"
#define SPDM_LABEL_UPDATE           "traffic upd"

/* KEY_UPDATE Operations (DSP0274 Section 10.9) */
#define SPDM_KEY_UPDATE_OP_UPDATE_KEY      1
#define SPDM_KEY_UPDATE_OP_UPDATE_ALL_KEYS 2
#define SPDM_KEY_UPDATE_OP_VERIFY_NEW_KEY  3

#ifdef __cplusplus
}
#endif

#endif /* WOLFSPDM_TYPES_H */
