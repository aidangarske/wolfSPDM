/* spdm.h
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

#ifndef WOLFSPDM_SPDM_H
#define WOLFSPDM_SPDM_H

/* Include build options (WOLFSPDM_DYNAMIC_MEMORY, etc.)
 * Generated from config.h during build; installed alongside this header. */
#ifndef HAVE_CONFIG_H
    #include <wolfspdm/options.h>
#endif

#include <wolfspdm/spdm_types.h>
#include <wolfspdm/spdm_error.h>

/* Feature detection macros - external projects (e.g. wolfTPM) can check these
 * to conditionally compile against optional wolfSPDM APIs. */
#ifndef NO_WOLFSPDM_MEAS
#define WOLFSPDM_HAS_MEASUREMENTS
#endif
#ifndef NO_WOLFSPDM_CHALLENGE
#define WOLFSPDM_HAS_CHALLENGE
#endif
#define WOLFSPDM_HAS_HEARTBEAT
#define WOLFSPDM_HAS_KEY_UPDATE

#ifdef __cplusplus
extern "C" {
#endif

/* wolfSPDM implements the standard SPDM 1.2+ protocol per DMTF DSP0274/DSP0277.
 * Flow: GET_VERSION -> GET_CAPABILITIES -> NEGOTIATE_ALGORITHMS ->
 *       GET_DIGESTS -> GET_CERTIFICATE -> KEY_EXCHANGE -> FINISH
 * Use with: libspdm emulator, standard SPDM responders */

/* --- wolfSPDM Overview ---
 *
 * wolfSPDM is a lightweight SPDM (Security Protocol and Data Model)
 * implementation using wolfCrypt for all cryptographic operations.
 *
 * Key Features:
 *   - Requester-only (initiator) implementation
 *   - Algorithm Set B fixed: P-384/SHA-384/AES-256-GCM
 *   - Full transcript tracking for proper TH1/TH2 computation
 *   - Supports SPDM 1.2, 1.3, and 1.4
 *   - Compatible with libspdm emulator for testing
 *   - No external dependencies beyond wolfCrypt
 *
 * Typical Usage:
 *
 *   Static (default, zero-malloc):
 *     WOLFSPDM_CTX ctx;
 *     wolfSPDM_Init(&ctx);
 *     wolfSPDM_SetIO(&ctx, callback, userPtr);
 *     wolfSPDM_Connect(&ctx);
 *     wolfSPDM_SecuredExchange(&ctx, ...);
 *     wolfSPDM_Disconnect(&ctx);
 *     wolfSPDM_Free(&ctx);
 *
 *   Dynamic (opt-in, requires --enable-dynamic-mem):
 *     ctx = wolfSPDM_New();       // Allocates and fully initializes
 *     wolfSPDM_SetIO(ctx, callback, userPtr);
 *     wolfSPDM_Connect(ctx);
 *     wolfSPDM_SecuredExchange(ctx, ...);
 *     wolfSPDM_Disconnect(ctx);
 *     wolfSPDM_Free(ctx);         // Frees the allocation
 *
 *   Note: WOLFSPDM_CTX is approximately 22KB. On embedded systems with
 *   small stacks, declare it as a static global rather than a local variable. */

/* Compile-time size for static allocation of WOLFSPDM_CTX.
 * Use this when you need a buffer large enough to hold WOLFSPDM_CTX
 * without access to the struct definition (e.g., in wolfTPM).
 * Classical (Algorithm Set B) struct size: ~31.3 KB, rounded to 32 KB.
 * With ML-DSA the larger PQC buffers (sigs, cert chains) and the ML-DSA verify
 * key push it to ~67 KB, rounded to 72 KB. wolfSPDM_InitStatic() verifies at
 * runtime that the provided buffer is large enough (WOLFSPDM_E_BUFFER_SMALL);
 * a compile-time _Static_assert in spdm_context.c also guards this value. */
#ifdef WOLFSPDM_HAVE_MLDSA
#define WOLFSPDM_CTX_STATIC_SIZE  73728  /* 72KB - fits CTX with ML-DSA buffers */
#else
#define WOLFSPDM_CTX_STATIC_SIZE  32768  /* 32KB - fits CTX with cert validation + challenge + key update fields */
#endif

/* Forward declaration */
struct WOLFSPDM_CTX;
typedef struct WOLFSPDM_CTX WOLFSPDM_CTX;

/* --- I/O Callback ---
 *
 * The I/O callback is called by wolfSPDM to send and receive raw SPDM
 * messages. The transport layer (SPI, I2C, TCP, etc.) is handled externally.
 *
 * Parameters:
 *   ctx      - wolfSPDM context
 *   txBuf    - Data to transmit (raw SPDM message, no transport headers)
 *   txSz     - Size of transmit data
 *   rxBuf    - Buffer to receive response
 *   rxSz     - [in] Size of receive buffer, [out] Actual received size
 *   userCtx  - User context pointer from wolfSPDM_SetIO()
 *
 * Returns:
 *   0 on success, negative on error
 *
 * Notes:
 *   - For MCTP transport, the callback should handle MCTP encapsulation
 *   - For secured messages (after KEY_EXCHANGE), the callback receives
 *     already-encrypted data including the session header */
typedef int (*WOLFSPDM_IO_CB)(
    WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz,
    void* userCtx
);

/* --- Context Management --- */

/**
 * Initialize a wolfSPDM context for use.
 * Zeroes the context and initializes all internal state.
 * Works on stack, static, or dynamically-allocated contexts.
 * Must be called before wolfSPDM_Connect().
 *
 * Call wolfSPDM_Free() before re-initializing to avoid leaking the RNG.
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_Init(WOLFSPDM_CTX* ctx);

#ifdef WOLFSPDM_DYNAMIC_MEMORY
/**
 * Allocate and fully initialize a new wolfSPDM context.
 * No separate wolfSPDM_Init() call needed.
 * Requires --enable-dynamic-mem at configure time.
 *
 * @return Pointer to new context, or NULL on failure.
 */
WOLFSPDM_API WOLFSPDM_CTX* wolfSPDM_New(void);
#endif

/**
 * Free a wolfSPDM context and all associated resources.
 * Safe for both stack-allocated and dynamically-allocated contexts.
 * Zeroes all sensitive key material before returning.
 *
 * @param ctx  The wolfSPDM context to free.
 */
WOLFSPDM_API void wolfSPDM_Free(WOLFSPDM_CTX* ctx);

/**
 * Get the size of the WOLFSPDM_CTX structure.
 * Useful for static allocation.
 *
 * @return Size in bytes.
 */
WOLFSPDM_API int wolfSPDM_GetCtxSize(void);

/**
 * Initialize a statically-allocated context with size check.
 * Verifies the buffer is large enough, then calls wolfSPDM_Init().
 *
 * @param ctx   Pointer to pre-allocated memory of at least wolfSPDM_GetCtxSize().
 * @param size  Size of the provided buffer.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_InitStatic(WOLFSPDM_CTX* ctx, int size);

/* --- Configuration --- */

/**
 * Set the I/O callback for sending/receiving SPDM messages.
 *
 * @param ctx      The wolfSPDM context.
 * @param ioCb     The I/O callback function.
 * @param userCtx  User context pointer passed to callback.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_SetIO(WOLFSPDM_CTX* ctx, WOLFSPDM_IO_CB ioCb, void* userCtx);

/**
 * Set the maximum SPDM version to negotiate.
 * Caps the version selected during GET_VERSION exchange.
 * Must be called before wolfSPDM_Connect().
 *
 * @param ctx         The wolfSPDM context.
 * @param maxVersion  Maximum version (e.g., SPDM_VERSION_12, SPDM_VERSION_14).
 *                    Must be in range 0x12-0x14. Use 0 to reset to compile-time default.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_SetMaxVersion(WOLFSPDM_CTX* ctx, byte maxVersion);

/**
 * Pin the requester session ID used during KEY_EXCHANGE.
 * Default behavior is to draw a random non-reserved value during Connect().
 * Use this only for deterministic test setups; the reserved values 0x0000
 * and 0xFFFF are rejected.
 *
 * @param ctx           The wolfSPDM context.
 * @param reqSessionId  Caller-chosen ReqSessionID (1..0xFFFE).
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_SetRequesterSessionId(WOLFSPDM_CTX* ctx,
    word16 reqSessionId);

/**
 * Opt in to operating without a configured trust anchor.
 * Without this call (and without wolfSPDM_SetTrustedCAs), wolfSPDM_Connect
 * refuses to complete the handshake against an unauthenticated responder
 * certificate chain. Intended for emulator / development use only.
 *
 * @param ctx   The wolfSPDM context.
 * @param allow Non-zero to permit handshakes without a trust anchor.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_AllowUntrustedCerts(WOLFSPDM_CTX* ctx, int allow);

/* --- Session Establishment --- */

/**
 * Establish an SPDM session (full handshake).
 * Performs: GET_VERSION -> GET_CAPABILITIES -> NEGOTIATE_ALGORITHMS ->
 *           GET_DIGESTS -> GET_CERTIFICATE -> KEY_EXCHANGE -> FINISH
 *
 * After successful completion, use wolfSPDM_SecuredExchange() for
 * encrypted communication.
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_Connect(WOLFSPDM_CTX* ctx);

/**
 * Check if an SPDM session is established.
 *
 * @param ctx  The wolfSPDM context.
 * @return 1 if connected, 0 if not.
 */
WOLFSPDM_API int wolfSPDM_IsConnected(WOLFSPDM_CTX* ctx);

/**
 * End the SPDM session gracefully.
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_Disconnect(WOLFSPDM_CTX* ctx);

/* --- Individual Handshake Steps (for fine-grained control) --- */

/**
 * Send GET_VERSION and receive VERSION response.
 * First step in SPDM handshake (VCA part 1).
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_GetVersion(WOLFSPDM_CTX* ctx);

/**
 * Send GET_CAPABILITIES and receive CAPABILITIES response.
 * Second step in SPDM handshake (VCA part 2).
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_GetCapabilities(WOLFSPDM_CTX* ctx);

/**
 * Send NEGOTIATE_ALGORITHMS and receive ALGORITHMS response.
 * Third step in SPDM handshake (VCA part 3).
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_NegotiateAlgorithms(WOLFSPDM_CTX* ctx);

/**
 * Send GET_DIGESTS and receive DIGESTS response.
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_GetDigests(WOLFSPDM_CTX* ctx);

/**
 * Send GET_CERTIFICATE and receive full certificate chain.
 * May require multiple requests for large chains.
 *
 * @param ctx     The wolfSPDM context.
 * @param slotId  Certificate slot (0-7, typically 0).
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_GetCertificate(WOLFSPDM_CTX* ctx, int slotId);

/**
 * Send KEY_EXCHANGE and receive KEY_EXCHANGE_RSP.
 * Performs ECDHE key exchange and derives handshake keys.
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_KeyExchange(WOLFSPDM_CTX* ctx);

/**
 * Send FINISH and receive FINISH_RSP (encrypted).
 * Completes the handshake and establishes the secure session.
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_Finish(WOLFSPDM_CTX* ctx);

/* --- Secured Messaging --- */

#ifndef WOLFSPDM_LEAN
/**
 * Encrypt a message for sending over the established session.
 *
 * @param ctx       The wolfSPDM context.
 * @param plain     Plaintext message to encrypt.
 * @param plainSz   Size of plaintext.
 * @param enc       Buffer for encrypted output (includes header and tag).
 * @param encSz     [in] Size of enc buffer, [out] Actual encrypted size.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_EncryptMessage(WOLFSPDM_CTX* ctx,
    const byte* plain, word32 plainSz,
    byte* enc, word32* encSz);

/**
 * Decrypt a message received over the established session.
 *
 * @param ctx       The wolfSPDM context.
 * @param enc       Encrypted message (includes header and tag).
 * @param encSz     Size of encrypted message.
 * @param plain     Buffer for decrypted output.
 * @param plainSz   [in] Size of plain buffer, [out] Actual decrypted size.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_DecryptMessage(WOLFSPDM_CTX* ctx,
    const byte* enc, word32 encSz,
    byte* plain, word32* plainSz);
#endif /* !WOLFSPDM_LEAN */

/**
 * Perform a secured message exchange (encrypt, send, receive, decrypt).
 * Convenience function combining encrypt, I/O, and decrypt.
 *
 * @param ctx         The wolfSPDM context.
 * @param cmdPlain    Plaintext command to send.
 * @param cmdSz       Size of command.
 * @param rspPlain    Buffer for plaintext response.
 * @param rspSz       [in] Size of response buffer, [out] Actual response size.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_SecuredExchange(WOLFSPDM_CTX* ctx,
    const byte* cmdPlain, word32 cmdSz,
    byte* rspPlain, word32* rspSz);

#ifndef NO_WOLFSPDM_MEAS
/* --- Measurements (Device Attestation) ---
 *
 * When requestSignature=1 (and NO_WOLFSPDM_MEAS_VERIFY is NOT defined):
 *   Retrieves measurements with a cryptographic signature from the responder,
 *   then verifies the signature using the responder's certificate (retrieved
 *   during wolfSPDM_Connect). Returns WOLFSPDM_SUCCESS if verification passes.
 *   Returns WOLFSPDM_E_MEAS_SIG_FAIL if the signature is invalid.
 *
 * When requestSignature=0:
 *   Retrieves measurements WITHOUT a signature. Returns WOLFSPDM_SUCCESS on
 *   retrieval; the call is treated as informational only and the blocks
 *   must not be used for security-critical decisions.
 *
 * If compiled with NO_WOLFSPDM_MEAS_VERIFY, signature verification is
 * unavailable. In that build a signed request (requestSignature=1) returns
 * WOLFSPDM_E_MEAS_NOT_VERIFIED (the signature bytes are still captured in
 * the context); unsigned requests still return WOLFSPDM_SUCCESS.
 *
 * Contexts are NOT thread-safe; do not call from multiple threads. */

/**
 * Retrieve measurements from the SPDM responder.
 *
 * @param ctx               The wolfSPDM context.
 * @param measOperation     SPDM_MEAS_OPERATION_ALL (0xFF) or specific index.
 * @param requestSignature  1 to request signed measurements, 0 for unsigned.
 * @return WOLFSPDM_SUCCESS on retrieval (unsigned) or successful signature
 *         verification (signed). WOLFSPDM_E_MEAS_SIG_FAIL when a signed
 *         response fails verification. WOLFSPDM_E_MEAS_NOT_VERIFIED only
 *         when a signed request is made in a build without verification
 *         support. Other negative error codes on protocol/transport errors.
 */
WOLFSPDM_API int wolfSPDM_GetMeasurements(WOLFSPDM_CTX* ctx, byte measOperation,
    int requestSignature);

/**
 * Get the number of measurement blocks retrieved.
 *
 * @param ctx  The wolfSPDM context.
 * @return Number of measurement blocks, or 0 if none.
 */
WOLFSPDM_API int wolfSPDM_GetMeasurementCount(WOLFSPDM_CTX* ctx);

/**
 * Get a specific measurement block by index.
 *
 * @param ctx        The wolfSPDM context.
 * @param blockIdx   Index into retrieved blocks (0-based).
 * @param measIndex  [out] SPDM measurement index (1-based).
 * @param measType   [out] DMTFSpecMeasurementValueType.
 * @param value      [out] Buffer for measurement value.
 * @param valueSz    [in] Size of value buffer, [out] Actual value size.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_GetMeasurementBlock(WOLFSPDM_CTX* ctx, int blockIdx,
    byte* measIndex, byte* measType, byte* value, word32* valueSz);
#endif /* !NO_WOLFSPDM_MEAS */

#ifndef WOLFSPDM_LEAN
/* --- Application Data Transfer ---
 *
 * Send/receive application data over an established SPDM session.
 * Max payload per call: WOLFSPDM_MAX_MSG_SIZE minus AEAD overhead (~4000 bytes).
 * These are message-oriented (no partial reads/writes).
 * Contexts are NOT thread-safe; do not call from multiple threads. */

/**
 * Send application data over an established SPDM session.
 *
 * @param ctx     The wolfSPDM context (must be connected).
 * @param data    Data to send.
 * @param dataSz  Size of data.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_SendData(WOLFSPDM_CTX* ctx, const byte* data, word32 dataSz);

/**
 * Receive application data over an established SPDM session.
 *
 * @param ctx     The wolfSPDM context (must be connected).
 * @param data    Buffer for received data.
 * @param dataSz  [in] Size of buffer, [out] Actual data size.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_ReceiveData(WOLFSPDM_CTX* ctx, byte* data, word32* dataSz);
#endif /* !WOLFSPDM_LEAN */

/* --- Session Information --- */

/**
 * Get the current session ID.
 *
 * The session ID is allocated by KEY_EXCHANGE_RSP and remains valid for
 * the rest of the handshake (FINISH) and the application phase. This
 * returns the value as soon as KEY_EXCHANGE_RSP sets it, not only after
 * wolfSPDM_IsConnected() goes true - I/O callbacks need it between
 * KEY_EXCHANGE and FINISH to distinguish secured records.
 *
 * NOTE: a non-zero return does NOT imply the session is established. Use
 * wolfSPDM_IsConnected() to test for completion of the handshake.
 *
 * @param ctx  The wolfSPDM context.
 * @return Session ID (combined reqSessionId | rspSessionId << 16), or 0
 *         before KEY_EXCHANGE_RSP has run, or after the handshake errored.
 */
WOLFSPDM_API word32 wolfSPDM_GetSessionId(WOLFSPDM_CTX* ctx);

/**
 * Get negotiated SPDM version.
 *
 * @param ctx  The wolfSPDM context.
 * @return Version (e.g., 0x12 for SPDM 1.2), or 0 if not negotiated.
 */
WOLFSPDM_API byte wolfSPDM_GetNegotiatedVersion(WOLFSPDM_CTX* ctx);

/**
 * Get the responder's last SPDM_ERROR code (Param1).
 *
 * Set by APIs that receive an SPDM_ERROR response from the responder
 * (e.g. wolfSPDM_GetMeasurements returning WOLFSPDM_E_PEER_ERROR).
 * Callers can branch on this code to back off on BUSY, abort on
 * UNSUPPORTED_REQUEST, retry on REQUEST_RESYNCH, etc.
 *
 * @param ctx  The wolfSPDM context.
 * @return Last responder error code, or 0 if none has been received.
 */
WOLFSPDM_API byte wolfSPDM_GetLastPeerError(WOLFSPDM_CTX* ctx);

/* Backwards-compat for the original spelling. Exported as a real symbol
 * so binaries previously linked against the old name keep loading. New
 * code should use wolfSPDM_GetNegotiatedVersion directly. */
WOLFSPDM_API byte wolfSPDM_GetVersion_Negotiated(WOLFSPDM_CTX* ctx);

/* --- Certificate Chain Validation --- */

/**
 * Load the trusted root CA certificate for certificate chain validation.
 * When set, wolfSPDM_Connect() / wolfSPDM_Challenge() will validate the
 * responder's certificate chain by comparing SHA-384 of the supplied
 * cert against the chain's RootHash. Only a single CA cert is supported
 * - the buffer is hashed as one DER blob, not parsed as a list.
 * Without this, only the public key is extracted (no chain anchor).
 *
 * @param ctx         The wolfSPDM context.
 * @param derCerts    DER-encoded CA certificate (single cert, not a chain).
 * @param derCertsSz  Size of DER certificate data.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_SetTrustedCAs(WOLFSPDM_CTX* ctx, const byte* derCerts,
    word32 derCertsSz);

#ifndef NO_WOLFSPDM_CHALLENGE
/* --- Challenge Authentication (Sessionless Attestation) --- */

/**
 * Perform CHALLENGE/CHALLENGE_AUTH exchange for sessionless attestation.
 * Requires state >= WOLFSPDM_STATE_CERT (cert chain must be retrieved).
 * Typical flow: GET_VERSION -> GET_CAPS -> NEGOTIATE_ALGO -> GET_DIGESTS
 *   -> GET_CERTIFICATE -> CHALLENGE
 *
 * @param ctx            The wolfSPDM context.
 * @param slotId         Certificate slot (0-7, typically 0).
 * @param measHashType   Measurement summary hash type:
 *                       SPDM_MEAS_SUMMARY_HASH_NONE (0x00),
 *                       SPDM_MEAS_SUMMARY_HASH_TCB (0x01), or
 *                       SPDM_MEAS_SUMMARY_HASH_ALL (0xFF).
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_Challenge(WOLFSPDM_CTX* ctx, int slotId, byte measHashType);
#endif /* !NO_WOLFSPDM_CHALLENGE */

/* --- Session Keep-Alive --- */

/**
 * Send HEARTBEAT and receive HEARTBEAT_ACK.
 * Must be in an established session (CONNECTED or MEASURED state).
 * Sent over the encrypted channel.
 *
 * @param ctx  The wolfSPDM context.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_Heartbeat(WOLFSPDM_CTX* ctx);

/* --- Key Update (Session Key Rotation) --- */

/**
 * Perform KEY_UPDATE to rotate session encryption keys.
 * Must be in an established session (CONNECTED or MEASURED state).
 * Follows up with VERIFY_NEW_KEY to confirm the new keys work.
 *
 * @param ctx        The wolfSPDM context.
 * @param updateAll  0 = rotate requester key only,
 *                   1 = rotate both requester and responder keys.
 * @return WOLFSPDM_SUCCESS or negative error code.
 */
WOLFSPDM_API int wolfSPDM_KeyUpdate(WOLFSPDM_CTX* ctx, int updateAll);

/* --- Debug/Utility --- */

/**
 * Enable or disable debug output.
 *
 * @param ctx    The wolfSPDM context.
 * @param enable Non-zero to enable, 0 to disable.
 */
WOLFSPDM_API void wolfSPDM_SetDebug(WOLFSPDM_CTX* ctx, int enable);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSPDM_SPDM_H */
