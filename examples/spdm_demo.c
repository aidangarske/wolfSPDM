/* spdm_demo.c
 *
 * wolfSPDM emulator demo - drives spdm-emu over TCP/MCTP for end-to-end
 * testing of session, measurements, challenge, heartbeat, and key update.
 *
 * Usage:
 *   spdm_demo --emu [--ver 1.2|1.3|1.4]
 *   spdm_demo --meas [--no-sig] [--ver ...]
 *   spdm_demo --challenge [--ver ...]
 *   spdm_demo --heartbeat [--ver ...]
 *   spdm_demo --key-update [--ver ...]
 *
 * Picks up the spdm-emu install dir from $SPDM_EMU_PATH (used to find the
 * ca.cert.der for --challenge).
 */

#include <wolfspdm/spdm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#ifdef __linux__
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#define HAS_SOCKET 1
#endif

#define EMU_HOST "127.0.0.1"
#define EMU_PORT 2323

#ifdef HAS_SOCKET

typedef struct {
    int sockFd;
} TCP_CTX;

static TCP_CTX g_tcpCtx = { -1 };

/* A secured SPDM record starts with the 4-byte session ID; a plain SPDM
 * message starts with a version byte. Look up the live session ID from
 * the wolfSPDM context: before KEY_EXCHANGE_RSP it's 0, after it matches
 * the first 4 bytes of every secured record. Robust against non-default
 * reqSessionId picks, unlike a buf[0] range check. */
static int is_secured_spdm(WOLFSPDM_CTX* ctx, const byte* buf, word32 sz)
{
    word32 sid;
    word32 b0;
    if (sz < 4) return 0;
    sid = wolfSPDM_GetSessionId(ctx);
    if (sid == 0) return 0;
    b0 = (word32)buf[0] | ((word32)buf[1] << 8) |
         ((word32)buf[2] << 16) | ((word32)buf[3] << 24);
    return b0 == sid;
}

/* MCTP transport I/O callback for spdm-emu (--trans MCTP, the default) */
static int tcp_io_callback(WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz,
    void* userCtx)
{
    TCP_CTX* tcpCtx = (TCP_CTX*)userCtx;
    byte sendBuf[4096];
    byte recvHdr[12];
    ssize_t sent, recvd;
    word32 payloadSz, respSize;

    if (tcpCtx == NULL || tcpCtx->sockFd < 0) {
        return -1;
    }

    /* Bound txSz first so the +1/+12 additions can't overflow word32. */
    if (txSz > sizeof(sendBuf) - 13) {
        return -1;
    }
    payloadSz = 1 + txSz;

    /* Socket header: command(4,BE) + transport_type(4,BE) + size(4,BE) */
    sendBuf[0] = 0x00; sendBuf[1] = 0x00; sendBuf[2] = 0x00; sendBuf[3] = 0x01;
    sendBuf[4] = 0x00; sendBuf[5] = 0x00; sendBuf[6] = 0x00; sendBuf[7] = 0x01;
    sendBuf[8]  = (byte)(payloadSz >> 24);
    sendBuf[9]  = (byte)(payloadSz >> 16);
    sendBuf[10] = (byte)(payloadSz >> 8);
    sendBuf[11] = (byte)(payloadSz & 0xFF);

    /* MCTP message type: 0x05 = SPDM, 0x06 = Secured SPDM. */
    sendBuf[12] = is_secured_spdm(ctx, txBuf, txSz) ? 0x06 : 0x05;

    if (txSz > 0) {
        memcpy(sendBuf + 13, txBuf, txSz);
    }

    sent = send(tcpCtx->sockFd, sendBuf, 12 + payloadSz, 0);
    if (sent != (ssize_t)(12 + payloadSz)) {
        return -1;
    }

    recvd = recv(tcpCtx->sockFd, recvHdr, 12, MSG_WAITALL);
    if (recvd != 12) return -1;

    respSize = ((word32)recvHdr[8] << 24) | ((word32)recvHdr[9] << 16) |
               ((word32)recvHdr[10] << 8) | (word32)recvHdr[11];

    if (respSize < 1 || respSize - 1 > *rxSz) {
        return -1;
    }

    /* Skip MCTP header byte */
    {
        byte mctpHdr;
        recvd = recv(tcpCtx->sockFd, &mctpHdr, 1, MSG_WAITALL);
        if (recvd != 1) return -1;
    }

    *rxSz = respSize - 1;
    if (*rxSz > 0) {
        recvd = recv(tcpCtx->sockFd, rxBuf, *rxSz, MSG_WAITALL);
        if (recvd != (ssize_t)*rxSz) return -1;
    }
    return 0;
}

static int tcp_connect(const char* host, int port)
{
    int sockFd;
    struct sockaddr_in addr;
    int optVal = 1;

    sockFd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockFd < 0) return -1;

    setsockopt(sockFd, IPPROTO_TCP, TCP_NODELAY, &optVal, sizeof(optVal));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        close(sockFd);
        return -1;
    }
    if (connect(sockFd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        close(sockFd);
        return -1;
    }
    g_tcpCtx.sockFd = sockFd;
    return 0;
}

static void tcp_disconnect(void)
{
    if (g_tcpCtx.sockFd >= 0) {
        close(g_tcpCtx.sockFd);
        g_tcpCtx.sockFd = -1;
    }
}

/* Load DER from file. Returns malloc'd buffer; caller frees. */
static byte* load_der(const char* path, word32* outSz)
{
    FILE* f = fopen(path, "rb");
    long sz;
    byte* buf;
    size_t r;

    if (f == NULL) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    sz = ftell(f);
    if (sz <= 0) { fclose(f); return NULL; }
    rewind(f);

    buf = (byte*)malloc((size_t)sz);
    if (buf == NULL) { fclose(f); return NULL; }

    r = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (r != (size_t)sz) { free(buf); return NULL; }

    *outSz = (word32)sz;
    return buf;
}

/* Static-mode buffer for the SPDM context; sized by the public header. */
static byte g_ctxBuf[WOLFSPDM_CTX_STATIC_SIZE];
#define CTX_BUF_SIZE ((int)sizeof(g_ctxBuf))

enum {
    MODE_SESSION = 1,   /* --emu */
    MODE_MEAS,          /* --meas */
    MODE_CHALLENGE,     /* --challenge */
    MODE_HEARTBEAT,     /* --heartbeat */
    MODE_KEY_UPDATE     /* --key-update */
};

static void usage(const char* argv0)
{
    fprintf(stderr,
        "Usage: %s {--emu|--meas|--challenge|--heartbeat|--key-update}\n"
        "          [--no-sig] [--ver 1.2|1.3|1.4]\n"
        "\n"
        "Env:\n"
        "  SPDM_EMU_PATH   path to spdm-emu build/bin/ (used for trusted CA\n"
        "                  lookup in --challenge mode)\n",
        argv0);
}

/* Map "1.2"/"1.3"/"1.4" -> 0x12/0x13/0x14. Returns 0 on parse error. */
static byte parse_version(const char* s)
{
    if (s == NULL) return 0;
    if (strcmp(s, "1.2") == 0) return SPDM_VERSION_12;
    if (strcmp(s, "1.3") == 0) return SPDM_VERSION_13;
    if (strcmp(s, "1.4") == 0) return SPDM_VERSION_14;
    return 0;
}

static int load_trusted_ca(WOLFSPDM_CTX* ctx)
{
    const char* emuPath = getenv("SPDM_EMU_PATH");
    char path[512];
    byte* der;
    word32 derSz;
    int rc;

    if (emuPath == NULL) {
        fprintf(stderr, "ERROR: SPDM_EMU_PATH not set; cannot locate "
            "ca.cert.der for --challenge\n");
        return -1;
    }
    snprintf(path, sizeof(path), "%s/ecp384/ca.cert.der", emuPath);

    der = load_der(path, &derSz);
    if (der == NULL) {
        fprintf(stderr, "ERROR: cannot read %s\n", path);
        return -1;
    }
    rc = wolfSPDM_SetTrustedCAs(ctx, der, derSz);
    free(der);
    if (rc != WOLFSPDM_SUCCESS) {
        fprintf(stderr, "ERROR: wolfSPDM_SetTrustedCAs: %s (%d)\n",
            wolfSPDM_GetErrorString(rc), rc);
        return -1;
    }
    return 0;
}

static int do_session(WOLFSPDM_CTX* ctx)
{
    int rc = wolfSPDM_Connect(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        fprintf(stderr, "wolfSPDM_Connect: %s (%d)\n",
            wolfSPDM_GetErrorString(rc), rc);
        return rc;
    }
    printf("Session established (id=0x%08x, version=0x%02x)\n",
        wolfSPDM_GetSessionId(ctx),
        wolfSPDM_GetNegotiatedVersion(ctx));
    return WOLFSPDM_SUCCESS;
}

static int do_meas(WOLFSPDM_CTX* ctx, int withSig)
{
    int rc;

    rc = do_session(ctx);
    if (rc != WOLFSPDM_SUCCESS) return rc;

    rc = wolfSPDM_GetMeasurements(ctx, SPDM_MEAS_OPERATION_ALL, withSig);
    if (withSig) {
        if (rc != WOLFSPDM_SUCCESS) {
            fprintf(stderr, "GetMeasurements (signed): %s (%d)\n",
                wolfSPDM_GetErrorString(rc), rc);
            return rc;
        }
        printf("Signed measurements verified (%d blocks)\n",
            wolfSPDM_GetMeasurementCount(ctx));
    }
    else {
        /* Unsigned: NOT_VERIFIED is the expected success return */
        if (rc != WOLFSPDM_SUCCESS && rc != WOLFSPDM_E_MEAS_NOT_VERIFIED) {
            fprintf(stderr, "GetMeasurements (unsigned): %s (%d)\n",
                wolfSPDM_GetErrorString(rc), rc);
            return rc;
        }
        printf("Unsigned measurements received (%d blocks)\n",
            wolfSPDM_GetMeasurementCount(ctx));
        rc = WOLFSPDM_SUCCESS;
    }
    return rc;
}

static int do_challenge(WOLFSPDM_CTX* ctx)
{
    int rc;

    /* Sessionless: walk through GET_VERSION -> CAPABILITIES -> ALGORITHMS ->
     * GET_DIGESTS -> GET_CERTIFICATE, then CHALLENGE. We don't call
     * wolfSPDM_Connect() because that does KEY_EXCHANGE + FINISH. */
    rc = wolfSPDM_GetVersion(ctx);
    if (rc != WOLFSPDM_SUCCESS) goto done;
    rc = wolfSPDM_GetCapabilities(ctx);
    if (rc != WOLFSPDM_SUCCESS) goto done;
    rc = wolfSPDM_NegotiateAlgorithms(ctx);
    if (rc != WOLFSPDM_SUCCESS) goto done;
    rc = wolfSPDM_GetDigests(ctx);
    if (rc != WOLFSPDM_SUCCESS) goto done;
    rc = wolfSPDM_GetCertificate(ctx, 0);
    if (rc != WOLFSPDM_SUCCESS) goto done;

    rc = load_trusted_ca(ctx);
    if (rc != 0) { rc = WOLFSPDM_E_INVALID_ARG; goto done; }

    /* wolfSPDM_Challenge internally validates the cert chain against the
     * loaded CAs when flags.hasTrustedCAs is set. */
    rc = wolfSPDM_Challenge(ctx, 0, SPDM_MEAS_SUMMARY_HASH_ALL);
    if (rc == WOLFSPDM_SUCCESS) {
        printf("Challenge succeeded (signature verified)\n");
    }
done:
    if (rc != WOLFSPDM_SUCCESS) {
        fprintf(stderr, "Challenge flow failed: %s (%d)\n",
            wolfSPDM_GetErrorString(rc), rc);
    }
    return rc;
}

static int do_heartbeat(WOLFSPDM_CTX* ctx)
{
    int rc = do_session(ctx);
    if (rc != WOLFSPDM_SUCCESS) return rc;
    rc = wolfSPDM_Heartbeat(ctx);
    if (rc == WOLFSPDM_SUCCESS) {
        printf("Heartbeat ACK received\n");
    }
    else {
        fprintf(stderr, "Heartbeat: %s (%d)\n",
            wolfSPDM_GetErrorString(rc), rc);
    }
    return rc;
}

static int do_key_update(WOLFSPDM_CTX* ctx)
{
    int rc = do_session(ctx);
    if (rc != WOLFSPDM_SUCCESS) return rc;
    rc = wolfSPDM_KeyUpdate(ctx, 1);  /* rotate both directions */
    if (rc == WOLFSPDM_SUCCESS) {
        printf("Key update succeeded\n");
    }
    else {
        fprintf(stderr, "KeyUpdate: %s (%d)\n",
            wolfSPDM_GetErrorString(rc), rc);
    }
    return rc;
}

int main(int argc, char* argv[])
{
    static const struct option longOpts[] = {
        { "emu",        no_argument,       0, 'e' },
        { "meas",       no_argument,       0, 'm' },
        { "no-sig",     no_argument,       0, 'n' },
        { "challenge",  no_argument,       0, 'c' },
        { "heartbeat",  no_argument,       0, 'b' },
        { "key-update", no_argument,       0, 'k' },
        { "ver",        required_argument, 0, 'v' },
        { "help",       no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };
    int mode = 0;
    int withSig = 1;
    byte maxVer = 0;
    int opt;
    int rc;
    WOLFSPDM_CTX* ctx = (WOLFSPDM_CTX*)g_ctxBuf;

    while ((opt = getopt_long(argc, argv, "emncbkv:h", longOpts, NULL)) != -1) {
        switch (opt) {
            case 'e': mode = MODE_SESSION; break;
            case 'm': mode = MODE_MEAS; break;
            case 'n': withSig = 0; break;
            case 'c': mode = MODE_CHALLENGE; break;
            case 'b': mode = MODE_HEARTBEAT; break;
            case 'k': mode = MODE_KEY_UPDATE; break;
            case 'v':
                maxVer = parse_version(optarg);
                if (maxVer == 0) {
                    fprintf(stderr, "Invalid --ver %s (expected 1.2/1.3/1.4)\n",
                        optarg);
                    return 1;
                }
                break;
            case 'h': usage(argv[0]); return 0;
            default:  usage(argv[0]); return 1;
        }
    }
    if (mode == 0) { usage(argv[0]); return 1; }

    if (wolfSPDM_GetCtxSize() > CTX_BUF_SIZE) {
        fprintf(stderr, "ERROR: CTX_BUF_SIZE too small (%d needed)\n",
            wolfSPDM_GetCtxSize());
        return 1;
    }

    if (tcp_connect(EMU_HOST, EMU_PORT) < 0) {
        fprintf(stderr, "ERROR: cannot connect to %s:%d (is spdm-emu running?)\n",
            EMU_HOST, EMU_PORT);
        return 1;
    }

    rc = wolfSPDM_InitStatic(ctx, CTX_BUF_SIZE);
    if (rc != WOLFSPDM_SUCCESS) {
        fprintf(stderr, "wolfSPDM_InitStatic: %s\n",
            wolfSPDM_GetErrorString(rc));
        tcp_disconnect();
        return 1;
    }

    wolfSPDM_SetIO(ctx, tcp_io_callback, &g_tcpCtx);

    if (maxVer != 0) {
        rc = wolfSPDM_SetMaxVersion(ctx, maxVer);
        if (rc != WOLFSPDM_SUCCESS) {
            fprintf(stderr, "wolfSPDM_SetMaxVersion: %s\n",
                wolfSPDM_GetErrorString(rc));
            goto done;
        }
    }

    switch (mode) {
        case MODE_SESSION:    rc = do_session(ctx);       break;
        case MODE_MEAS:       rc = do_meas(ctx, withSig); break;
        case MODE_CHALLENGE:  rc = do_challenge(ctx);     break;
        case MODE_HEARTBEAT:  rc = do_heartbeat(ctx);     break;
        case MODE_KEY_UPDATE: rc = do_key_update(ctx);    break;
        default: rc = -1; break;
    }

    if (rc == WOLFSPDM_SUCCESS && wolfSPDM_IsConnected(ctx)) {
        wolfSPDM_Disconnect(ctx);
    }

done:
    wolfSPDM_Free(ctx);
    tcp_disconnect();
    return (rc == WOLFSPDM_SUCCESS) ? 0 : 1;
}

#else  /* !HAS_SOCKET */
int main(void)
{
    fprintf(stderr, "spdm_demo: socket support unavailable on this platform\n");
    return 1;
}
#endif
