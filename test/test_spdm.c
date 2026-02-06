/* test_spdm.c
 *
 * Basic test for wolfSPDM library.
 * Tests against libspdm emulator (spdm_responder_emu --trans TCP)
 */

#include <wolfspdm/spdm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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
    int isSecured;
} TCP_CTX;

static TCP_CTX g_tcpCtx = { -1, 0 };

/* MCTP transport I/O callback for libspdm emulator */
static int tcp_io_callback(WOLFSPDM_CTX* ctx,
    const byte* txBuf, word32 txSz,
    byte* rxBuf, word32* rxSz,
    void* userCtx)
{
    TCP_CTX* tcpCtx = (TCP_CTX*)userCtx;
    byte sendBuf[512];
    byte recvHdr[12];
    ssize_t sent, recvd;
    word32 payloadSz, respSize;

    (void)ctx;

    if (tcpCtx == NULL || tcpCtx->sockFd < 0) {
        return -1;
    }

    /* Payload = MCTP header (1) + SPDM message */
    payloadSz = 1 + txSz;

    if (12 + payloadSz > sizeof(sendBuf)) {
        return -1;
    }

    /* Socket header: command(4,BE) + transport_type(4,BE) + size(4,BE) */
    sendBuf[0] = 0x00; sendBuf[1] = 0x00; sendBuf[2] = 0x00; sendBuf[3] = 0x01;
    sendBuf[4] = 0x00; sendBuf[5] = 0x00; sendBuf[6] = 0x00; sendBuf[7] = 0x01;
    sendBuf[8] = (byte)(payloadSz >> 24);
    sendBuf[9] = (byte)(payloadSz >> 16);
    sendBuf[10] = (byte)(payloadSz >> 8);
    sendBuf[11] = (byte)(payloadSz & 0xFF);

    /* MCTP header */
    sendBuf[12] = tcpCtx->isSecured ? 0x06 : 0x05;

    if (txSz > 0) {
        memcpy(sendBuf + 13, txBuf, txSz);
    }

    sent = send(tcpCtx->sockFd, sendBuf, 12 + payloadSz, 0);
    if (sent != (ssize_t)(12 + payloadSz)) {
        return -1;
    }

    recvd = recv(tcpCtx->sockFd, recvHdr, 12, MSG_WAITALL);
    if (recvd != 12) {
        return -1;
    }

    respSize = ((word32)recvHdr[8] << 24) | ((word32)recvHdr[9] << 16) |
               ((word32)recvHdr[10] << 8) | (word32)recvHdr[11];

    if (respSize < 1 || respSize - 1 > *rxSz) {
        return -1;
    }

    /* Skip MCTP header */
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

int main(int argc, char* argv[])
{
    WOLFSPDM_CTX* ctx;
    int rc;

    (void)argc;
    (void)argv;

    printf("wolfSPDM Test - Connecting to %s:%d\n", EMU_HOST, EMU_PORT);

    if (tcp_connect(EMU_HOST, EMU_PORT) < 0) {
        printf("ERROR: Cannot connect to emulator.\n");
        printf("Start the emulator first:\n");
        printf("  ./spdm_responder_emu --trans TCP\n");
        return 1;
    }

    ctx = wolfSPDM_New();
    if (ctx == NULL) {
        printf("ERROR: wolfSPDM_New failed\n");
        tcp_disconnect();
        return 1;
    }

    rc = wolfSPDM_Init(ctx);
    if (rc != WOLFSPDM_SUCCESS) {
        printf("ERROR: wolfSPDM_Init failed: %s\n", wolfSPDM_GetErrorString(rc));
        wolfSPDM_Free(ctx);
        tcp_disconnect();
        return 1;
    }

    wolfSPDM_SetDebug(ctx, 1);
    wolfSPDM_SetIO(ctx, tcp_io_callback, &g_tcpCtx);

    printf("\nEstablishing SPDM session...\n\n");
    rc = wolfSPDM_Connect(ctx);

    if (rc == WOLFSPDM_SUCCESS) {
        printf("\n===========================================\n");
        printf(" SUCCESS: SPDM Session Established!\n");
        printf(" SessionID: 0x%08x\n", wolfSPDM_GetSessionId(ctx));
        printf("===========================================\n");
    } else {
        printf("\nERROR: wolfSPDM_Connect failed: %s (%d)\n",
            wolfSPDM_GetErrorString(rc), rc);
    }

    wolfSPDM_Free(ctx);
    tcp_disconnect();

    return (rc == WOLFSPDM_SUCCESS) ? 0 : 1;
}
#else
int main(void)
{
    printf("Socket support not available\n");
    return 1;
}
#endif
