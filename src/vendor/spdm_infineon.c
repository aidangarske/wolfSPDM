/* spdm_infineon.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

/* Infineon OPTIGA SLB9678 SPDM Functions
 *
 * Infineon PSK provisioning and configuration commands. Both asymmetric
 * and PSK handshakes use the shared protocol code, subject to firmware
 * capabilities. Framing uses the shared TCG code in spdm_tcg.c.
 */

#include "spdm_internal.h"

#ifdef WOLFSPDM_INFINEON

#include <wolfspdm/spdm_infineon.h>

/* ----- Infineon PSK-Mode Vendor Commands ----- */

int wolfSPDM_Infineon_GetStatus(WOLFSPDM_CTX* ctx,
    WOLFSPDM_INFINEON_STATUS* status)
{
    WOLFSPDM_VENDOR_RSP rsp;
    int rc;

    if (ctx == NULL || status == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    XMEMSET(status, 0, sizeof(*status));

    wolfSPDM_DebugPrint(ctx, "Infineon: GET_STS_\n");

    /* SLB9678 accepts GET_STATUS with no payload (Type field omitted) */
    rc = wolfSPDM_TCG_VendorCmdClear(ctx, WOLFSPDM_VDCODE_GET_STS,
        NULL, 0, &rsp);
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugHex(ctx, "GET_STS_ payload", rsp.payload, rsp.payloadSz);

    /* Per TCG spec Table 15 - GET_STATUS_RSP payload:
     * [0] SpecMajorVersion, [1] SpecMinorVersion,
     * [2] PSKSet (00=NO, 01=YES),
     * [3] SPDMOnly (00=DISABLED, 01=ENABLED, 81=PENDING_DISABLE) */
    if (rsp.payloadSz < 4) {
        return WOLFSPDM_E_FRAMING;
    }
    status->spdmEnabled = 1;
    status->pskProvisioned = (rsp.payload[2] != 0);
    status->spdmOnlyLocked = (rsp.payload[3] != 0);
    status->spdmOnlyPending = (rsp.payload[3] == 0x81);
    wolfSPDM_DebugPrint(ctx, "GET_STS_: v%u.%u PSK=%s SPDMOnly=0x%02x\n",
        rsp.payload[0], rsp.payload[1],
        status->pskProvisioned ? "YES" : "NO",
        rsp.payload[3]);

    return WOLFSPDM_SUCCESS;
}

int wolfSPDM_Infineon_SetOnlyMode(WOLFSPDM_CTX* ctx, int lock)
{
    byte param[1];
    int rc;

    if (ctx == NULL) {
        return WOLFSPDM_E_INVALID_ARG;
    }

    if (ctx->state != WOLFSPDM_STATE_CONNECTED) {
        return WOLFSPDM_E_NOT_CONNECTED;
    }

    param[0] = lock ? WOLFSPDM_SPDMONLY_LOCK : WOLFSPDM_SPDMONLY_UNLOCK;

    wolfSPDM_DebugPrint(ctx, "Infineon: SPDMONLY %s\n",
        lock ? "LOCK" : "UNLOCK");

    rc = wolfSPDM_TCG_VendorCmdSecured(ctx, WOLFSPDM_VDCODE_SPDMONLY,
        param, sizeof(param));
    if (rc != WOLFSPDM_SUCCESS) {
        return rc;
    }

    wolfSPDM_DebugPrint(ctx, "SPDMONLY: Success (Lock=%u)\n", param[0]);
    return WOLFSPDM_SUCCESS;
}

#endif /* WOLFSPDM_INFINEON */

