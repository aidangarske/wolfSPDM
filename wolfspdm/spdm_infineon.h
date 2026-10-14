/* spdm_infineon.h
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

/* Infineon OPTIGA SLB9678 TPM SPDM Support
 *
 * Sessions use the shared TCG binding with SHA-384/AES-256-GCM and require
 * firmware advertising KEY_EX_CAP and PUB_KEY_ID_CAP. Do not infer that
 * support from the device name; verify capabilities before connecting.
 *
 * Reference: SLB9678 TPM 2.0 FW45.02 Extended Datasheet, Section 3.2.6.9.
 */

#ifndef WOLFSPDM_INFINEON_H
#define WOLFSPDM_INFINEON_H

#ifdef WOLFSPDM_INFINEON

/* Include shared TCG declarations */
#include <wolfspdm/spdm_tcg.h>

#ifdef __cplusplus
extern "C" {
#endif

/* GET_STATUS / SPDM_ONLY / TPM_CMD reuse the shared 8-byte vendor-defined
 * command codes in spdm_tcg.h; the part adds none of its own here. */

/* ----- Infineon SPDM Status ----- */

/* GET_STATUS_RSP fields per TCG spec Table 15 */
typedef struct WOLFSPDM_INFINEON_STATUS {
    unsigned int spdmEnabled    : 1;
    unsigned int sessionActive  : 1;
    unsigned int spdmOnlyLocked : 1;
    unsigned int spdmOnlyPending : 1;
    unsigned int pskProvisioned : 1;
} WOLFSPDM_INFINEON_STATUS;

/* ----- Infineon SPDM Functions ----- */

WOLFSPDM_API int wolfSPDM_Infineon_GetStatus(WOLFSPDM_CTX* ctx,
    WOLFSPDM_INFINEON_STATUS* status);

WOLFSPDM_API int wolfSPDM_Infineon_SetOnlyMode(WOLFSPDM_CTX* ctx, int lock);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSPDM_INFINEON */

#endif /* WOLFSPDM_INFINEON_H */
