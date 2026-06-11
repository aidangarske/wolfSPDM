# API Reference

Public APIs are declared in `wolfspdm/spdm.h`.

All APIs return `WOLFSPDM_SUCCESS` (`0`) on success unless documented otherwise; failures are negative error codes from `wolfspdm/spdm_error.h`.

## Context and lifecycle

- `wolfSPDM_Init`
- `wolfSPDM_InitStatic`
- `wolfSPDM_GetCtxSize`
- `wolfSPDM_Free`
- `wolfSPDM_New` *(only when built with `WOLFSPDM_DYNAMIC_MEMORY`)*

## Configuration

- `wolfSPDM_SetIO`
- `wolfSPDM_SetMaxVersion`
- `wolfSPDM_SetRequesterSessionId`
- `wolfSPDM_AllowUntrustedCerts`
- `wolfSPDM_SetTrustedCAs`
- `wolfSPDM_SetDebug`

## Session establishment and state

- `wolfSPDM_Connect`
- `wolfSPDM_IsConnected`
- `wolfSPDM_Disconnect`
- `wolfSPDM_GetSessionId`
- `wolfSPDM_GetNegotiatedVersion`
- `wolfSPDM_GetVersion_Negotiated` *(legacy compatibility symbol)*
- `wolfSPDM_GetLastPeerError`

## Fine-grained handshake

- `wolfSPDM_GetVersion`
- `wolfSPDM_GetCapabilities`
- `wolfSPDM_NegotiateAlgorithms`
- `wolfSPDM_GetDigests`
- `wolfSPDM_GetCertificate`
- `wolfSPDM_KeyExchange`
- `wolfSPDM_Finish`

## Secured messaging

- `wolfSPDM_SecuredExchange`
- `wolfSPDM_SendData` *(not in `WOLFSPDM_LEAN`)*
- `wolfSPDM_ReceiveData` *(not in `WOLFSPDM_LEAN`)*
- `wolfSPDM_EncryptMessage` *(not in `WOLFSPDM_LEAN`)*
- `wolfSPDM_DecryptMessage` *(not in `WOLFSPDM_LEAN`)*

## Attestation

- `wolfSPDM_GetMeasurements` *(not with `NO_WOLFSPDM_MEAS`)*
- `wolfSPDM_GetMeasurementCount` *(not with `NO_WOLFSPDM_MEAS`)*
- `wolfSPDM_GetMeasurementBlock` *(not with `NO_WOLFSPDM_MEAS`)*
- `wolfSPDM_Challenge` *(not with `NO_WOLFSPDM_CHALLENGE`)*

## Session maintenance

- `wolfSPDM_Heartbeat`
- `wolfSPDM_KeyUpdate`

## Error utilities

- `wolfSPDM_GetErrorString`

## Common error codes

Examples:
- `WOLFSPDM_E_INVALID_ARG`
- `WOLFSPDM_E_BAD_STATE`
- `WOLFSPDM_E_NOT_CONNECTED`
- `WOLFSPDM_E_IO_FAIL`
- `WOLFSPDM_E_PEER_ERROR`
- `WOLFSPDM_E_MEAS_SIG_FAIL`
- `WOLFSPDM_E_CHALLENGE`
- `WOLFSPDM_E_KEY_UPDATE`
