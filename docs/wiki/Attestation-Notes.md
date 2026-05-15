# Attestation Notes

wolfSPDM supports SPDM attestation through both measurement retrieval and challenge authentication.

## Measurement attestation (`GET_MEASUREMENTS`)

Primary API:

```c
int wolfSPDM_GetMeasurements(WOLFSPDM_CTX* ctx, byte measOperation,
    int requestSignature);
```

Behavior:
- `requestSignature=1`: requests signed measurements; verifies signature when verification support is compiled in
- `requestSignature=0`: retrieves unsigned measurements (informational)

Result access:
- `wolfSPDM_GetMeasurementCount`
- `wolfSPDM_GetMeasurementBlock`

Relevant return codes:
- `WOLFSPDM_SUCCESS`
- `WOLFSPDM_E_MEAS_NOT_VERIFIED`
- `WOLFSPDM_E_MEAS_SIG_FAIL`
- `WOLFSPDM_E_MEASUREMENT`

## Sessionless challenge attestation (`CHALLENGE_AUTH`)

Primary API:

```c
int wolfSPDM_Challenge(WOLFSPDM_CTX* ctx, int slotId, byte measHashType);
```

Typical prerequisite state:
- Version/capabilities/algorithms negotiated
- Digest and cert chain retrieved

## Trust anchor handling

Load trusted CA material with:

```c
int wolfSPDM_SetTrustedCAs(WOLFSPDM_CTX* ctx, const byte* derCerts,
    word32 derCertsSz);
```

`wolfSPDM_SetTrustedCAs` currently accepts a single DER certificate buffer for root-hash matching.

## Feature toggles

- `NO_WOLFSPDM_MEAS` disables measurements
- `NO_WOLFSPDM_MEAS_VERIFY` disables measurement signature verification
- `NO_WOLFSPDM_CHALLENGE` disables challenge API

For deeper measurement details and test examples, see `docs/ATTESTATION.md`.
