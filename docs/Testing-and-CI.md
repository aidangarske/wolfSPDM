# Testing and CI

## Local tests

### Unit tests

```bash
make check
./test/unit_test
```

### Integration test with DMTF spdm-emu

```bash
export SPDM_EMU_PATH=../spdm-emu/build/bin
./examples/spdm_test.sh
```

`spdm_test.sh` runs 18 scenarios:
- Session
- Signed measurements
- Unsigned measurements
- Challenge
- Heartbeat
- Key update

Across SPDM versions 1.2, 1.3, and 1.4.

## CI workflow coverage

Documented workflows include:

- Build and Test (OS/config matrix)
- Multiple Compilers (GCC 11-13, Clang 14-17)
- Compiler Warnings (`-Werror`, pedantic/conversion/shadow checks)
- Static Analysis (cppcheck + scan-build)
- Memory Check (Valgrind)
- Empty Brace Scope Scan
- CodeQL Security
- Codespell
- SPDM Emulator Test (integration matrix on x64 + aarch64)
- SPDM Emulator PQC (ML-DSA) Test — wolfSSL master + spdm-emu (OpenSSL backend),
  ML-DSA-44/65 session/measurements/challenge over the wire

See `.github/workflows/README.md` for workflow inventory details.

## ML-DSA (post-quantum) test coverage

- **Unit (`make check`, ML-DSA build):** PqcAsymAlgo/PqcAsymSel wire offsets and
  the Base/Pqc mutual-exclusion; a real wolfSSL ML-DSA sign + verify round-trip
  through `wolfSPDM_VerifyMeasurementSig` for ML-DSA-44/65/87 (with a tamper
  negative); and KEY_EXCHANGE_RSP / CHALLENGE_AUTH signature-size guards.
- **Real-certificate validation:** `wolfSPDM_ExtractResponderPubKey` was
  validated against the actual spdm-emu ML-DSA cert chains for all three levels
  (44 -> WC_ML_DSA_44, 65 -> 65, 87 -> 87), plus a negative case where a
  level-65 cert is rejected when ML-DSA-87 was negotiated (level pinning).
- **Over-the-wire (CI):** ML-DSA-44 and ML-DSA-65 complete against spdm-emu.
  ML-DSA-87 responses exceed the 4608 B DataTransferSize and need the SPDM 1.2
  chunking engine (follow-on), so 87 is covered at the unit/cert level.

## Validation caveat

Building/tests require a compatible wolfSSL installation and may fail if `--with-wolfssl` is not provided or wolfSSL is absent from default search paths.
