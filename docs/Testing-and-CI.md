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
- SPDM Emulator PQC Test — wolfSSL master + spdm-emu (OpenSSL backend) on the
  full x64 + aarch64 matrix. Builds wolfSPDM ML-KEM-only as well as the combined
  config, then runs over the wire: ML-DSA-44/65/87 (signatures), ML-KEM-512/768/1024
  (key exchange), and a **fully post-quantum** leg (ML-KEM-768 + ML-DSA-65/87) for
  session, measurements, and challenge.

See `.github/workflows/README.md` for workflow inventory details.

## ML-DSA (post-quantum signatures) test coverage

- **Unit (`make check`, ML-DSA build):** PqcAsymAlgo/PqcAsymSel wire offsets and
  the Base/Pqc mutual-exclusion; a real wolfSSL ML-DSA sign + verify round-trip
  through `wolfSPDM_VerifyMeasurementSig` for ML-DSA-44/65/87 (with a tamper
  negative); and KEY_EXCHANGE_RSP / CHALLENGE_AUTH signature-size guards.
- **Real-certificate validation:** `wolfSPDM_ExtractResponderPubKey` was
  validated against the actual spdm-emu ML-DSA cert chains for all three levels
  (44 -> WC_ML_DSA_44, 65 -> 65, 87 -> 87), plus a negative case where a
  level-65 cert is rejected when ML-DSA-87 was negotiated (level pinning).
- **Over-the-wire (CI):** ML-DSA-44/65/87 all complete against spdm-emu;
  ML-DSA-87 responses exceed the 4608 B DataTransferSize and are reassembled via
  the SPDM 1.2 chunking engine (see [[Message Chunking]]).

## ML-KEM (post-quantum key exchange) test coverage

- **Unit (`make check`, ML-KEM build):** KEMAlg negotiation wire offsets, the
  DHE-xor-KEM mutual-exclusion, a real wolfSSL ML-KEM encapsulate/decapsulate
  round-trip asserting `K′ == K`, the KEY_EXCHANGE `ek` placement, the
  KEY_EXCHANGE_RSP ciphertext-offset math, the reconnect key-type-switch (no
  type-confused free), the KEM-only-below-1.4 refusal, and the oversized-request
  fail-fast guard.
- **Over-the-wire (CI):** ML-KEM-512/768/1024 against spdm-emu (`--dhe NONE
  --kem ML_KEM_*`), and a **fully post-quantum** leg pairing ML-KEM-768 with
  ML-DSA-65/87 — the ML-DSA-87 case also exercises chunking, so ML-KEM + ML-DSA +
  CHUNK_GET reassembly all run in a single handshake.
- **Config coverage (CI):** an ML-KEM-only build (`--disable-mldsa
  --enable-mlkem`) exercises the ML-KEM-only `WOLFSPDM_CTX_STATIC_SIZE` budget.

## Validation caveat

Building/tests require a compatible wolfSSL installation and may fail if `--with-wolfssl` is not provided or wolfSSL is absent from default search paths.
