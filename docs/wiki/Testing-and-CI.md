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

See `.github/workflows/README.md` for workflow inventory details.

## Validation caveat

Building/tests require a compatible wolfSSL installation and may fail if `--with-wolfssl` is not provided or wolfSSL is absent from default search paths.
