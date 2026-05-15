# CI Workflows

| Workflow | File | Description |
|----------|------|-------------|
| Build and Test | `build-test.yml` | Matrix build across OS (ubuntu-latest, 22.04) and configure options (debug, dynamic-mem). Runs unit tests for each combination. |
| Multiple Compilers | `multi-compiler.yml` | Builds and tests with GCC 11-13 and Clang 14-17 using `-Wall -Wextra -Werror`. |
| Compiler Warnings | `compiler-warnings.yml` | GCC strict warnings (`-Wpedantic -Wconversion -Wshadow -Werror`) and Clang `-Werror` build. |
| Static Analysis | `static-analysis.yml` | Runs cppcheck (style, performance, portability) and Clang Static Analyzer (scan-build). |
| Memory Check | `memory-check.yml` | Valgrind leak check with `--leak-check=full` for both static and dynamic memory modes. |
| Empty Brace Scope Scan | `empty-brace-scan.yml` | Fails CI when C source/header files contain standalone brace scope blocks. |
| CodeQL Security | `codeql.yml` | GitHub CodeQL security-and-quality analysis. Runs on PRs and weekly (Monday 6 AM UTC). |
| Codespell | `codespell.yml` | Spell-checks source files. |
| SPDM Emulator Test | `spdm-emu-test.yml` | End-to-end integration test against the DMTF libspdm emulator. Runs 18 tests (6 scenarios x SPDM 1.2/1.3/1.4): session establishment, signed/unsigned measurements, challenge authentication, heartbeat, key update. Matrix across ubuntu-22.04 (x64), ubuntu-24.04 (x64), ubuntu-24.04-arm (aarch64). |
