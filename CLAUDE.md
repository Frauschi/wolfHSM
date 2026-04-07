# CLAUDE.md - wolfHSM Development Guide

## Project Overview

wolfHSM is a portable, open-source client-server framework for hardware cryptography, non-volatile memory (NVM), and isolated secure processing. Built by wolfSSL, it targets automotive-style HSM-enabled microcontrollers but runs on any platform with a secure/trusted execution environment. It supports PKCS11 and AUTOSAR SHE protocols.

**Architecture:** Client-server model where the server runs in a trusted environment and clients communicate via the wolfHSM client library. wolfCrypt API calls are automatically offloaded to the server as remote procedure calls.

## Repository Structure

```
wolfhsm/          # Public headers (API)
src/               # Core library source files
port/              # Platform-specific ports
  posix/           #   POSIX port (used for testing)
  skeleton/        #   Template for new ports
  infineon/        #   Infineon TC3xx/TC4xx
  renesas/         #   Renesas RH850
  stmicro/         #   STMicroelectronics SPC58
  ti/              #   Texas Instruments
  microchip/       #   Microchip
test/              # Unit tests (POSIX-based)
  config/          #   Test build configuration (wolfhsm_cfg.h, user_settings.h)
benchmark/         # Performance benchmarks
examples/          # Example applications
  posix/           #   POSIX client/server examples
  demo/            #   Demo configurations
tools/             # Utilities
  whnvmtool/       #   NVM image tool
  testcertgen/     #   Test certificate generator
  static-analysis/ #   Static analysis configuration
docs/              # Documentation sources
```

## Build System

The project uses **GNU Make**. wolfHSM depends on **wolfSSL** (wolfCrypt) which must be checked out alongside this repo (default: `../../wolfssl` relative to `test/`).

### Building and Running Tests

```bash
# Standard build and test
cd test && make -j WOLFSSL_DIR=../wolfssl && make run

# Build with specific features enabled
cd test && make -j DMA=1 WOLFSSL_DIR=../wolfssl && make run
cd test && make -j SHE=1 WOLFSSL_DIR=../wolfssl && make run
cd test && make -j THREADSAFE=1 WOLFSSL_DIR=../wolfssl && make run

# Debug build
cd test && make -j DEBUG=1 WOLFSSL_DIR=../wolfssl && make run
cd test && make -j DEBUG_VERBOSE=1 WOLFSSL_DIR=../wolfssl && make run

# With sanitizers
cd test && make -j ASAN=1 WOLFSSL_DIR=../wolfssl && make run
cd test && make -j THREADSAFE=1 TSAN=1 WOLFSSL_DIR=../wolfssl && make run

# No-crypto build (no wolfCrypt dependency)
cd test && make -j NOCRYPTO=1 WOLFSSL_DIR=../wolfssl && make run

# Run wolfCrypt test suite through wolfHSM
cd test && make -j TESTWOLFCRYPT=1 WOLFSSL_DIR=../wolfssl && make run

# Build all targets (test, benchmark, tools, examples)
make all

# Clean everything
make clean
```

### Key Makefile Variables

| Variable | Description |
|---|---|
| `WOLFSSL_DIR` | Path to wolfSSL source (default: `../../wolfssl`) |
| `DEBUG=1` | Enable debug build with `-ggdb` and `WOLFHSM_CFG_DEBUG` |
| `DEBUG_VERBOSE=1` | Verbose debug output (implies DEBUG) |
| `ASAN=1` | Address sanitizer |
| `TSAN=1` | Thread sanitizer (mutually exclusive with ASAN) |
| `DMA=1` | Enable DMA support |
| `SHE=1` | Enable AUTOSAR SHE extension |
| `NOCRYPTO=1` | Build without wolfCrypt |
| `THREADSAFE=1` | Enable thread-safe locking |
| `COVERAGE=1` | Code coverage instrumentation |
| `TESTWOLFCRYPT=1` | Include wolfCrypt test suite |
| `STRESS=1` | Thread stress test (requires THREADSAFE=1) |

### Static Analysis

```bash
make scan   # Runs scan-build on the test target
```

## C Standard and Compiler Settings

- **C standard:** C90 (`-std=c90`) by default
- **Warnings:** `-Werror -Wall -Wextra` — all warnings are errors
- **Column limit:** 80 characters
- **Indentation:** 4 spaces, no tabs

## Code Formatting

The project uses **clang-format-15** with the `.clang-format` config at the repo root. CI checks formatting on PRs against the base branch.

```bash
# Format changed files against the base branch
git-clang-format-15 main
```

Key style rules:
- Braces on new line after functions only; K&R style for control statements (`else` on new line)
- 4-space indent, no tabs
- 80-column limit
- Align consecutive assignments and declarations
- Pointer alignment: left (`int* ptr`)
- No sorting of includes

## Naming Conventions

- **Files:** `wh_<module>.c` / `wh_<module>.h` (e.g., `wh_client.c`, `wh_server_crypto.c`)
- **Functions:** `wh_<Module>_<Action>` (e.g., `wh_Client_Init`, `wh_Server_HandleRequestMessage`)
- **Types/Structs:** `wh<Module><Name>` (e.g., `whClientContext`, `whServerConfig`)
- **Constants/Macros:** `WH_<MODULE>_<NAME>` (e.g., `WH_ERROR_OK`, `WH_COMM_DATA_LEN`)
- **Config macros:** `WOLFHSM_CFG_<NAME>` (e.g., `WOLFHSM_CFG_DMA`, `WOLFHSM_CFG_SHE_EXTENSION`)
- **Header guards:** `WOLFHSM_WH_<MODULE>_H_`

## Configuration System

wolfHSM uses compile-time configuration via defines. Configuration is layered:

1. **`wolfhsm_cfg.h`** — User-provided project config (included when `WOLFHSM_CFG` is defined)
2. **`wolfhsm/wh_settings.h`** — Default values and validation of configuration
3. **`user_settings.h`** — wolfSSL/wolfCrypt config (included when `WOLFSSL_USER_SETTINGS` is defined)

Test configurations live in `test/config/`. When creating new features, add corresponding `WOLFHSM_CFG_*` defines.

## Error Handling

All functions return `int` error codes from `wolfhsm/wh_error.h`:
- `WH_ERROR_OK` (0) — success
- Negative values indicate errors (e.g., `WH_ERROR_BADARGS`, `WH_ERROR_NOTFOUND`)
- Error codes start at -2000 for general errors, -2100 for NVM/keystore, -2200 for SHE

Always check return values. Use the existing error code constants rather than inventing new ones unless a genuinely new error category is needed.

## Architecture Patterns

### Client-Server Communication
- Messages are defined in `wolfhsm/wh_message_*.h` with serialization in `src/wh_message_*.c`
- The comm layer (`wh_comm`) handles framing; transport layer is pluggable
- Request/response pattern: client sends request, server processes, server sends response

### Transport Layer
- Abstract transport interface defined in `wh_comm.h`
- Implementations: shared memory (`wh_transport_mem`), TCP, TLS, SHM (in port/)
- New transports implement the `whTransportClient`/`whTransportServer` callbacks

### Port Layer
- Platform-specific code lives in `port/<platform>/`
- Use `port/skeleton/` as a template for new ports
- Ports provide: flash driver, transport, time, locking, logging

### Key/NVM Management
- Keys cached in RAM (`wh_keycache`), backed by NVM flash (`wh_nvm_flash`)
- Key IDs use a structured format defined in `wh_keyid.h`

## CI Workflows

GitHub Actions runs on every PR:
- **build-and-test.yml** — Builds and tests with various feature flag combinations (DMA, SHE, THREADSAFE, ASAN, NOCRYPTO, TESTWOLFCRYPT, etc.)
- **build-and-bench.yml** — Benchmark builds
- **build-and-run-examples.yml** — Example builds
- **build-and-test-stress.yml** — Thread stress tests with TSAN
- **build-and-test-clientonly.yml** — Client-only build tests
- **build-and-test-whnvmtool.yml** — NVM tool tests
- **clang-format-check.yml** — Formatting check with clang-format-15
- **code-coverage.yml** — Coverage report generation
- **static-analysis.yml** — scan-build static analysis

## Testing

Tests are in `test/`. Each module has a corresponding `wh_test_<module>.c` file. The main test driver is `wh_test.c`.

When adding new functionality:
1. Create `test/wh_test_<feature>.c` and `test/wh_test_<feature>.h`
2. Register the test in `wh_test.c`
3. Ensure tests pass with multiple flag combinations: standard, `DMA=1`, `ASAN=1`, `NOCRYPTO=1`, `SHE=1`, `THREADSAFE=1`

## License

GPLv3 (see LICENSE). All source files must include the wolfSSL copyright header.

## Common Pitfalls

- **Always clean before switching build flags:** `make clean` before changing `DMA`, `SHE`, `NOCRYPTO`, etc.
- **wolfSSL dependency:** Most builds require wolfSSL source. Only `NOCRYPTO=1` builds skip it.
- **C90 compliance:** No `//` comments, no mixed declarations and code, no variable-length arrays. Declare variables at the top of blocks.
- **Thread safety:** Code guarded by `WOLFHSM_CFG_THREADSAFE` must use the lock API (`wh_lock.h`). Never assume single-threaded access to shared server state.
- **Message size limits:** Payloads must fit within `WOLFHSM_CFG_COMM_DATA_LEN` (default 1280 bytes, 8192 in test config).
