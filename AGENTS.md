# AGENTS.md — Crypto (Python Script Protector)

## Quick start

```sh
cmake -S . -B build && cmake --build build -j$(nproc)
./build/test_crypto                          # C++ unit tests (doctest)
python3 -m pytest tests/test_pyobf.py        # Python obfuscator tests
ctest --test-dir build -V                    # or via CTest
```

## Build system

- **CMake 3.16+**, C++20, requires `OpenSSL::Crypto` + `ZLIB::ZLIB`
- Single target `crypto` (CLI binary) and `test_crypto` (unit test binary)
- `test_crypto` compiles *all* source files directly (not just test files) — edit `CMakeLists.txt` if adding new `.cpp`
- Generated `compile_commands.json` is in `build/`
- Version in `include/crypto/common.h` is `1.5.0` (CMakeLists still says 1.1.0 — trust `common.h`)

## CLI entrypoint

`src/main.cpp` → `src/cli/cli.cpp` → dispatch via `CommandMode` enum.  
Commands: `encode`, `decode`, `encrypt`, `decrypt`, `protect`.

Default algorithms: `aes-gcm` (encrypt/protect), `base64` (encode). Key priority: `-k | --keygen | --keyfile | --keyenv | built-in default`.

Exit codes: `0=OK`, `1=ARGS`, `2=FILE`, `3=CRYPTO`, `4=INTERNAL`.

## Architecture

Three layers, applied composably:
1. **Encode/decode** — text transforms (base64/32/85, ascii85, hex, xor variants)
2. **Encrypt/decrypt** — AES-256-ECB/CBC/CTR/GCM + ChaCha20, PBKDF2 key derivation, HMAC integrity
3. **Protect** — packages into self-decrypting Python script with optional obfuscation, compression, VM, anti-analysis

## Embedded Python scripts

Several Python scripts are embedded in C headers via raw string literals. When the Python sources change, regenerate the headers:

```sh
python3 tools/generate_pyobf_h.py        # include/crypto/pyobf.h       (from include/crypto/pyobf_core.py)
python3 tools/generate_compress_h.py     # include/crypto/compress_script.h (from tools/compress.py)
```

Other embedded scripts (not auto-generated): `include/vm/vm_py.h`, `include/vm/vm_interp_py.h`, `include/vm/vm_split.h`.

## VM subsystem (`include/vm/vm.h`, `src/vm/*.cpp`)

Register VM (64 regs, 8-byte fixed-size instructions, 160+ opcodes). Extended pipeline:

1. Standard compilation → ISA expand → obfuscated conditions → register spilling → self-modifying code → variable-length/polymorphic encoding → opcode shuffle → serialize

VM enhancement spec lives in `VM_ENHANCEMENT_SPEC.md` (not yet fully implemented — check checkboxes in appendix).

## Obfuscation techniques

Applied via `--obf` flag on `protect`: `rename`, `strings`, `vstrings`, `cleanup`, `flow`, `aflow`, `opaque`, `mutate`, `mba`, `junk`, `funcenc`, `all`.  
Technique `all` = `cleanup → rename → vstrings → aflow → mutate → junk` (order matters).

## Testing quirks

- C++ tests use **doctest** (`lib/doctest.h`, header-only, `DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN` in `test_all.cpp`)
- `test_obfuscate.cpp` generates temp `.py` files in `/tmp/` and runs `python3` for validation — requires Python 3.10+
- Python 3.10+ required for all obfuscation, VM, and compression features
- External Python packages (optional, only when using specific compress algos): `brotli`, `zstandard`, `lz4`, `snappy`, `blosc`
- Test data files are in `tests/`: `a.py`, `b.py`, `manual/`
- Do not run `test_openssl.cpp` (standalone, not part of build)

# GLOBAL RULES

## Architecture and code structure
- Prioritize simplicity and readability. Split complex functions into smaller ones that each perform only a single responsibility
- Modify only the code and shell commands relevant to the current task. Avoid changing unrelated parts of the codebase or environment

## Code Style
- Comment important logic and implementation details when necessary. Use English exclusively for all comments
- Prefer functional programming over object-oriented programming whenever practical
- Declare all import statements at the top of the file and avoid placing imports inside functions or conditional blocks unless necessary
- Favor modern, idiomatic code over legacy C-style approaches
- Before implementing new code, verify whether the required logic, functionality, or library already exists and can be reused

## Error Handling
- Always report errors clearly and explicitly. Never fail silently or ignore errors
- Identify and explain the root cause of errors, not just their symptoms.
- Focus on resolving the underlying cause of a problem. Avoid patches that only mask symptoms without eliminating the source of the issue
- Never stop at identifying the problem. Follow the full remediation cycle until the issue is verified as resolved: Error → Root Cause Analysis → Fix → Build → Test → Pass


## Testing
- Do not rely on a single successful test run. Execute 10–15 consecutive test runs and only accept the fix if all runs pass consistently
- Maintain a clean project structure by keeping all test-related files in the /tests/ directory and separating them from source, root, and build artifacts

## Termianl Usage
- Treat the repository as read-only. Never perform Git write operations (git add, git commit, git push, git merge, git rebase, git reset, etc.). Only use Git commands that inspect or retrieve information without altering repository state
- External dependencies, documentation, and reference materials may be downloaded using curl or wget when necessary. Prefer official and trusted sources whenever possible

## Effective
- Ensure the code maintains a balanced trade-off between performance, speed, security, readability, and maintainability
- Reasonable performance degradation (up to 2–3×) may be accepted in exchange for stronger security guarantees. However, such trade-offs must be intentional, justified, and kept within controllable limits

## Policy
- Treat the codebase as an interconnected system. Any change to an algorithm, obfuscation layer, interface, or core component must be accompanied by a review of upstream and downstream dependencies to ensure all affected parts remain compatible and synchronized
- Maintain PROJECT_STATUS.txt as the authoritative project status record. Whenever functionality, architecture, dependencies, or implementation details change, update the file accordingly while limiting modifications strictly to the affected sections
- Treat AGENTS.md as a protected, read-only configuration document. The file may only be consulted for guidance and compliance. Modifications, replacements, appends, deletions, or any other write operations are strictly prohibited, especially within the #GLOBAL RULES section

## Mandatory Regulations
- Compliance with the entire #GLOBAL RULES section of AGENTS.md is required. No rule may be ignored, bypassed, or selectively applied