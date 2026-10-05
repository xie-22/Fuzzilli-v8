# Usage
## 1. Requirements
- A built Fuzzilli release binary at `.build/release/FuzzilliCli`
- A V8 fuzzing build (`d8` or `v8_shell`) compiled with fuzzing flags
- Optional: `wasm-opt` (from Binaryen) if using `--wasm`
- Linux host (REPRL, core pattern, ASAN/UBSAN env)

## 2. Quick Start

Set up your environment once:

```bash
export FUZZILLI_DIR=/path/to/fuzzilli
export TARGET_SHELL=/path/to/d8
export OUTPUT_DIR=/path/to/fuzzilli_results
export WASM_OPT=/usr/local/bin/wasm-opt
```

Then run:

```bash
cd "$FUZZILLI_DIR"
mkdir -p "$OUTPUT_DIR"

"$FUZZILLI_DIR/.build/release/FuzzilliCli" \
    --profile=v8 \
    --jobs=3 \
    --engine=mutation \
    --corpus=energy \
    --storagePath="$OUTPUT_DIR/main_asan" \
    --resume \
    --wasm \
    --wasm-opt-path="$WASM_OPT" \
    --tag="my-tag" \
    "$TARGET_SHELL"
```

## 3. Recommended Production Script

Save as `run_fuzzilli_v8.sh` and adjust paths at the top:

```bash
#!/bin/bash
set -euo pipefail

# ---- Configurable paths ----
FUZZILLI_DIR="${FUZZILLI_DIR:-/v8/fuzzilli}"
TARGET_SHELL="${TARGET_SHELL:-/v8/out/fuzzbuild/d8}"
OUTPUT_DIR="${OUTPUT_DIR:-/v8/fuzzilli_results}"
WASM_OPT="${WASM_OPT:-/usr/local/bin/wasm-opt}"
TAG="${TAG:-vrp-v8}"

CLI="$FUZZILLI_DIR/.build/release/FuzzilliCli"
BASE="$OUTPUT_DIR/cluster"
LOG="$BASE/main_asan.log"

export ASAN_OPTIONS="symbolize=0:detect_leaks=0:abort_on_error=1:handle_abort=1:allocator_may_return_null=1:detect_odr_violation=0:check_initialization_order=0:quarantine_size_mb=16:max_redzone=32"
export UBSAN_OPTIONS="symbolize=0:halt_on_error=1:abort_on_error=1:handle_abort=1"

if [ "$(cat /proc/sys/kernel/core_pattern 2>/dev/null)" != "/dev/null" ]; then
    sysctl -w kernel/core_pattern=/dev/null || true
fi

cd "$FUZZILLI_DIR"
mkdir -p "$BASE"

stdbuf -oL "$CLI" \
    --profile=v8 --jobs=3 \
    --minimizationLimit=0.2 \
    --engine=mutation --corpus=energy \
    --reproducibilityRuns=1 \
    --maxCorpusSize=3000 --minCorpusSize=2000 \
    --timeout=266,1000 \
    --storagePath="$BASE/main_asan" \
    --corpusImportMode=full \
    --diagnostics \
    --wasm \
    --resume \
    --consecutiveMutations=10 \
    --wasm-opt-path="$WASM_OPT" \
    --inspect \
    --tag="$TAG-x" "$TARGET_SHELL" 2>&1 | tee "$LOG"
```

Run with overrides:

```bash
FUZZILLI_DIR=/opt/fuzzilli \
TARGET_SHELL=/opt/v8/out/x64.release/d8 \
OUTPUT_DIR=/data/fuzz \
WASM_OPT=/usr/bin/wasm-opt \
TAG=my-run \
bash run_fuzzilli_v8.sh
```

## 4. Path Reference

| Variable | Purpose | Typical value |
|---|---|---|
| `FUZZILLI_DIR` | Fuzzilli source root | `/v8/fuzzilli` |
| `TARGET_SHELL` | V8 fuzzing binary | `/v8/out/fuzzbuild/d8` |
| `OUTPUT_DIR` | Crash / corpus storage | `/v8/fuzzilli_results` |
| `WASM_OPT` | Binaryen `wasm-opt` binary | `/usr/local/bin/wasm-opt` |
| `TAG` | Label stored in settings and crashes | `vrp-v8` |

> Adjust these to match your local environment. The script only requires that `FuzzilliCli`, `d8`, and `wasm-opt` (if used) exist and are executable.

## 5. Verifying Your Setup

```bash
# FuzzilliCli exists and runs
"$FUZZILLI_DIR/.build/release/FuzzilliCli" --help

# Target shell starts and accepts V8 fuzzing flags
"$TARGET_SHELL" --version

# wasm-opt is available (only if --wasm is used)
"$WASM_OPT" --version
```

If `--wasm-opt-path` is omitted, Wasm generators still work but Binaryen-based generation is disabled.

## 6. Common Warnings

| Message | Meaning |
|---|---|
| `Failed to load N program(s) from .../old_corpus` | Old `.fzil` files are incompatible or corrupted; they are skipped, not fatal. |
| `Scheduling import of 0 programs from previous fuzzing run` | Nothing reusable from the previous run; fuzzer starts from code generators. |
| `Initialized, N edges` | Coverage instrumentation is active. |
| `Checking constructor availability...` | Startup probe against the target shell. |

These are normal on a fresh or resumed run and do not prevent fuzzing.

## 7. Notes

- Always run distributed fuzzing (`--instanceType`) in an isolated network.
- `--resume` takes precedence over `--overwrite`.
- `--maxRuntimeInHours` takes precedence over `--maxIterations`.
- Use `--staticCorpus` to reproduce a known crash without growing the corpus.
- For long runs, keep `core_pattern=/dev/null` to avoid giant core dumps.
