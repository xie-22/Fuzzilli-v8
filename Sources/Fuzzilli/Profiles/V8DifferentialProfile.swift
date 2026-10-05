// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import Foundation

/// Differential fuzzing profile for V8 15.3 (3C).
///
/// The main runner executes programs with the full Turboshaft/Maglev
/// optimization surface. The reference runner runs the same programs through
/// pure Ignition (--no-maglev --no-turbofan --no-sparkplug). Because the
/// current d8 builds do not include the Dumpling patch, the oracle falls back
/// to comparing the observable stdout/fuzzout of both runs; the codePrefix
/// determinism shim removes Date/Math.random/Temporal nondeterminism so that
/// any output
/// mismatch indicates a real JIT-vs-interpreter miscompilation.
/// NOTE: Worker is intentionally disabled in this differential profile:
/// its output is asynchronous (separate thread), so uncaught-exception
/// timing is nondeterministic and yields spurious "differs" results. Worker
/// is still fuzzed in the main v8 profile (WorkerGenerator).
/// NOTE: the reference runner must NOT use --jitless: that flag disables
/// WebAssembly entirely (wasm requires executable memory), so every
/// WebAssembly-touching program threw "WebAssembly is not defined" in
/// the reference run and produced a spurious differential.
/// If a Dumpling-patched d8 is used, the deep frame-dump comparison is used
/// automatically instead.
public let v8DifferentialProfile = Profile(
    processArgs: { randomize in
        var args = v8ProcessArgs(randomize: randomize, forSandbox: false)

        // Turboshaft & Maglev optimization surface.
        args.append("--turboshaft")
        args.append("--turboshaft-typed-optimizations")
        args.append("--turboshaft-assert-types")
        args.append("--turboshaft-loop-optimization")
        args.append("--maglev")
        args.append("--maglev-assert")
        args.append("--maglev-assert-types")
        args.append("--maglev-range-verification")
        args.append("--maglev-escape-analysis")
        args.append("--maglev-object-tracking")

        // Determinism flags for the differential oracle (required on BOTH
        // runners):
        //  --predictable: deterministic hash seeds and allocation patterns.
        //  --no-concurrent-recompilation: serialize JIT tier-up so that the
        //    optimization state at every execution point is reproducible.
        //  --random-seed: fixed seed for the engine's random generator.
        // NOTE: --no-stress-opt does not exist in V8 15.3.
        args.append("--predictable")
        args.append("--no-concurrent-recompilation")
        args.append("--random-seed=1337")

        args.append("--harmony-temporal")
        // NOTE: WasmGC and Wasm Memory64 are stable in V8 15.x; their
        // experimental flags no longer exist.

        return args
    },

    processArgsReference: [
        "--no-maglev",
        "--no-turbofan",
        "--no-sparkplug",
        "--expose-gc",
        "--expose-externalize-string",
        "--omit-quit",
        "--allow-natives-syntax",
        "--fuzzing",
        "--harmony",
        "--experimental-fuzzing",
        "--js-staging",
        "--wasm-staging",
        "--wasm-fast-api",
        "--expose-fast-api",
        "--wasm-test-streaming",
        // NOTE: --wasm-assume-ref-cast-desc-succeeds removed (unknown flag
        // under --wasm-staging in d8 15.3; pollutes stdout).
        "--predictable",
        "--no-concurrent-recompilation",
        "--random-seed=1337",
        "--harmony-temporal",
    ],

    processEnv: [
        "ASAN_OPTIONS": "symbolize=0:handle_segv=0:handle_sigbus=0:handle_abort=1:abort_on_error=1:detect_leaks=0:allocator_may_return_null=1",
        "UBSAN_OPTIONS": "symbolize=0:halt_on_error=1"
    ],

    maxExecsBeforeRespawn: 1000,

    timeout: Timeout.interval(300, 900),

    codePrefix: """
        // --- Determinism Shim ---
        (function() {
            const originalDate = Date;
            const FIXED_TIME = 1767225600000;
            const FIXED_STRING = new originalDate(FIXED_TIME).toString();

            Date.now = function() { return FIXED_TIME; };
            globalThis.Date = new Proxy(originalDate, {
                construct(target, args) {
                    if (args.length === 0) return new target(FIXED_TIME);
                    return new target(...args);
                },
                apply(target, thisArg, args) { return FIXED_STRING; }
            });
            globalThis.Date.prototype = originalDate.prototype;

            // Math.random shim
            const rng = function() {
                let s = 0x12345678;
                return function() {
                    s ^= s << 13; s ^= s >> 17; s ^= s << 5;
                    return (s >>> 0) / 4294967296;
                };
            }();
            Math.random = rng;

            // performance.now shim: d8 exposes performance.now().
            if (typeof performance !== 'undefined') {
                performance.now = function() { return 123456.789; };
            }

            if (typeof Temporal !== 'undefined' && Temporal.Now) {
                const fixedInstant = Temporal.Instant.fromEpochMilliseconds(FIXED_TIME);

                Temporal.Now.instant = () => fixedInstant;

                // Shim Zoned/Plain methods to use the fixed instant
                Temporal.Now.zonedDateTimeISO = (tzLike) =>
                    fixedInstant.toZonedDateTimeISO(tzLike || Temporal.Now.timeZoneId());

                Temporal.Now.plainDateTimeISO = (tzLike) =>
                    fixedInstant.toZonedDateTimeISO(tzLike || Temporal.Now.timeZoneId()).toPlainDateTime();

                Temporal.Now.plainDateISO = (tzLike) =>
                    fixedInstant.toZonedDateTimeISO(tzLike || Temporal.Now.timeZoneId()).toPlainDate();

                Temporal.Now.plainTimeISO = (tzLike) =>
                    fixedInstant.toZonedDateTimeISO(tzLike || Temporal.Now.timeZoneId()).toPlainTime();
            }
        })();
        // --- End Determinism Shim ---
        """,

    codeSuffix: """
        """,

    ecmaVersion: ECMAScriptVersion.es6,

    startupTests: [
        // Check that the fuzzilli integration is available.
        ("fuzzilli('FUZZILLI_PRINT', 'test')", .shouldSucceed),

        // Check that common crash types are detected.
        // IMMEDIATE_CRASH()
        ("fuzzilli('FUZZILLI_CRASH', 0)", .shouldCrash),
        // CHECK failure
        ("fuzzilli('FUZZILLI_CRASH', 1)", .shouldCrash),
        // Wild-write
        ("fuzzilli('FUZZILLI_CRASH', 3)", .shouldCrash),
    ],

    additionalCodeGenerators: [
        (ForceJITCompilationThroughLoopGenerator, 5),
        (ForceTurboFanCompilationGenerator, 5),
        (ForceMaglevCompilationGenerator, 5),
        (ForceOsrGenerator, 5),
        // NOTE: TurbofanVerifyTypeGenerator removed (false-positive CHECK
        // crashes on type-feedback divergence).

        (V8GcGenerator, 10),

        (WasmStructGenerator, 15),
        (WasmArrayGenerator, 15),
        (SharedObjectGenerator, 5),
        (PretenureAllocationSiteGenerator, 5),
        (HoleNanGenerator, 5),
        (UndefinedNanGenerator, 5),
        (StringShapeGenerator, 5),
        (HeapNumberGenerator, 5),

        // Malformed / invisible / cross-language boundary strings (Task 6).
        (MalformedStringGenerator, 15),

        // Turboshaft / Maglev targeted generators.
        (TurboshaftTypeConfusionGenerator, 10),
        (TurboshaftRangeInferenceGenerator, 10),
        (ArrayBoundsCheckEliminationGenerator, 10),
        (EscapeAnalysisScalarReplacementGenerator, 10),
        (TemporalHotLoopGenerator, 5),
    ],

    additionalProgramTemplates: WeightedList<ProgramTemplate>([
        (MapTransitionFuzzer, 2),
        (ValueSerializerFuzzer, 1),
        (V8RegExpFuzzer, 1),
        (IndirectLazyDeoptFuzzer, 2),
        (RecursiveLazyDeoptFuzzer, 2),
        (HomomorphicFeedbackFuzzer, 2),
        (ProtoAssignSeqOptFuzzer, 2),
        (TurbofanTierUpNonInlinedCallFuzzer, 2),
    ]),

    disabledCodeGenerators: [],

    disabledMutators: [],

    additionalBuiltins: [
        "gc": .function([.opt(gcOptions.instanceType)] => (.undefined | .jsPromise())),
        "d8": .jsD8,
        // via --expose-externalize-string:
        "externalizeString": .function([.plain(.jsString)] => .jsString),
        "isOneByteString": .function([.plain(.jsString)] => .boolean),
        "createExternalizableString": .function([.plain(.jsString)] => .jsString),
        "createExternalizableTwoByteString": .function([.plain(.jsString)] => .jsString),
    ],

    additionalObjectGroups: [
        jsD8, jsD8Test, jsD8FastCAPI, gcOptions,
    ],

    additionalEnumerations: [.gcTypeEnum, .gcExecutionEnum],

    additionalOptionsBags: [],

    optionalPostProcessor: DumplingFuzzingPostProcessor()
)
