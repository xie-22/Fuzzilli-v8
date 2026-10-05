// Copyright 2019 Google LLC
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

public let v8Profile = Profile(
    processArgs: { randomize in
        var args = v8ProcessArgs(randomize: randomize, forSandbox: false)
        
        // V8 15.3 Turboshaft & Maglev optimization surface (3A).
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
        args.append("--allow-natives-syntax")
        args.append("--expose-gc")
        args.append("--fuzzing")
        args.append("--omit-quit")
        
        // Aggressive memory layout & GC race triggering.
        args.append("--stress-compaction")
        // Option 2 (audit): disable concurrent recompilation to isolate a
        // possible compile-vs-GC race. If the flaky crash persists, the race is
        // between synchronous compilation and concurrent GC (test with
        // --single-threaded-gc instead).
        args.append("--no-concurrent-recompilation")
        args.append("--expose-externalize-string")
        args.append("--harmony-temporal")
        // NOTE: WasmGC and Wasm Memory64 are stable in V8 15.x; the
        // --experimental-wasm-gc / --experimental-wasm-memory64 flags no
        // longer exist and would break REPRL startup.
        // NOTE: --sandbox-fuzzing is intentionally NOT enabled here.
        // In sandbox fuzzing mode V8's crash filter turns every crash that is
        // not a sandbox violation (null derefs, in-heap wild writes) into a
        // clean _exit(), and CHECK failures into plain non-zero exits. Fuzzilli
        // would classify both as "failed" and silently discard them - which
        // would hide exactly the JIT/Turboshaft miscompilation bugs that
        // --turboshaft-assert-types is meant to surface.
        // Use the dedicated v8Sandbox profile (forSandbox: true) for the
        // sandbox-violation-only campaign.
        
        return args
    },

    processArgsReference: nil,

    // 注入 ASAN/UBSAN 环境变量，压制无意义缓冲与符号化挂死，确保 Crash 直达操作系统
    processEnv: [
        "ASAN_OPTIONS": "symbolize=0:handle_segv=0:handle_sigbus=0:handle_abort=1:abort_on_error=1:detect_leaks=0:allocator_may_return_null=1:detect_stack_use_after_return=1:quarantine_size_mb=256:malloc_context_size=30",
        "UBSAN_OPTIONS": "symbolize=0:halt_on_error=1"
    ],

    maxExecsBeforeRespawn: 1000,

    timeout: Timeout.interval(300, 900),

    codePrefix: """
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
        // DCHECK failure
        ("fuzzilli('FUZZILLI_CRASH', 2)", .shouldCrash),
        // Wild-write
        ("fuzzilli('FUZZILLI_CRASH', 3)", .shouldCrash),
        // NOTE: FUZZILLI_CRASH 8 ("DEBUG is defined") is intentionally NOT
        // tested here: it only crashes under `#ifdef DEBUG`, which requires an
        // `is_debug=true` build. The fuzzbuild is a release+dchecks build
        // (is_debug=false, dcheck_always_on=true), so case 8 is a no-op and
        // the .shouldCrash expectation would only produce a false warning.
        // Check that abort_with_sandbox_violation works.
        ("fuzzilli('FUZZILLI_CRASH', 9)", .shouldCrash),
    ],

    additionalCodeGenerators: [
        (ForceJITCompilationThroughLoopGenerator, 5),
        (ForceTurboFanCompilationGenerator, 5),
        (ForceMaglevCompilationGenerator, 5),
        (ForceOsrGenerator, 5),
        // NOTE: TurbofanVerifyTypeGenerator removed: %VerifyType CHECK-crashes
        // on type-feedback divergence, producing false positives.

        (WorkerGenerator, 10),
        (V8GcGenerator, 5),
        (V8AllocationTimeoutGenerator, 5),
        (V8MajorGcGenerator, 5),

        (WasmStructGenerator, 5),
        (WasmArrayGenerator, 5),
        (SharedObjectGenerator, 5),
        (PretenureAllocationSiteGenerator, 5),
        (HoleNanGenerator, 2),
        (UndefinedNanGenerator, 2),
        (StringShapeGenerator, 2),
        (HeapNumberGenerator, 2),

        // Malformed / invisible / cross-language boundary strings (Task 6):
        // targets string flattening, cons-strings, RegExp JIT and Unicode
        // normalization in V8.
        (MalformedStringGenerator, 5),

        // Turboshaft / Maglev targeted generators.
        (TurboshaftTypeConfusionGenerator, 15),
        (TurboshaftRangeInferenceGenerator, 20),
        (ArrayBoundsCheckEliminationGenerator, 20),
        (EscapeAnalysisScalarReplacementGenerator, 20),
        (TypedArrayBoundsCheckEliminationGenerator, 20),
        (TemporalHotLoopGenerator, 5),
    ],

    additionalProgramTemplates: WeightedList<ProgramTemplate>([
        (MapTransitionFuzzer, 2),
        (ValueSerializerFuzzer, 1),
        (V8RegExpFuzzer, 1),
        (WasmFastCallFuzzer, 1),
        (FastApiCallFuzzer, 1),
        (IndirectLazyDeoptFuzzer, 2),
        (RecursiveLazyDeoptFuzzer, 2),
        (HomomorphicFeedbackFuzzer, 2),
        (WasmDeoptFuzzer, 1),
        (WasmInJsInliningFuzzer, 1),
        (WasmTurbofanFuzzer, 1),
        (ProtoAssignSeqOptFuzzer, 2),
        (TurbofanTierUpNonInlinedCallFuzzer, 2),
    ]),

    disabledCodeGenerators: [
        // Legacy wasm exception handling (try/catch/delegate/rethrow with
        // exnref labels) was removed from V8 before 15.x. These generators
        // can never produce their required .wasmExceptionLabel input and
        // only waste generation attempts (log spam: "Cannot produce type
        // Constraint(.wasmExceptionLabel)").
        "WasmLegacyTryCatchGenerator",
        "WasmLegacyTryDelegateGenerator",
        "WasmLegacyRethrowGenerator",
    ],

    disabledMutators: [],

    additionalBuiltins: [
        "gc": .function([.opt(gcOptions.instanceType)] => (.undefined | .jsPromise())),
        "d8": .jsD8,
        "Worker": .jsWorkerConstructor,
        // via --expose-externalize-string:
        "externalizeString": .function([.plain(.jsString)] => .jsString),
        "isOneByteString": .function([.plain(.jsString)] => .boolean),
        "createExternalizableString": .function([.plain(.jsString)] => .jsString),
        "createExternalizableTwoByteString": .function([.plain(.jsString)] => .jsString),
    ],

    additionalObjectGroups: [
        jsD8, jsD8Test, jsD8FastCAPI, gcOptions, .jsWorkers, .jsWorkerPrototype,
        .jsWorkerConstructors,
    ],

    additionalEnumerations: [.gcTypeEnum, .gcExecutionEnum],

    additionalOptionsBags: [],

    optionalPostProcessor: nil
)
