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

/// Generators targeting the Turboshaft / Maglev optimization pipelines of V8 15.3.
///
/// Attack surfaces covered (see §3A of the fuzzing plan):
///  - Type narrowing & range inference inconsistencies (TypedOptimizationsPhase,
///    RangeInferencePhase): bitwise ops on mixed smi/double feedback, shift
///    counts 0..63, signed/unsigned overflow, float subnormals, NaN, -0.0, Infinity.
///  - Bounds check elimination & array length tracking: side-effectful length
///    mutations (push/pop/length assignment) inside loop bodies whose guards
///    read `.length`, ElementsKind transitions (PACKED_SMI -> PACKED_DOUBLE ->
///    HOLEY) across calls of the same optimized function.
///  - Escape analysis & scalar replacement: allocations crossing function
///    boundaries, closures capturing locals, forced escape through an array.
///
/// All generators emit V8 natives syntax (%PrepareFunctionForOptimization,
/// %OptimizeMaglevOnNextCall, %OptimizeFunctionOnNextCall, %DeoptimizeFunction)
/// and require --allow-natives-syntax (enabled by the v8 profile).
/// NOTE: %VerifyType is deliberately NOT used: it CHECK-crashes on type-feedback
/// divergence, turning the miscompilations we want to find into false crashes.

/// Shared helpers ---------------------------------------------------------------

private let turboshaftBitwiseOps: [BinaryOperator] = [
    .BitAnd, .BitOr, .Xor, .LShift, .RShift, .UnRShift, .Add, .Sub, .Mul, .Div, .Mod,
]

private let turboshaftShiftOps: [BinaryOperator] = [.LShift, .RShift, .UnRShift]

/// Generate an "interesting" floating point value: NaN, +/-Infinity, -0.0,
/// a subnormal, or the 2^53 smi/double boundary.
private func turboshaftSpecialNumber(_ b: ProgramBuilder) -> Variable {
    switch Int.random(in: 0..<6) {
    case 0:
        // NaN via 0 / 0
        return b.binary(b.loadInt(0), b.loadInt(0), with: .Div)
    case 1:
        // +Infinity via 1 / 0
        return b.binary(b.loadInt(1), b.loadInt(0), with: .Div)
    case 2:
        // -Infinity via -(1 / 0)
        let inf = b.binary(b.loadInt(1), b.loadInt(0), with: .Div)
        return b.unary(.Minus, inf)
    case 3:
        // -0.0 via -(0 / 1)
        let zero = b.binary(b.loadInt(0), b.loadInt(1), with: .Div)
        return b.unary(.Minus, zero)
    case 4:
        // Smallest positive subnormal double (5e-324)
        return b.loadFloat(Double.leastNonzeroMagnitude)
    default:
        // 2^53: the largest exactly representable integer in a double
        return b.loadFloat(9007199254740992.0)
    }
}

/// Call `f` with arguments that alternate between smi, double, and
/// "interesting" float values to build conflicting type feedback.
private func turboshaftFeedbackCalls(_ b: ProgramBuilder, to f: Variable, count: Int) {
    for _ in 0..<count {
        let smallInt = b.loadInt(Int64.random(in: -1000...1000))
        let float = b.loadFloat(Double.random(in: -1000...1000))
        let special = turboshaftSpecialNumber(b)
        let bigInt = b.loadInt(Int64.random(in: Int64(Int32.min)...Int64(Int32.max)))

        switch Int.random(in: 0..<4) {
        case 0:
            b.callFunction(f, withArgs: [smallInt, bigInt], guard: probability(0.3))
        case 1:
            b.callFunction(f, withArgs: [float, smallInt], guard: probability(0.3))
        case 2:
            b.callFunction(f, withArgs: [special, bigInt], guard: probability(0.3))
        default:
            b.callFunction(f, withArgs: [smallInt, float], guard: probability(0.3))
        }
    }
}

/// Force tier-up of `f` to Maglev (50%) or Turbofan, then with 50% probability
/// deoptimize and re-optimize the function to exercise the deoptimization
/// expansion and re-optimization paths.
private func turboshaftForceTierUp(_ b: ProgramBuilder, _ f: Variable) {
    if probability(0.5) {
        b.eval("%OptimizeMaglevOnNextCall(%@)", with: [f])
    } else {
        b.eval("%OptimizeFunctionOnNextCall(%@)", with: [f])
    }
    b.callFunction(f, withArgs: b.randomArguments(forCalling: f))

    if probability(0.5) {
        b.eval("%DeoptimizeFunction(%@)", with: [f])
        b.callFunction(f, withArgs: b.randomArguments(forCalling: f))
        b.eval("%OptimizeFunctionOnNextCall(%@)", with: [f])
        b.callFunction(f, withArgs: b.randomArguments(forCalling: f))
    }
}

/// Generators ----------------------------------------------------------------------

/// Mix smi/double/NaN/-0.0/Infinity values with bitwise operations, shifts by
/// 0..63, int32/uint32 truncations, and divisions by -1..2 inside a hot loop.
/// The conflicting type feedback is designed to make Turboshaft's type lattice
/// (--turboshaft-assert-types) diverge from the runtime values.
public let TurboshaftTypeConfusionGenerator = CodeGenerator(
    "TurboshaftTypeConfusionGenerator"
) { b in
    let f = b.buildPlainFunction(with: .parameters(n: 2)) { args in
        var v = args[0]
        let w = args[1]

        b.buildRepeatLoop(n: Int.random(in: 2...6)) { _ in
            v = b.binary(v, w, with: turboshaftBitwiseOps.randomElement()!)
            // Int32 truncation (x | 0) and UInt32 truncation (x >>> 0).
            v = b.binary(v, b.loadInt(0), with: .BitOr)
            v = b.binary(v, b.loadInt(0), with: .UnRShift)
            // Variable shift counts across the 0..63 boundary.
            let shiftCount = b.loadInt(Int64.random(in: 0...63))
            v = b.binary(v, shiftCount, with: turboshaftShiftOps.randomElement()!)
            // Mix in special floating point values.
            v = b.binary(v, turboshaftSpecialNumber(b), with: [.Add, .Sub, .Mul].randomElement()!)
            // Division / modulo by small values including -1 and 0.
            let small = b.loadInt(Int64.random(in: -2...2))
            v = b.binary(v, small, with: [.Div, .Mod].randomElement()!)
            // Overflow-prone multiplication: MAX_INT32-ish values.
            let big = b.loadInt(Int64.random(in: 2_000_000_000...2_200_000_000))
            v = b.binary(v, big, with: [.Mul, .Add].randomElement()!)
        }
        b.doReturn(v)
    }

    b.eval("%PrepareFunctionForOptimization(%@)", with: [f])
    turboshaftFeedbackCalls(b, to: f, count: 3)

    if probability(0.5) {
        b.eval("%OptimizeMaglevOnNextCall(%@)", with: [f])
    } else {
        b.eval("%OptimizeFunctionOnNextCall(%@)", with: [f])
    }
    b.callFunction(f, withArgs: [b.loadInt(1), b.loadInt(2)])

    // Deopt + re-opt cycle with different feedback.
    if probability(0.7) {
        b.eval("%DeoptimizeFunction(%@)", with: [f])
        turboshaftFeedbackCalls(b, to: f, count: 2)
        b.eval("%OptimizeFunctionOnNextCall(%@)", with: [f])
        b.callFunction(f, withArgs: [turboshaftSpecialNumber(b), b.loadInt(-1)])
    }
}

/// Drive arithmetic through clamps, wraparound accumulators, division by
/// -1/0/1, Math.imul/min/max/clz32 in a hot loop. Targets the range inference
/// and integer overflow tracking of Turboshaft.
public let TurboshaftRangeInferenceGenerator = CodeGenerator(
    "TurboshaftRangeInferenceGenerator"
) { b in
    let f = b.buildPlainFunction(with: .parameters(n: 1)) { args in
        var v = args[0]
        var acc = b.loadInt(0)

        b.buildRepeatLoop(n: Int.random(in: 2...8)) { _ in
            // Clamp v into [0, 1000] to build a tight range lattice.
            v = b.ternary(b.compare(v, with: b.loadInt(0), using: .lessThan), b.loadInt(0), v)
            v = b.ternary(
                b.compare(v, with: b.loadInt(1000), using: .greaterThan), b.loadInt(1000), v)

            // Wraparound accumulator.
            acc = b.binary(acc, v, with: .Add)
            acc = b.ternary(
                b.compare(acc, with: b.loadInt(1_000_000), using: .greaterThan), b.loadInt(0), acc)
            acc = b.binary(acc, b.loadInt(0), with: .BitOr)

            // Division / modulo by -1, 0, and 1 (INT_MIN / -1 overflow case).
            let small = b.loadInt(Int64.random(in: -1...1))
            v = b.binary(v, small, with: [.Div, .Mod].randomElement()!)

            // Math intrinsics with range-relevant semantics.
            let math = b.createNamedVariable(forBuiltin: "Math")
            let operand = b.loadInt(Int64.random(in: -1000...1000))
            switch Int.random(in: 0..<3) {
            case 0:
                v = b.callMethod("imul", on: math, withArgs: [v, operand])
            case 1:
                v = b.callMethod("min", on: math, withArgs: [v, b.loadInt(500)])
            default:
                v = b.callMethod("max", on: math, withArgs: [v, b.loadInt(500)])
            }
        }
        b.doReturn(acc)
    }

    b.eval("%PrepareFunctionForOptimization(%@)", with: [f])
    // Straddle the clamp boundaries with the feedback inputs.
    b.callFunction(f, withArgs: [b.loadInt(-1)], guard: probability(0.3))
    b.callFunction(f, withArgs: [b.loadInt(500)], guard: probability(0.3))
    b.callFunction(f, withArgs: [b.loadInt(2000)], guard: probability(0.3))
    b.callFunction(f, withArgs: [b.loadFloat(Double.nan)], guard: probability(0.3))

    turboshaftForceTierUp(b, f)
    b.callFunction(f, withArgs: [b.loadInt(Int64(Int32.min))])
}

/// Loop whose guard reads `arr.length` while the body mutates the array length
/// via push/pop, direct length assignment, and hole creation. Combined with
/// per-call ElementsKind transitions (packed smi / packed double / holey) this
/// targets bounds check elimination and length-tracking assumptions.
public let ArrayBoundsCheckEliminationGenerator = CodeGenerator(
    "ArrayBoundsCheckEliminationGenerator"
) { b in
    let f = b.buildPlainFunction(with: .parameters(n: 1)) { args in
        let arr = args[0]

        b.buildForLoop(
            i: { b.loadInt(0) },
            { i in b.compare(i, with: b.getProperty("length", of: arr), using: .lessThan) },
            { i in b.unary(.PostInc, i) },
            { i, _ in
                // Read arr[i] (dynamic index through computed property access).
                let x = b.getComputedProperty(i, of: arr)

                // Side effects that mutate the array length inside the loop.
                switch Int.random(in: 0..<4) {
                case 0:
                    b.callMethod("push", on: arr, withArgs: [b.binary(x, b.loadInt(1), with: .Add)])
                case 1:
                    b.callMethod("pop", on: arr)
                case 2:
                    // Truncate / extend the array through its length property.
                    b.setProperty("length", of: arr, to: b.binary(i, b.loadInt(1), with: .Add))
                default:
                    // Create a hole far out of bounds (PACKED -> HOLEY transition).
                    b.setElement(Int64.random(in: 1000...10000), of: arr, to: x)
                }
            }
        )
    }

    // Per-call ElementsKind polymorphism: PACKED_SMI, PACKED_DOUBLE, PACKED
    // (object) and HOLEY variants of the same optimized function.
    let smiArray = b.createIntArray(with: [1, 2, 3, 4, 5, 6, 7, 8])
    let doubleArray = b.createFloatArray(with: [1.5, 2.5, 3.5, 4.5])
    let objectArray = b.createArray(with: [b.loadString("a"), b.loadString("b"), b.loadString("c")])
    let holeyArray = b.createArray(with: [b.loadInt(1)])
    b.setElement(10, of: holeyArray, to: b.loadInt(99))

    b.eval("%PrepareFunctionForOptimization(%@)", with: [f])
    b.callFunction(f, withArgs: [smiArray], guard: probability(0.3))
    b.callFunction(f, withArgs: [doubleArray], guard: probability(0.3))
    b.callFunction(f, withArgs: [objectArray], guard: probability(0.3))
    b.callFunction(f, withArgs: [holeyArray], guard: probability(0.3))

    turboshaftForceTierUp(b, f)
    b.callFunction(f, withArgs: [holeyArray])
}

/// Hot loop over a Float64Array backed by a resizable ArrayBuffer. The loop
/// guard reads `.length` while the body performs out-of-bounds element
/// accesses and resizes the underlying buffer. Targets bounds check
/// elimination and backing-store/length tracking in Turboshaft: if the
/// compiler caches the length or backing store across the resize, a
/// subsequent element access escapes the real bounds and turns into an
/// ASAN-visible OOB read/write.
public let TypedArrayBoundsCheckEliminationGenerator = CodeGenerator(
    "TypedArrayBoundsCheckEliminationGenerator"
) { b in
    // Resizable ArrayBuffer (RAB) with a Float64Array view.
    let rab = b.construct(
        b.createNamedVariable(forBuiltin: "ArrayBuffer"),
        withArgs: [
            b.loadInt(64),
            b.buildObjectLiteral { o in o.addProperty("maxByteLength", as: b.loadInt(8192)) },
        ])
    let f64Ctor = b.createNamedVariable(forBuiltin: "Float64Array")
    let ta = b.construct(f64Ctor, withArgs: [rab])

    let f = b.buildPlainFunction(with: .parameters(n: 1)) { args in
        let view = args[0]

        b.buildForLoop(
            i: { b.loadInt(0) },
            { i in b.compare(i, with: b.getProperty("length", of: view), using: .lessThan) },
            { i in b.unary(.PostInc, i) },
            { i, _ in
                let x = b.getComputedProperty(i, of: view)

                switch Int.random(in: 0..<5) {
                case 0:
                    // Negative-index write (no-op at runtime, but a target for
                    // a mis-eliminated bounds check).
                    b.setComputedProperty(
                        b.loadInt(Int64.random(in: -100...(-1))), of: view, to: x)
                case 1:
                    // Far out-of-bounds write above the view.
                    b.setComputedProperty(
                        b.loadInt(Int64.random(in: 1000...10000)), of: view, to: x)
                case 2:
                    // Out-of-bounds read above the view.
                    let idx = b.binary(i, b.loadInt(9999), with: .Add)
                    let _ = b.getComputedProperty(idx, of: view)
                case 3:
                    // Detach the backing store via transfer(). The view is now
                    // detached, so a mis-eliminated bounds/detachment check
                    // reads the moved/freed backing store (UAF / stale-pointer
                    // access) instead of in-bounds stale data.
                    let buffer = b.getProperty("buffer", of: view)
                    b.callMethod("transfer", on: buffer, withArgs: [], guard: true)
                    let _ = b.getComputedProperty(i, of: view)
                default:
                    // Resize the underlying RAB under the live view. Resize
                    // may throw (shrinking below used bytes), so guard it.
                    let buffer = b.getProperty("buffer", of: view)
                    b.callMethod(
                        "resize", on: buffer,
                        withArgs: [b.loadInt(Int64.random(in: 0...256))], guard: true)
                }
            }
        )
        b.doReturn(b.getComputedProperty(b.loadInt(0), of: view))
    }

    b.eval("%PrepareFunctionForOptimization(%@)", with: [f])
    b.callFunction(f, withArgs: [ta], guard: probability(0.3))
    b.callFunction(f, withArgs: [ta], guard: probability(0.3))

    turboshaftForceTierUp(b, f)
    b.callFunction(f, withArgs: [ta])
}

/// Allocate objects, pass them across function boundaries, capture them in
/// closures, then force their escape through an array. Targets the escape
/// analysis / scalar replacement of the optimizing compilers.
public let EscapeAnalysisScalarReplacementGenerator = CodeGenerator(
    "EscapeAnalysisScalarReplacementGenerator"
) { b in
    let f = b.buildPlainFunction(with: .parameters(n: 0)) { _ in
        // The candidate for scalar replacement.
        let o = b.buildObjectLiteral { obj in
            obj.addProperty("x", as: b.loadInt(1))
            obj.addProperty("y", as: b.loadFloat(2.5))
            obj.addProperty("z", as: b.loadString("v8"))
        }

        // Callee that reads/writes the object. If it is inlined and `o` does
        // not escape, the object may be scalar-replaced.
        let g = b.buildPlainFunction(with: .parameters(.object())) { gArgs in
            let p = gArgs[0]
            let x = b.getProperty("x", of: p)
            b.setProperty("y", of: p, to: b.binary(x, b.loadInt(1), with: .Add))
            b.updateProperty("z", of: p, with: b.loadString("!"), using: .Add)
        }

        // Closure capturing `o`.
        let h = b.buildArrowFunction(with: .parameters(n: 0)) { _ in
            b.getProperty("x", of: o)
        }

        // Hot loop through the callee.
        b.buildRepeatLoop(n: Int.random(in: 2...8)) { _ in
            b.callFunction(g, withArgs: [o])
        }

        // Read through the closure.
        b.callFunction(h, withArgs: [])

        // Force an escape through an array to defeat the analysis and leave
        // stale/replaced references behind.
        let sink = b.createArray(with: [])
        b.callMethod("push", on: sink, withArgs: [o])

        b.doReturn(o)
    }

    b.eval("%PrepareFunctionForOptimization(%@)", with: [f])
    b.callFunction(f, withArgs: [], guard: probability(0.3))
    b.callFunction(f, withArgs: [], guard: probability(0.3))

    turboshaftForceTierUp(b, f)
    b.callFunction(f, withArgs: [])
}

/// Temporal API nanosecond arithmetic in a hot loop. Temporal.PlainTime.add
/// with loop-varying nanosecond counts exercises the range/type modeling of
/// the optimizing compilers on Temporal objects.
public let TemporalHotLoopGenerator = CodeGenerator(
    "TemporalHotLoopGenerator"
) { b in
    let f = b.buildPlainFunction(with: .parameters(n: 1)) { args in
        var x = args[0]
        let temporal = b.createNamedVariable(forBuiltin: "Temporal")
        let now = b.getProperty("Now", of: temporal)
        let durationConstructor = b.getProperty("Duration", of: temporal)

        b.buildRepeatLoop(n: Int.random(in: 2...5)) { _ in
            let plainTime = b.callMethod("plainTimeISO", on: now)
            let durationBag = b.buildObjectLiteral { obj in
                obj.addProperty("nanoseconds", as: x)
            }
            let duration = b.callMethod("from", on: durationConstructor, withArgs: [durationBag])
            let added = b.callMethod("add", on: plainTime, withArgs: [duration])
            x = b.getProperty("nanosecond", of: added)
        }
        b.doReturn(x)
    }

    b.eval("%PrepareFunctionForOptimization(%@)", with: [f])
    b.callFunction(f, withArgs: [b.loadInt(1)], guard: probability(0.3))
    b.callFunction(f, withArgs: [b.loadInt(999_999_999)], guard: probability(0.3))
    b.callFunction(f, withArgs: [b.loadInt(-999_999_999)], guard: probability(0.3))

    turboshaftForceTierUp(b, f)
    b.callFunction(f, withArgs: [b.loadInt(1_000_000_001)])
}
