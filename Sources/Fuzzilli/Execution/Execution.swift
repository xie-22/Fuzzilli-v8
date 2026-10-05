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

/// The possible outcome of a program execution.
public enum ExecutionOutcome: CustomStringConvertible, Equatable, Hashable {
    case crashed(Int)
    case failed(Int)
    case succeeded
    case timedOut
    // This outcome is added to support native differential fuzzing.
    // It should get very similar treatment to crashed -> if the run resulted
    // in a differential, most likely there's a bug.
    // Please note that this feature is unstable yet, so the statement above
    // might not always be the case.
    case differential

    public var description: String {
        switch self {
        case .crashed(let signal):
            return "Crashed (signal \(signal))"
        case .failed(let exitcode):
            return "Failed (exit code \(exitcode))"
        case .succeeded:
            return "Succeeded"
        case .timedOut:
            return "TimedOut"
        case .differential:
            return "Differential"
        }
    }

    public func isCrash() -> Bool {
        if case .crashed = self {
            return true
        } else {
            return false
        }
    }

    public func isFailure() -> Bool {
        if case .failed = self {
            return true
        } else {
            return false
        }
    }

    public func isDifferential() -> Bool {
        if case .differential = self {
            return true
        } else {
            return false
        }
    }
}

/// The result of executing a program.
public protocol Execution {
    var outcome: ExecutionOutcome { get }
    var stdout: String { get }
    var stderr: String { get }
    var fuzzout: String { get }
    var execTime: TimeInterval { get }
}

/// Normalize nondeterministic noise in execution output before differential
/// comparison:
///  - stack frame lines ("at <fn> (path:line:col)") are collapsed to a
///    canonical "<frame>" form so that inlining/frame-layout differences
///    between the optimized and unoptimized tiers do not produce false
///    differentials,
///  - NaN payloads (nan(0x...)) and bare NaN/-NaN are unified to "NaN",
///  - hex addresses (>= 4 hex digits) are replaced with 0xADDR,
///  - "Maximum call stack size exceeded" dumps: their location (header
///    line number, source excerpt, and caret) depends on each tier's frame
///    size rather than on program semantics, so it is collapsed to a
///    canonical form. The presence/absence of the overflow is preserved,
///    so a real miscompilation that causes unbounded recursion on only one
///    tier still surfaces as a differential.
func normalizeDifferentialOutput(_ raw: String) -> String {
    var lines: [String] = []
    for line in raw.split(separator: "\n", omittingEmptySubsequences: false) {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        if trimmed.hasPrefix("at ")
            && trimmed.range(of: #"\(\S+:\d+:\d+\)"#, options: .regularExpression) != nil
        {
            lines.append("    at <frame>")
            continue
        }
        lines.append(String(line))
    }
    var normalized = lines.joined(separator: "\n")

    normalized = normalized.replacingOccurrences(
        of: #"-?nan\(0x[0-9a-fA-F]+\)"#, with: "nan(0xADDR)", options: .regularExpression)
    normalized = normalized.replacingOccurrences(
        of: #"(?<![\w.])-?NaN(?![\w])"#, with: "NaN", options: .regularExpression)
    normalized = normalized.replacingOccurrences(
        of: #"0x[0-9a-fA-F]{4,}"#, with: "0xADDR", options: .regularExpression)

    // A stack-overflow dump's location (header line number, source
    // excerpt, caret) is a function of the tier's frame size, not of
    // program correctness. Collapse it so Ignition and Turboshaft agree.
    normalized = normalized.replacingOccurrences(
        of: #"\S+:\d+(?::\d+)?: RangeError: Maximum call stack size exceeded\n[^\n]*\n[^\n]*\nRangeError: Maximum call stack size exceeded"#,
        with: "RangeError: Maximum call stack size exceeded\nRangeError: Maximum call stack size exceeded",
        options: .regularExpression)
    return normalized
}

/// Format the diff of two execution outputs for storage in the differential footer.
private func formatDiff(label: String, optData: String, unoptData: String) -> String {
    return """
        === OPT \(label) ===
        \(optData)

        === UNOPT \(label) ===
        \(unoptData)
        """
}

/// Struct to capture result of exection in differential mode
struct DiffExecution: Execution {
    let outcome: ExecutionOutcome
    let execTime: TimeInterval
    let stdout: String
    let stderr: String
    let fuzzout: String

    private init(
        outcome: ExecutionOutcome,
        execTime: TimeInterval,
        stdout: String,
        stderr: String,
        fuzzout: String
    ) {
        self.outcome = outcome
        self.execTime = execTime
        self.stdout = stdout
        self.stderr = stderr
        self.fuzzout = fuzzout
    }

    // TODO(mdanylo): we shouldn't pass dump outputs as a separate parameter,
    // instead we should rather make them a part of a REPRL protocol between Fuzzilli and V8.
    static func diff(
        optExec: Execution, unoptExec: Execution,
        optDumpOut: String, unoptDumpOut: String
    ) -> Execution {

        assert(optExec.outcome == .succeeded && unoptExec.outcome == .succeeded)

        let relateOutcome = DiffOracle.relate(optDumpOut, with: unoptDumpOut)

        return DiffExecution(
            outcome: relateOutcome ? .succeeded : .differential,
            execTime: optExec.execTime,
            stdout: formatDiff(
                label: "STDOUT", optData: optExec.stdout, unoptData: unoptExec.stdout),
            stderr: formatDiff(
                label: "STDERR", optData: optExec.stderr, unoptData: unoptExec.stderr),
            fuzzout: formatDiff(
                label: "FUZZOUT", optData: optExec.fuzzout, unoptData: unoptExec.fuzzout)
        )
    }

    /// Fallback differential result based on observable output comparison.
    /// Used when the target engine has no Dumpling dumping support: the
    /// optimized and unoptimized runs must then produce byte-identical
    /// stdout and fuzzout (the profile's determinism shim removes
    /// Date/Math.random/Temporal nondeterminism).
    static func outputsDiffer(
        optExec: Execution, unoptExec: Execution
    ) -> Execution {
        assert(optExec.outcome == .succeeded && unoptExec.outcome == .succeeded)

        return DiffExecution(
            outcome: .differential,
            execTime: optExec.execTime,
            stdout: formatDiff(
                label: "STDOUT",
                optData: normalizeDifferentialOutput(optExec.stdout),
                unoptData: normalizeDifferentialOutput(unoptExec.stdout)),
            stderr: formatDiff(
                label: "STDERR", optData: optExec.stderr, unoptData: unoptExec.stderr),
            fuzzout: formatDiff(
                label: "FUZZOUT",
                optData: normalizeDifferentialOutput(optExec.fuzzout),
                unoptData: normalizeDifferentialOutput(unoptExec.fuzzout))
        )
    }
}
