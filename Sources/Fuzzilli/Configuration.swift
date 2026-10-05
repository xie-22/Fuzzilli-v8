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

// TODO(mdanylo): this should be part of the protocol between Fuzzilli and V8.
public struct DifferentialConfig {
    public let dumpFilenamePattern: String

    public init(dumpFilenamePattern: String) {
        self.dumpFilenamePattern = dumpFilenamePattern
    }

    public func getDumpFilename(isOptimized: Bool) -> String {
        let subDirectory = isOptimized ? "optimizedDump" : "unoptimizedDump"
        return String(format: dumpFilenamePattern, subDirectory)
    }

    public func getDumpFilenameParameter(isOptimized: Bool) -> String {
        return "--dump-out-filename=\(getDumpFilename(isOptimized: isOptimized))"
    }

    public static func create(for instanceId: Int, storagePath: String) -> DifferentialConfig {
        let fileName = "output_dump_\(instanceId).txt"
        let pattern = "\(storagePath)/%@/\(fileName)"
        return DifferentialConfig(dumpFilenamePattern: pattern)
    }
}

public struct Configuration {
    /// The config specific to differential fuzzing
    public let diffConfig: DifferentialConfig?

    /// The commandline arguments used by this instance.
    public let arguments: [String]

    /// Timeout in milliseconds after which child processes will be killed.
    public var timeout: UInt32

    /// Log level to use.
    public let logLevel: LogLevel

    /// Code snippets that are be executed during startup and then checked to lead to the expected result.
    public let startupTests: [(String, ExpectedStartupTestResult)]

    /// The fraction of instruction to keep from the original program when minimizing.
    public let minimizationLimit: Double

    /// When receiving programs from another node during distributed fuzzing, discard this percentage of samples.
    public let dropoutRate: Double

    /// Enable the saving of programs that failed or timed-out during execution.
    public let enableDiagnostics: Bool

    /// Whether to enable inspection for generated programs.
    public let enableInspection: Bool

    /// Determines if we want to have a static corpus, i.e. we don't add any
    /// programs to the corpus even if they find new coverage.
    public let staticCorpus: Bool

    /// Additional string that will be stored in the settings.json file and
    /// also appended as a comment in the footer of crashing samples.
    public let tag: String?

    /// Whether the fuzzer is running with wasm features or without.
    public let isWasmEnabled: Bool

    /// Path to the wasm-opt binary to enable Binaryen Wasm generation.
    public let wasmOptPath: String?

    /// The directory in which the corpus and additional diagnostics files are stored.
    public let storagePath: String?

    /// The number of iterations without finding a new interesting program after which
    /// the fuzzer switches from corpus generation to the main fuzzing phase.
    public let corpusGenerationIterations: Int

    /// Advises the fuzzer to generate cases that are more suitable for differential fuzzing.
    public let forDifferentialFuzzing: Bool

    /// The subdirectory in {config.storagePath} at which all programs are stored which could not
    /// be imported due to disabled wasm capabilities in the fuzzer.
    public static let excludedWasmDirectory = "excluded_wasm_programs"

    /// Whether the fuzzer generates bundles containing multiple JavaScript scripts or modules.
    public let generateBundle: Bool

    /// Whether to skip startup crash and timeout tests.
    public let skipStartupTests: Bool

    /// Number of consecutive reproducible executions required before a crash or
    /// differential outcome is registered as a deterministic finding. Flaky
    /// findings below this threshold are discarded (flaky crash suppression, 5C).
    public let reproducibilityRuns: Int

    /// Maximum wall-clock time (in seconds) a single program minimization may
    /// run before it is aborted. Minimization is by far the largest fuzzer
    /// overhead; capping it keeps most wall-clock time available for fuzzing.
    public let minimizationTimeout: TimeInterval

    /// Maximum wall-clock time (seconds) a single CRASH or DIFFERENTIAL
    /// minimization may run. Crash/differential reproducers are rare and must
    /// be shrunk aggressively (to a few KB), so they get a much larger budget
    /// than the high-volume "interesting sample" minimization (which uses
    /// `minimizationTimeout`).
    public let crashMinimizationTimeout: TimeInterval

    public init(
        arguments: [String] = [],
        timeout: UInt32 = 250,
        skipStartupTests: Bool = false,
        reproducibilityRuns: Int = 3,
        minimizationTimeout: TimeInterval = 5.0,
        crashMinimizationTimeout: TimeInterval = 30.0,
        logLevel: LogLevel = .info,
        startupTests: [(String, ExpectedStartupTestResult)] = [],
        minimizationLimit: Double = 0.0,
        dropoutRate: Double = 0,
        enableDiagnostics: Bool = false,
        enableInspection: Bool = false,
        staticCorpus: Bool = false,
        tag: String? = nil,
        isWasmEnabled: Bool = false,
        wasmOptPath: String? = nil,
        generateBundle: Bool = false,
        storagePath: String? = nil,
        corpusGenerationIterations: Int = 100,
        forDifferentialFuzzing: Bool = false,
        instanceId: Int = -1,
        dumplingDumpEnabled: Bool = false
    ) {
        self.arguments = arguments
        self.timeout = timeout
        self.skipStartupTests = skipStartupTests
        self.reproducibilityRuns = reproducibilityRuns
        self.minimizationTimeout = minimizationTimeout
        self.crashMinimizationTimeout = crashMinimizationTimeout
        self.logLevel = logLevel
        self.startupTests = startupTests
        self.dropoutRate = dropoutRate
        self.minimizationLimit = minimizationLimit
        self.enableDiagnostics = enableDiagnostics
        self.enableInspection = enableDiagnostics || enableInspection
        self.staticCorpus = staticCorpus
        self.tag = tag
        self.isWasmEnabled = isWasmEnabled
        self.wasmOptPath = wasmOptPath
        self.generateBundle = generateBundle
        self.storagePath = storagePath
        self.corpusGenerationIterations = corpusGenerationIterations
        self.forDifferentialFuzzing = forDifferentialFuzzing
        self.diffConfig =
            dumplingDumpEnabled
            ? DifferentialConfig.create(for: instanceId, storagePath: storagePath!) : nil
    }

    public func getInstanceSpecificArguments(forReferenceRunner: Bool) -> [String] {
        return diffConfig.map { [$0.getDumpFilenameParameter(isOptimized: !forReferenceRunner)] }
            ?? []
    }
}

public enum ExpectedStartupTestResult {
    case shouldSucceed
    case shouldCrash
    case shouldNotCrash
}

public struct InspectionOptions: OptionSet {
    public let rawValue: Int
    public init(rawValue: Int) {
        self.rawValue = rawValue
    }

    public static let history = InspectionOptions(rawValue: 1 << 0)
    public static let all = InspectionOptions([.history])
}
