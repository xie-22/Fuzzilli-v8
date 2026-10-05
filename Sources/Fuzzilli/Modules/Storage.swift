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

/// Module to store programs to disk.
public class Storage: Module {
    private let storageDir: String
    private let crashesDir: String
    private let duplicateCrashesDir: String
    private let differentialsDir: String
    private let corpusDir: String
    private let statisticsDir: String
    private let stateFile: String
    private let failedDir: String
    private let timeOutDir: String
    private let diagnosticsDir: String
    private let optimizedDumpDir: String
    private let unoptimizedDumpDir: String

    private let statisticsExportInterval: Double?

    private unowned let fuzzer: Fuzzer
    private let logger: Logger

    public init(for fuzzer: Fuzzer, storageDir: String, statisticsExportInterval: Double? = nil) {
        self.storageDir = storageDir
        self.crashesDir = storageDir + "/crashes"
        self.duplicateCrashesDir = storageDir + "/crashes/duplicates"
        self.differentialsDir = storageDir + "/differentials"
        self.corpusDir = storageDir + "/corpus"
        self.failedDir = storageDir + "/failed"
        self.timeOutDir = storageDir + "/timeouts"
        self.statisticsDir = storageDir + "/stats"
        self.stateFile = storageDir + "/state.bin"
        self.diagnosticsDir = storageDir + "/diagnostics"
        self.optimizedDumpDir = storageDir + "/optimizedDump"
        self.unoptimizedDumpDir = storageDir + "/unoptimizedDump"

        self.statisticsExportInterval = statisticsExportInterval

        self.fuzzer = fuzzer
        self.logger = Logger(withLabel: "Storage")
    }

    public func initialize(with fuzzer: Fuzzer) {
        do {
            try FileManager.default.createDirectory(
                atPath: crashesDir, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(
                atPath: duplicateCrashesDir, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(
                atPath: differentialsDir, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(
                atPath: corpusDir, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(
                atPath: statisticsDir, withIntermediateDirectories: true)
            if fuzzer.config.enableDiagnostics {
                try FileManager.default.createDirectory(
                    atPath: failedDir, withIntermediateDirectories: true)
                try FileManager.default.createDirectory(
                    atPath: timeOutDir, withIntermediateDirectories: true)
                try FileManager.default.createDirectory(
                    atPath: diagnosticsDir, withIntermediateDirectories: true)
            }
            if fuzzer.config.diffConfig != nil {
                try FileManager.default.createDirectory(
                    atPath: optimizedDumpDir, withIntermediateDirectories: true)
                try FileManager.default.createDirectory(
                    atPath: unoptimizedDumpDir, withIntermediateDirectories: true)
            }
        } catch {
            logger.fatal(
                "Failed to create storage directories. Is \(storageDir) writable by the current user?"
            )
        }

        struct Settings: Codable {
            var processArguments: [String]
            var tag: String?
        }

        // Write the current settings to disk.
        let settings = Settings(
            processArguments: Array(fuzzer.runner.processArguments[1...]), tag: fuzzer.config.tag)
        var settingsData: Data?
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = .prettyPrinted
            settingsData = try encoder.encode(settings)
        } catch {
            logger.fatal("Failed to encode the settings data: \(error).")
        }

        do {
            let settingsUrl = URL(fileURLWithPath: "\(self.storageDir)/settings.json")
            try settingsData!.write(to: settingsUrl)
        } catch {
            logger.fatal(
                "Failed to write settings to disk. Is \(storageDir) writable by the current user?")
        }

        func signalName(for number: Int) -> String {
            switch number {
            case 1: return "SIGHUP"
            case 2: return "SIGINT"
            case 3: return "SIGQUIT"
            case 4: return "SIGILL"
            case 5: return "SIGTRAP"
            case 6: return "SIGABRT"
            case 7: return "SIGBUS"
            case 8: return "SIGFPE"
            case 9: return "SIGKILL"
            case 11: return "SIGSEGV"
            case 13: return "SIGPIPE"
            case 14: return "SIGALRM"
            case 15: return "SIGTERM"
            case 31: return "SIGSYS"
            default: return "unknown"
            }
        }

        fuzzer.registerEventListener(for: fuzzer.events.CrashFound) { ev in
            let filename = "program_\(self.formatDate())_\(ev.program.id)_\(ev.behaviour.rawValue)"
            if ev.isUnique {
                self.storeProgram(ev.program, as: filename, in: self.crashesDir)
            } else {
                self.storeProgram(ev.program, as: filename, in: self.duplicateCrashesDir)
            }

            // Prominent crash summary on stderr (Task 7): signal type and the
            // absolute path of the stored artifacts. Written to stderr so it
            // does not interfere with the TerminalUI's panel on stdout.
            var termsig = "unknown"
            if let footer = ev.program.comments.at(.footer) {
                for line in footer.components(separatedBy: "\n")
                where line.hasPrefix("TERMSIG:") {
                    let raw = String(line.dropFirst("TERMSIG:".count))
                        .trimmingCharacters(in: .whitespaces)
                    termsig = "\(raw) (\(signalName(for: Int(raw) ?? -1)))"
                }
            }
            let summary = "\u{001B}[1;31m[CRASH] signal=\(termsig) behaviour=\(ev.behaviour.rawValue) unique=\(ev.isUnique)\u{001B}[0m\n\u{001B}[1;31m[CRASH] stored: \(self.crashesDir)/\(filename).js + .fzil\u{001B}[0m"
            FileHandle.standardError.write(Data((summary + "\n").utf8))
        }

        fuzzer.registerEventListener(for: fuzzer.events.DifferentialFound) { ev in
            // 5C: only deterministic differentials are stored as findings.
            guard ev.behaviour == .deterministic else { return }
            let filename = "program_\(self.formatDate())_\(ev.program.id)_\(ev.behaviour.rawValue)"
            self.storeProgram(ev.program, as: filename, in: self.differentialsDir)
        }

        fuzzer.registerEventListener(for: fuzzer.events.InterestingProgramFound) { ev in
            let filename = "program_\(self.formatDate())_\(ev.program.id)"
            self.storeProgram(ev.program, as: filename, in: self.corpusDir)
        }

        if fuzzer.config.enableDiagnostics {
            fuzzer.registerEventListener(for: fuzzer.events.DiagnosticsEvent) { ev in
                let filename = "\(self.formatDate())_\(ev.name)_\(String(currentMillis()))"
                let url = URL(fileURLWithPath: "\(self.diagnosticsDir)/\(filename).diag")
                self.createFile(url, withContent: ev.content)
            }

            fuzzer.registerEventListener(for: fuzzer.events.InvalidProgramFound) { program in
                let filename = "program_\(self.formatDate())_\(program.id)"
                self.storeProgram(program, as: filename, in: self.failedDir)
            }

            fuzzer.registerEventListener(for: fuzzer.events.TimeOutFound) { program in
                let filename = "program_\(self.formatDate())_\(program.id)"
                self.storeProgram(program, as: filename, in: self.timeOutDir)
            }
        }

        // If enabled, export fuzzing statistics to disk in regular intervals.
        if let interval = statisticsExportInterval {
            guard let stats = Statistics.instance(for: fuzzer) else {
                logger.fatal("Requested stats export but no Statistics module is active")
            }
            fuzzer.timers.scheduleTask(every: interval) { self.saveStatistics(stats) }
            fuzzer.registerEventListener(for: fuzzer.events.Shutdown) { _ in
                self.saveStatistics(stats)
            }
        }
    }

    private func createFile(_ url: URL, withContent content: String) {
        do {
            try content.write(to: url, atomically: false, encoding: String.Encoding.utf8)
            // Force the data to stable storage before any further processing
            // (Task 7): crash and corpus files must survive process death.
            if let handle = FileHandle(forWritingAtPath: url.path) {
                try? handle.synchronize()
                try? handle.close()
            }
        } catch {
            logger.error("Failed to write file \(url): \(error)")
        }
    }

    private func createFile(_ url: URL, withContent content: Data) {
        do {
            try content.write(to: url)
            // Force the data to stable storage (Task 7).
            if let handle = FileHandle(forWritingAtPath: url.path) {
                try? handle.synchronize()
                try? handle.close()
            }
        } catch {
            logger.error("Failed to write file \(url): \(error)")
        }
    }

    func storeProgram(_ program: Program, as filename: String, in directory: String) {
        // Always include comments when writing programs to disk
        let options = LiftingOptions.includeComments

        let code = fuzzer.lifter.lift(program, withOptions: options)
        let url = URL(fileURLWithPath: "\(directory)/\(filename).js")
        createFile(url, withContent: code)

        // Also store the FuzzIL program in its protobuf format. This can later be imported again or inspected using the FuzzILTool
        do {
            let pb = try program.asProtobuf().serializedData()
            let url = URL(fileURLWithPath: "\(directory)/\(filename).fzil")
            createFile(url, withContent: pb)
        } catch {
            logger.warning("Failed to serialize program to protobuf: \(error)")
        }

        // If inspection is enabled, we also include the programs ancestor chain in a separate .history file
        if fuzzer.config.enableInspection && program.parent != nil {
            let lifter = FuzzILLifter()

            var ancestors: [Program] = []
            var current: Program? = program
            while current != nil {
                ancestors.append(current!)
                current = current?.parent
            }
            ancestors.reverse()

            var content = ""
            for program in ancestors {
                content += "// ===== [ Program \(program.id) ] =====\n"
                content += lifter.lift(program, withOptions: options) + "\n\n"
            }

            let url = URL(fileURLWithPath: "\(directory)/\(filename).fuzzil.history")
            createFile(url, withContent: content)
        }
    }

    private func saveStatistics(_ stats: Statistics) {
        let statsData = stats.compute()
        let evaluatorStateData = fuzzer.evaluator.exportState()

        do {
            let statsData = try statsData.jsonUTF8Data()
            let date = formatDate()
            let statsUrl = URL(fileURLWithPath: "\(self.statisticsDir)/\(date).json")
            try statsData.write(to: statsUrl)
            let evaluatorStateUrl = URL(
                fileURLWithPath: "\(self.statisticsDir)/\(date)_evaluator_state.bin")
            try evaluatorStateData.write(to: evaluatorStateUrl)

        } catch {
            logger.error("Failed to write statistics or evaluator state data to disk: \(error)")
        }
    }

    private func formatDate() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMddHHmmss"
        return formatter.string(from: Date())
    }
}
