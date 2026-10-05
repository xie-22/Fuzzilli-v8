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

/// Timeouts are configured either by a single value, then this value will be
/// used, or by an interval, in which case a value will be determined on
/// start-up. Timeouts are in milliseconds.
public enum Timeout {
    case value(UInt32)
    case interval(UInt32, UInt32)

    public func maxTimeout() -> UInt32 {
        switch self {
        case .value(let value):
            return value
        case .interval(_, let max):
            return max
        }
    }
}

public class Fuzzer {
    /// Id of this fuzzer.
    public let id: UUID

    /// Has this fuzzer been initialized?
    public private(set) var isInitialized = false

    /// Has this fuzzer been stopped?
    public private(set) var isStopped = false

    /// The configuration used by this fuzzer.
    public var config: Configuration

    /// The list of events that can be dispatched on this fuzzer instance.
    public let events: Events

    /// Timer API for this fuzzer.
    public let timers: Timers

    /// The script runner used to execute generated scripts.
    public let runner: ScriptRunner

    /// The script runners used to compare against in differential executions.
    public let referenceRunner: ScriptRunner?

    /// The fuzzer engine producing new programs from existing ones and executing them.
    public let engine: FuzzEngine

    /// The active code generators. It is possible to change these (temporarily) at runtime.
    public private(set) var codeGenerators: WeightedList<CodeGenerator>

    /// Feedback-driven scheduler steering the selection of code generators
    /// based on their runtime outcomes (coverage, crashes, differentials).
    private let generatorScheduler: MarkovGeneratorScheduler

    // This needs to stay in sync with the provided codeGenerators.
    public private(set) var contextGraph: ContextGraph

    /// The active program templates.
    public let programTemplates: WeightedList<ProgramTemplate>

    /// The mutators used by the engine.
    public let mutators: WeightedList<Mutator>

    /// The evaluator to score generated programs.
    public let evaluator: ProgramEvaluator

    /// The model of the target environment.
    public let environment: JavaScriptEnvironment

    /// The lifter to translate FuzzIL programs to the target language.
    public let lifter: Lifter

    /// The corpus of "interesting" programs found so far.
    public let corpus: Corpus

    /// The minimizer to shrink programs that cause crashes or trigger new interesting behaviour.
    public let minimizer: Minimizer

    /// The engine used for initial corpus generation (if performed).
    public let corpusGenerationEngine: GenerativeEngine

    /// The possible states of a fuzzer.
    public enum State {
        case uninitialized
        case waiting
        case corpusImport
        case corpusGeneration
        case fuzzing
    }

    /// The current state of this fuzzer.
    public private(set) var state: State = .uninitialized

    private func changeState(to newState: State) {
        logger.info("Changing state from \(state) to \(newState)")
        assert(newState != .uninitialized)
        assert(newState != .waiting || state == .uninitialized)
        assert(state != .fuzzing)
        state = newState
    }

    private let startTime = Date()

    public var isDifferentialFuzzing: Bool {
        return referenceRunner != nil
    }

    public func uptime() -> TimeInterval {
        return -startTime.timeIntervalSinceNow
    }

    var modules = [String: Module]()
    private let queue: DispatchQueue
    private let fuzzGroup = DispatchGroup()
    private var logger: Logger

    public enum ExitCondition {
        case none
        case iterationsPerformed(Int)
        case timeFuzzed(TimeInterval)
    }

    private var exitCondition = ExitCondition.none
    private var iterations = 0
    private var iterationOfLastInterestingSample = 0
    private var currentCorpusImportJob = CorpusImportJob(corpus: [], mode: .full)

    private var iterationsSinceLastInterestingProgram: Int {
        assert(iterations >= iterationOfLastInterestingSample)
        return iterations - iterationOfLastInterestingSample
    }

    private final class WeakFuzzerRef {
        weak var value: Fuzzer?
        init(_ value: Fuzzer) {
            self.value = value
        }
    }

    private static let dispatchQueueKey = DispatchSpecificKey<WeakFuzzerRef>()

    public init(
        configuration: Configuration, scriptRunner: ScriptRunner,
        referenceScriptRunner: ScriptRunner?, engine: FuzzEngine, mutators: WeightedList<Mutator>,
        codeGenerators: WeightedList<CodeGenerator>,
        programTemplates: WeightedList<ProgramTemplate>, evaluator: ProgramEvaluator,
        environment: JavaScriptEnvironment, lifter: Lifter, corpus: Corpus, minimizer: Minimizer,
        queue: DispatchQueue? = nil
    ) {
        let uniqueId = UUID()
        self.id = uniqueId
        self.queue =
            queue ?? DispatchQueue(label: "Fuzzer \(uniqueId)", target: DispatchQueue.global())

        self.config = configuration
        self.events = Events()
        self.timers = Timers(queue: self.queue)
        self.engine = engine
        self.mutators = mutators
        self.codeGenerators = codeGenerators

        self.programTemplates = programTemplates
        self.evaluator = evaluator
        self.environment = environment
        self.lifter = lifter
        self.corpus = corpus
        self.runner = scriptRunner
        self.referenceRunner = referenceScriptRunner
        self.minimizer = minimizer
        self.logger = Logger(withLabel: "Fuzzer")
        self.generatorScheduler = MarkovGeneratorScheduler(generators: codeGenerators)
        self.contextGraph = ContextGraph(
            for: codeGenerators, isBundle: configuration.generateBundle, withLogger: self.logger,
            scheduler: self.generatorScheduler)

        self.corpusGenerationEngine = GenerativeEngine(generateBundle: configuration.generateBundle)
        if let postProcessor = engine.postProcessor {
            corpusGenerationEngine.registerPostProcessor(postProcessor)
        }

        self.queue.setSpecific(key: Fuzzer.dispatchQueueKey, value: WeakFuzzerRef(self))

        #if DEBUG
            do {
                let allNames =
                    self.codeGenerators.map { $0.name }
                    + self.mutators.map { $0.name }
                    + self.programTemplates.map { $0.name }
                var seen = Set<String>()
                let duplicateNames = allNames.filter { !seen.insert($0).inserted }
                assert(
                    duplicateNames.isEmpty,
                    "Contributor names must be unique, found duplicates: \(duplicateNames)")

                let allStubs = self.codeGenerators.flatMap { $0.parts }
                var seenStubs = Set<ObjectIdentifier>()
                let duplicateStubs = allStubs.filter {
                    !seenStubs.insert(ObjectIdentifier($0)).inserted
                }
                assert(
                    duplicateStubs.isEmpty,
                    "CodeGenerator stubs must be unique, found duplicate: \(duplicateStubs)")
            }
        #endif
    }

    public static var current: Fuzzer? {
        return DispatchQueue.getSpecific(key: Fuzzer.dispatchQueueKey)?.value
    }

    public func async(do block: @escaping () -> Void) {
        queue.async {
            guard !self.isStopped else { return }
            block()
        }
    }

    public func sync(do block: () -> Void) {
        guard !self.isStopped else { return }
        if Fuzzer.current === self {
            block()
        } else {
            queue.sync {
                guard !self.isStopped else { return }
                block()
            }
        }
    }

    public func sync<T>(do block: () throws -> T) rethrows -> T {
        if Fuzzer.current === self {
            return try block()
        } else {
            return try queue.sync(execute: block)
        }
    }

    public func setCodeGenerators(_ generators: WeightedList<CodeGenerator>) {
        guard generators.contains(where: { $0.useInPrefix }) else {
            fatalError(
                "Code generators must contain at least one generator to be used in the prefix")
        }
        self.contextGraph = ContextGraph(
            for: generators, isBundle: self.config.generateBundle, withLogger: self.logger,
            scheduler: self.generatorScheduler)
        self.codeGenerators = generators
    }

    public func addModule(_ module: Module) {
        assert(!isInitialized)
        assert(modules[module.name] == nil)
        modules[module.name] = module
        assert(modules.values.filter({ $0 is DistributedFuzzingChildNode }).count <= 1)
    }

    public func initialize() {
        dispatchPrecondition(condition: .onQueue(queue))
        assert(!isInitialized)

        runner.initialize(with: self)
        if let referenceRunner {
            referenceRunner.initialize(with: self)
        }

        engine.initialize(with: self)
        evaluator.initialize(with: self)
        environment.initialize(with: self)
        corpus.initialize(with: self)
        minimizer.initialize(with: self)
        corpusGenerationEngine.initialize(with: self)

        for module in modules.values {
            module.initialize(with: self)
        }

        var lastCheck = Date()
        timers.scheduleTask(every: 1 * Minutes) { [weak self] in
            guard let self = self else { return }
            let now = Date()
            let interval = now.timeIntervalSince(lastCheck)
            lastCheck = now
            if interval > 180 {
                self.logger.warning(
                    "Fuzzer appears unresponsive (watchdog triggered after \(Int(interval))s)."
                )
            }
        }

        assert(state == .uninitialized || state == .corpusImport)
        if state == .uninitialized {
            let isChildNode = modules.values.contains(where: { $0 is DistributedFuzzingChildNode })
            if isChildNode {
                changeState(to: .waiting)
            } else {
                assert(corpus.isEmpty)
                changeState(to: .corpusGeneration)
            }
        }

        dispatchEvent(events.Initialized)
        logger.info("Initialized")
        isInitialized = true
    }

    public func updateStateAfterSynchronizingWithParentNode() {
        if state != .waiting { return }

        if corpus.isEmpty && config.staticCorpus {
            logger.info("Waiting some more time to receive corpus samples from parent instance...")
            return timers.runAfter(15 * Seconds, updateStateAfterSynchronizingWithParentNode)
        } else if corpus.isEmpty {
            changeState(to: .corpusGeneration)
        } else {
            changeState(to: .fuzzing)
        }

        assert(state != .waiting)
        dispatchEvent(events.Synchronized)
    }

    public func start(runUntil exitCondition: ExitCondition = .none) {
        dispatchPrecondition(condition: .onQueue(queue))
        assert(isInitialized)
        self.exitCondition = exitCondition
        logger.info("Let's go!")
        fuzzOne()
    }

    public func shutdown(reason: ShutdownReason) {
        dispatchPrecondition(condition: .onQueue(queue))
        guard !isStopped else { return }

        isStopped = true
        timers.stop()

        logger.info("Shutting down due to \(reason)")
        dispatchEvent(events.Shutdown, data: reason)
        dispatchEvent(events.ShutdownComplete, data: reason)
    }

    public func registerEventListener<T>(
        for event: Event<T>, listener: @escaping Event<T>.EventListener
    ) {
        dispatchPrecondition(condition: .onQueue(queue))
        event.addListener(listener)
    }

    public func dispatchEvent<T>(_ event: Event<T>, data: T) {
        dispatchPrecondition(condition: .onQueue(queue))
        for listener in event.listeners {
            listener(data)
        }
    }

    private func dispatchEvent(_ event: Event<Void>) {
        dispatchEvent(event, data: ())
    }

    public enum ImportResult {
        case imported
        case dropped
        case needsWasm
        case needsBundles
        case failed(ExecutionOutcome)
    }

    private func containsWasm(_ program: Program) -> Bool {
        program.code.contains {
            $0.op.requiredContext.contains(.wasm) || $0.op.requiredContext.contains(.wasmTypeGroup)
        }
    }

    @discardableResult
    public func importProgram(
        _ program: Program, origin: ProgramOrigin, enableDropout: Bool = false
    ) -> ImportResult {
        dispatchPrecondition(condition: .onQueue(queue))

        if enableDropout && probability(config.dropoutRate) {
            return .dropped
        }

        if !config.isWasmEnabled && containsWasm(program) {
            if let path = config.storagePath {
                let dirName = "\(path)/\(Configuration.excludedWasmDirectory)"
                try! FileManager.default.createDirectory(
                    atPath: dirName, withIntermediateDirectories: true)
                (modules["Storage"] as! Storage).storeProgram(
                    program, as: "program_\(program.id).fzil", in: dirName)
            }
            return .needsWasm
        }

        if !config.generateBundle && program.code.isBundle {
            return .needsBundles
        }

        let execution = execute(program, purpose: .programImport)

        var wasImported = false
        switch execution.outcome {
        case .crashed(let termsig):
            processCrash(
                program, withSignal: termsig, withStderr: execution.stderr,
                withStdout: execution.stdout, origin: origin, withExectime: execution.execTime)

        case .differential:
            processDifferential(
                program, withStderr: execution.stderr, origin: origin)

        case .succeeded:
            if let aspects = evaluator.evaluate(execution) {
                wasImported = processMaybeInteresting(
                    program, havingAspects: aspects, origin: origin)
            }

            if case .corpusImport(let mode) = origin, mode == .full, !wasImported {
                corpus.add(program, ProgramAspects(outcome: .succeeded))
                dispatchEvent(events.InterestingProgramFound, data: (program, origin))
                wasImported = true
            }

        default:
            break
        }

        return wasImported ? .imported : .failed(execution.outcome)
    }

    public func importCrash(_ program: Program, origin: ProgramOrigin) {
        dispatchPrecondition(condition: .onQueue(queue))

        let execution = execute(program, purpose: .programImport)
        if case .crashed(let termsig) = execution.outcome {
            processCrash(
                program, withSignal: termsig, withStderr: execution.stderr,
                withStdout: execution.stdout, origin: origin, withExectime: execution.execTime)
        } else {
            dispatchEvent(
                events.CrashFound,
                data: (program, behaviour: .flaky, isUnique: true, origin: origin))
        }
    }

    private func removeCallsTo(_ filteredFunctions: [String], from program: Program) -> Program {
        func shouldRemoveUsesOf(_ name: String) -> Bool {
            for filteredFunction in filteredFunctions {
                if filteredFunction.last == "*" {
                    if name.starts(with: filteredFunction.dropLast()) {
                        return true
                    }
                } else {
                    assert(!filteredFunction.contains("*"))
                    if name == filteredFunction {
                        return true
                    }
                }
            }
            return false
        }

        let b = makeBuilder()
        let dummy = b.buildPlainFunction(with: .parameters(n: 0)) { _ in }
        var variablesToReplaceWithDummy = VariableSet()
        b.adopting {
            for instr in program.code {
                var removeInstruction = false
                switch instr.op.opcode {
                case .createNamedVariable(let op):
                    if op.declarationMode == .none && shouldRemoveUsesOf(op.variableName) {
                        removeInstruction = true
                        variablesToReplaceWithDummy.insert(instr.output)
                    }
                default:
                    break
                }

                if !removeInstruction {
                    let inouts = instr.inouts.map({
                        variablesToReplaceWithDummy.contains($0) ? dummy : b.adopt($0)
                    })
                    let newInstr = Instruction(instr.op, inouts: inouts, flags: instr.flags)
                    b.append(newInstr)
                }
            }
        }

        let foundAnyFunctionsToRemove = !variablesToReplaceWithDummy.isEmpty
        if foundAnyFunctionsToRemove {
            return b.finalize()
        } else {
            return program
        }
    }

    private static let maxProgramImportFixupAttempts = 3
    public func importProgramWithFixup(_ originalProgram: Program, origin: ProgramOrigin) -> (
        result: ImportResult, fixupAttempts: Int
    ) {
        var program = originalProgram
        var result = importProgram(program, origin: origin)

        switch result {
        case .dropped, .needsWasm, .needsBundles, .imported:
            return (result, 0)
        case .failed(_):
            break
        }

        let b = makeBuilder()
        let filteredFunctions = [
            "assert*", "print*", "startTest", "enterFunc", "exitFunc", "report*", "options*"
        ]
        program = removeCallsTo(filteredFunctions, from: program)
        result = importProgram(program, origin: origin)
        switch result {
        case .dropped, .needsWasm, .needsBundles, .imported:
            return (result, 1)
        case .failed(_):
            break
        }

        for instr in program.code {
            var newOp = instr.op
            if let op = instr.op as? GuardableOperation, !op.isGuarded {
                newOp = op.withGuardedState(true)
            }
            b.append(Instruction(newOp, inouts: instr.inouts, flags: instr.flags))
        }
        program = b.finalize()
        if let result = currentCorpusImportJob.fixupMutator.mutate(program, for: self) {
            program = result
        }
        result = importProgram(program, origin: origin)
        switch result {
        case .dropped, .needsWasm, .needsBundles, .imported:
            return (result, 2)
        case .failed(_):
            break
        }

        if !program.code.isBundle {
            b.buildTryCatchFinally(
                tryBody: {
                    b.adopting {
                        for instr in program.code {
                            b.adopt(instr)
                        }
                    }
                }, catchBody: { _ in })
            program = b.finalize()
            result = importProgram(program, origin: origin)
        }

        assert(Fuzzer.maxProgramImportFixupAttempts == 3)
        return (result, 3)
    }

    public func scheduleCorpusImport(
        _ corpus: [Program], importMode: CorpusImportMode
    ) {
        dispatchPrecondition(condition: .onQueue(queue))
        assert(state == .uninitialized)

        guard state != .corpusImport && currentCorpusImportJob.isFinished else {
            return logger.error("Cannot currently schedule multiple corpus imports")
        }

        guard !corpus.isEmpty else { return }

        let shuffledCorpus = corpus.shuffled()
        currentCorpusImportJob = CorpusImportJob(corpus: shuffledCorpus, mode: importMode)
        changeState(to: .corpusImport)
    }

    public func corpusImportProgress() -> Double {
        assert(state == .corpusImport)
        return currentCorpusImportJob.progress()
    }

    public func execute(
        _ program: Program, withTimeout timeout: UInt32? = nil, purpose: ExecutionPurpose
    ) -> Execution {
        dispatchPrecondition(condition: .onQueue(queue))
        assert(runner.isInitialized)

        let script = lifter.lift(program)

        dispatchEvent(events.PreExecute, data: (program, purpose))
        let execution = runner.run(script, withTimeout: timeout ?? config.timeout)
        dispatchEvent(events.PostExecute, data: execution)

        if isDifferentialFuzzing && purpose.supportsDifferentialRun
            && execution.outcome == .succeeded
        {
            return executeDifferentialIfNeeded(
                execution, script, withTimeout: timeout ?? config.timeout)
        }

        return execution
    }

    @discardableResult
    func processMaybeInteresting(
        _ program: Program, havingAspects aspects: ProgramAspects, origin: ProgramOrigin
    ) -> Bool {
        var aspects = aspects
        let minAttempts = 5
        let maxAttempts = 50
        var didConverge = false
        var attempt = 0
        repeat {
            attempt += 1
            if attempt > maxAttempts {
                logger.warning("Sample did not converge after \(maxAttempts) attempts. Discarding it")
                return false
            }

            guard let intersection = evaluator.computeAspectIntersection(of: program, with: aspects)
            else {
                return false
            }

            didConverge = aspects.count == intersection.count
            aspects = intersection
        } while !didConverge || attempt < minAttempts

        if origin == .local {
            iterationOfLastInterestingSample = iterations
        }

        func finishProcessing(_ program: Program) {
            // Strict validation before announcing/syncing: a program that
            // fails strict validation (e.g. a Return referencing a variable
            // from a closed scope) would be rejected by other nodes'
            // decoders, producing "Received malformed program" spam in
            // thread/network cluster mode. Skip it here instead.
            do {
                try program.code.check(checkVisibility: true)
            } catch {
                logger.verbose(
                    "Discarding statically invalid program before announcement/sync: \(error)"
                )
                return
            }
            if config.enableInspection {
                if origin == .local {
                    program.comments.add("Program is interesting due to \(aspects)", at: .footer)
                } else {
                    program.comments.add("Imported program is interesting due to \(aspects)", at: .footer)
                }
            }
            assert(!program.code.contains(where: { $0.op is JsInternalOperation }))
            dispatchEvent(events.InterestingProgramFound, data: (program, origin))

            if !config.staticCorpus || origin.isFromCorpusImport() {
                corpus.add(program, aspects)
            }
        }

        if !origin.requiresMinimization() {
            finishProcessing(program)
        } else {
            fuzzGroup.enter()
            minimizer.withMinimizedCopy(
                program, withAspects: aspects, limit: config.minimizationLimit
            ) { minimizedProgram in
                self.fuzzGroup.leave()
                finishProcessing(minimizedProgram)
            }
        }
        return true
    }

    func collectCrashInfo(
        for program: Program, withSignal termsig: Int, withStderr stderr: String,
        withStdout stdout: String, withExectime exectime: TimeInterval
    ) -> [String] {
        var info = [String]()
        info.append("CRASH INFO")
        info.append("==========")
        if let tag = config.tag { info.append("INSTANCE TAG: \(tag)") }
        info.append("TERMSIG: \(termsig)")
        info.append("STDERR:\n\(stderr.trimmingCharacters(in: .newlines))")
        info.append("STDOUT:\n\(stdout.trimmingCharacters(in: .newlines))")
        info.append("FUZZER ARGS: \(config.arguments.joined(separator: " "))")
        info.append("TARGET ARGS: \(runner.processArguments.joined(separator: " "))")
        info.append("CONTRIBUTORS: \(program.contributors.map({ $0.name }).joined(separator: ", "))")
        info.append("EXECUTION TIME: \(Int(exectime * 1000))ms")
        return info
    }

    func processCrash(
        _ program: Program, withSignal termsig: Int, withStderr stderr: String,
        withStdout stdout: String, origin: ProgramOrigin, withExectime exectime: TimeInterval
    ) {
        // 5C: flaky crash suppression - require N consecutive reproducible
        // executions before registering the program as a deterministic crash
        // finding. This also avoids spending minimization time (the dominant
        // fuzzer overhead) on crashes that will not reproduce.
        var reproducibleRuns = 0
        for _ in 0..<config.reproducibilityRuns {
            let execution = execute(
                program, withTimeout: self.config.timeout * 2,
                purpose: .checkForDeterministicBehavior)
            if case .crashed = execution.outcome {
                reproducibleRuns += 1
            }
        }
        guard reproducibleRuns >= config.reproducibilityRuns else {
            logger.warning(
                "Discarding flaky crash (reproduced \(reproducibleRuns)/\(config.reproducibilityRuns) runs)"
            )
            // Attach the crash info from the ORIGINAL crashing execution so
            // the stored artifact carries TERMSIG/STDERR/stack/STDOUT even
            // though the crash itself does not reproduce. Without this, the
            // stored file has no crash info and the log shows signal=unknown.
            if !(program.comments.at(.footer)?.contains("CRASH INFO") ?? false) {
                for line in collectCrashInfo(
                    for: program, withSignal: termsig, withStderr: stderr, withStdout: stdout,
                    withExectime: exectime)
                {
                    program.comments.add(line, at: .footer)
                }
            }
            dispatchEvent(events.CrashFound, data: (program, .flaky, true, origin))
            return
        }

        func processCommon(_ program: Program) {
            let hasCrashInfo = program.comments.at(.footer)?.contains("CRASH INFO") ?? false
            if !hasCrashInfo {
                for line in collectCrashInfo(
                    for: program, withSignal: termsig, withStderr: stderr, withStdout: stdout,
                    withExectime: exectime)
                {
                    program.comments.add(line, at: .footer)
                }
            }

            let execution = execute(
                program, withTimeout: self.config.timeout * 2,
                purpose: .checkForDeterministicBehavior)
            if case .crashed = execution.outcome {
                let isUnique = evaluator.evaluateCrash(execution) != nil
                dispatchEvent(events.CrashFound, data: (program, .deterministic, isUnique, origin))
            } else {
                dispatchEvent(events.CrashFound, data: (program, .flaky, true, origin))
            }
        }

        if !origin.requiresMinimization() {
            return processCommon(program)
        }

        fuzzGroup.enter()
        minimizer.withMinimizedCopy(
            program, withAspects: ProgramAspects(outcome: .crashed(termsig)),
            timeout: config.crashMinimizationTimeout
        ) { minimizedProgram in
            self.fuzzGroup.leave()
            processCommon(minimizedProgram)
        }
    }

    func processDifferential(
        _ program: Program, withStderr stderr: String,
        origin: ProgramOrigin
    ) {
        // 5C: flaky differential suppression - require N consecutive
        // reproducible differential outcomes before registering the finding.
        var reproducibleRuns = 0
        for _ in 0..<config.reproducibilityRuns {
            let execution = execute(
                program, withTimeout: self.config.timeout * 2,
                purpose: .checkForDeterministicBehavior)
            if case .differential = execution.outcome {
                reproducibleRuns += 1
            }
        }
        guard reproducibleRuns >= config.reproducibilityRuns else {
            logger.warning(
                "Discarding flaky differential (reproduced \(reproducibleRuns)/\(config.reproducibilityRuns) runs)"
            )
            dispatchEvent(events.DifferentialFound, data: (program, .flaky, true, origin))
            return
        }

        func processCommon(_ program: Program) {
            let hasDiffInfo = program.comments.at(.footer)?.contains("DIFFERENTIAL INFO") ?? false
            if !hasDiffInfo {
                let footerMessage = """
                    DIFFERENTIAL INFO
                    ==========
                    STDERR:
                    \(stderr)
                    ARGS: \(runner.processArguments.joined(separator: " "))
                    REFERENCE ARGS: \(referenceRunner!.processArguments.joined(separator: " "))
                    """
                program.comments.add(footerMessage, at: .footer)
            }

            let execution = execute(
                program, withTimeout: self.config.timeout * 2,
                purpose: .checkForDeterministicBehavior)
            if case .differential = execution.outcome {
                dispatchEvent(
                    events.DifferentialFound, data: (program, .deterministic, true, origin))
            } else {
                dispatchEvent(events.DifferentialFound, data: (program, .flaky, true, origin))
            }
        }

        if !origin.requiresMinimization() {
            return processCommon(program)
        }

        fuzzGroup.enter()
        minimizer.withMinimizedCopy(
            program, withAspects: ProgramAspects(outcome: .differential),
            timeout: config.crashMinimizationTimeout
        ) { minimizedProgram in
            self.fuzzGroup.leave()
            processCommon(minimizedProgram)
        }
    }

    public func makeBuilder(forMutating parent: Program? = nil) -> ProgramBuilder {
        dispatchPrecondition(condition: .onQueue(queue))
        let isBundle = parent?.code.isBundle ?? config.generateBundle
        let parent = config.enableInspection ? parent : nil
        return ProgramBuilder(for: self, parent: parent, isBundle: isBundle)
    }

    private func fuzzOne() {
        dispatchPrecondition(condition: .onQueue(queue))
        assert(currentCorpusImportJob.isFinished || state == .corpusImport)

        guard !self.isStopped else { return }

        switch exitCondition {
        case .none: break
        case .iterationsPerformed(let maxIterations):
            if iterations >= maxIterations { return shutdown(reason: .finished) }
        case .timeFuzzed(let maxRuntime):
            if uptime() > maxRuntime { return shutdown(reason: .finished) }
        }

        switch state {
        case .uninitialized:
            fatalError("This state should never be observed here")

        case .waiting:
            Thread.sleep(forTimeInterval: 5 * Seconds)
            if uptime() > 15 * Minutes {
                logger.fatal("Did not receive a corpus from our parent node within 15 minutes")
            }

        case .corpusImport:
            assert(!currentCorpusImportJob.isFinished)
            let program = currentCorpusImportJob.nextProgram()

            if currentCorpusImportJob.numberOfProgramsProcessedSoFar % 500 == 0 {
                logger.info(
                    "Corpus import progress: processed \(currentCorpusImportJob.numberOfProgramsProcessedSoFar) of \(currentCorpusImportJob.totalNumberOfProgramsToImport) programs"
                )
            }

            let (result, fixupAttempts) = importProgramWithFixup(
                program, origin: .corpusImport(mode: currentCorpusImportJob.importMode))
            currentCorpusImportJob.notifyImportOutcome(result, fixupAttempts: fixupAttempts)

            if currentCorpusImportJob.isFinished {
                logger.info("Corpus import finished.")
                dispatchEvent(events.CorpusImportComplete)
                changeState(to: .fuzzing)
            }

        case .corpusGeneration:
            assert(!config.staticCorpus)
            iterations += 1
            corpusGenerationEngine.fuzzOne()

            if iterationsSinceLastInterestingProgram > config.corpusGenerationIterations {
                guard !corpus.isEmpty else {
                    logger.fatal("Initial corpus generation failed, corpus is still empty.")
                }
                logger.info("Initial corpus generation finished. Corpus now contains \(corpus.size) elements")
                changeState(to: .fuzzing)
            }

        case .fuzzing:
            iterations += 1
            engine.fuzzOne()
        }

        fuzzGroup.notify(queue: queue) {
            self.fuzzOne()
        }
    }

    private func makeComplexProgram(builder b: ProgramBuilder) {
        let f = b.buildPlainFunction(with: .parameters(n: 2)) { params in
            let x = b.getProperty("x", of: params[0])
            let y = b.getProperty("y", of: params[0])
            let s = b.binary(x, y, with: .Add)
            let p = b.binary(s, params[1], with: .Mul)
            b.doReturn(p)
        }

        b.buildRepeatLoop(n: 1000) { i in
            let x = b.loadInt(42)
            let y = b.loadInt(43)
            let arg1 = b.createObject(with: ["x": x, "y": y])
            let arg2 = i
            b.callFunction(f, withArgs: [arg1, arg2])
        }
    }

    public func runStartupTests(with timeout: Timeout) -> Timeout {
        assert(isInitialized)

        var execution = execute(Program(isBundle: false), purpose: .startup)
        guard case .succeeded = execution.outcome else {
            logger.fatal("Cannot execute programs. Are command line flags valid?")
        }

        var b = makeBuilder()
        b.maybeWrapInsideBundleScript {
            let exception = b.loadInt(42)
            b.throwException(exception)
        }
        execution = execute(b.finalize(), purpose: .startup)
        guard case .failed = execution.outcome else {
            logger.fatal("Cannot detect failed executions.")
        }

        var maxExecutionTime: TimeInterval = 0
        b.maybeWrapInsideBundleScript {
            makeComplexProgram(builder: b)
        }
        let complexProgram = b.finalize()
        for _ in 0..<5 {
            let execution = execute(complexProgram, purpose: .startup)
            maxExecutionTime = max(maxExecutionTime, execution.execTime)
        }

        var hasAnyCrashTests = false

        if config.skipStartupTests {
            logger.warning("Startup tests skipped via configuration (--skip-startup-tests).")
        } else {
            for (test, expectedResult) in config.startupTests {
                b = makeBuilder()
                b.maybeWrapInsideBundleScript {
                    b.eval(test)
                }
                execution = execute(b.finalize(), purpose: .startup)

                if execution.outcome == .timedOut {
                    logger.warning(
                        "Testcase \"\(test)\" timed out, the configured timeout threshold (\(config.timeout)ms) might be too low. Continuing anyway.")
                }

                switch expectedResult {
                case .shouldSucceed where execution.outcome != .succeeded:
                    logger.warning(
                        "Testcase \"\(test)\" did not execute successfully\nstdout:\n\(execution.stdout)\nstderr:\n\(execution.stderr)")
                case .shouldCrash where !execution.outcome.isCrash():
                    logger.warning("Testcase \"\(test)\" did not report as crashed (got \(execution.outcome)). Continuing.")
                case .shouldNotCrash where execution.outcome.isCrash():
                    logger.warning(
                        "Testcase \"\(test)\" unexpectedly crashed\nstdout:\n\(execution.stdout)\nstderr:\n\(execution.stderr)")
                default:
                    if expectedResult == .shouldCrash {
                        maxExecutionTime = max(maxExecutionTime, execution.execTime)
                        hasAnyCrashTests = true
                    }
                    break
                }
            }
        }

        if config.generateBundle {
            b = makeBuilder()
            let moduleVariable = b.buildBundleModule(name: "module.mjs") {
                let v = b.loadInt(42)
                b.exportVariables(variables: [v], exportNames: ["foo"])
            }

            b.buildBundleModuleEntryPoint {
                let importInstruction = b.importVariables(
                    module: moduleVariable, importNames: ["foo"])
                let imported = importInstruction.output
                let v2 = b.loadInt(43)
                b.binary(imported, v2, with: .Add)
            }

            execution = execute(b.finalize(), purpose: .startup)
            guard case .succeeded = execution.outcome else {
                logger.fatal("Bundle test did not execute successfully.")
            }
        }

        if !hasAnyCrashTests && !config.skipStartupTests {
            logger.warning("Cannot check if crashes are detected as there are no startup tests that should cause a crash.")
        }

        let maxExecutionTimeMs = (Int(maxExecutionTime * 1000 + 9) / 10) * 10
        let recommendedTimeout = 2 * maxExecutionTimeMs

        let actualTimeout: Timeout
        if case .interval(let lowerLimit, let upperLimit) = timeout {
            let timeout = max(min(UInt32(recommendedTimeout), upperLimit), lowerLimit)
            logger.info("Determined a timeout of \(timeout)ms based on interval [\(lowerLimit), \(upperLimit)]")
            actualTimeout = Timeout.value(timeout)
            config.timeout = timeout
        } else {
            actualTimeout = timeout
        }

        logger.info("Recommended timeout: at least \(recommendedTimeout)ms. Current timeout: \(config.timeout)ms")

        b = makeBuilder()
        b.maybeWrapInsideBundleScript {
            let str = b.loadString("Hello World!")
            b.doPrint(str)
        }
        let output = execute(b.finalize(), purpose: .startup).fuzzout.trimmingCharacters(
            in: .whitespacesAndNewlines)
        if output != "Hello World!" {
            logger.warning("Cannot receive FuzzIL output (got \"\(output)\" instead of \"Hello World!\")")
        }

        let executor = JavaScriptExecutor(
            withExecutablePath: runner.processArguments[0],
            arguments: Array(runner.processArguments[1...]), env: runner.env)
        do {
            let output = try executor.executeScript("", withTimeout: 300).output
            if output.lengthOfBytes(using: .utf8) > 0 {
                logger.warning("Runner has non-empty output for empty program!")
            }
        } catch {
            logger.warning("Could not run shell in standalone mode to check flags.")
        }

        logger.info("Startup tests finished successfully")
        return actualTimeout
    }

    private func executeDifferentialIfNeeded(
        _ execution: Execution, _ script: String, withTimeout timeout: UInt32
    ) -> Execution {
        // Run the unoptimized reference execution.
        let unoptExecution = referenceRunner!.run(script, withTimeout: timeout)
        if unoptExecution.outcome != .succeeded { return unoptExecution }

        // Dumpling path: deep frame-dump comparison. Only available when the
        // target d8 was built with the Dumpling patch (--maglev-dumping,
        // --interpreter-dumping, --dump-out-filename) and the profile enabled
        // dump arguments.
        if let diffConfig = config.diffConfig {
            let optPath = diffConfig.getDumpFilename(isOptimized: true)
            let unoptPath = diffConfig.getDumpFilename(isOptimized: false)
            if let optimizedDump = try? String(contentsOfFile: optPath, encoding: .utf8),
                let unoptimizedDump = try? String(contentsOfFile: unoptPath, encoding: .utf8),
                !optimizedDump.isEmpty
            {
                let result = DiffExecution.diff(
                    optExec: execution, unoptExec: unoptExecution, optDumpOut: optimizedDump,
                    unoptDumpOut: unoptimizedDump)

                if result.outcome == .differential {
                    logger.error("[DUMPLING] POTENTIAL DIFFERENTIAL DETECTED\n\(script)")
                }
                return result
            }
        }

        // Fallback oracle: compare observable outputs of both executions.
        // Outputs are normalized (stack frames, NaN payloads, hex addresses)
        // before comparison; the profile's determinism shim removes
        // Date/Math.random/Temporal/performance nondeterminism so that any
        // remaining output mismatch indicates a real JIT-vs-interpreter
        // miscompilation.
        let optStdout = normalizeDifferentialOutput(execution.stdout)
        let refStdout = normalizeDifferentialOutput(unoptExecution.stdout)
        let optFuzzout = normalizeDifferentialOutput(execution.fuzzout)
        let refFuzzout = normalizeDifferentialOutput(unoptExecution.fuzzout)
        if optStdout == refStdout && optFuzzout == refFuzzout {
            return execution
        }

        logger.error("[DIFF-STDOUT] POTENTIAL DIFFERENTIAL DETECTED\n\(script)")
        if execution.stdout != unoptExecution.stdout {
            logger.warning(
                "Raw STDOUT differs (opt=\(execution.stdout.count)B, ref=\(unoptExecution.stdout.count)B)\nOPT: \(execution.stdout.prefix(300))\nREF: \(unoptExecution.stdout.prefix(300))"
            )
        }
        if execution.fuzzout != unoptExecution.fuzzout {
            logger.warning(
                "Raw FUZZOUT differs (opt=\(execution.fuzzout.count)B, ref=\(unoptExecution.fuzzout.count)B)\nOPT: \(execution.fuzzout.prefix(300))\nREF: \(unoptExecution.fuzzout.prefix(300))"
            )
        }
        return DiffExecution.outputsDiffer(optExec: execution, unoptExec: unoptExecution)
    }

    private struct CorpusImportJob {
        private var corpusToImport: [Program]
        let importMode: CorpusImportMode
        let totalNumberOfProgramsToImport: Int
        let fixupMutator = FixupMutator(name: "CorpusImportFixupMutator")

        private(set) var numberOfProgramsProcessedSoFar = 0
        private(set) var numberOfProgramsThatExecutedSuccessfullyDuringImport = 0
        private(set) var numberOfProgramsThatWereImport = 0
        private(set) var numberOfProgramsThatFailedDuringImport = 0
        private(set) var numberOfProgramsThatTimedOutDuringImport = 0
        private(set) var numberOfProgramsThatNeededOneFixupAttempt = 0
        private(set) var numberOfProgramsThatNeededTwoFixupAttempts = 0
        private(set) var numberOfProgramsThatNeededThreeFixupAttempts = 0
        private(set) var numberOfProgramsRequiringWasmButDisabled = 0
        private(set) var numberOfProgramsRequiringBundlesButDisabled = 0

        var numberOfProgramsThatNeededFixup: Int {
            assert(Fuzzer.maxProgramImportFixupAttempts == 3)
            return numberOfProgramsThatNeededOneFixupAttempt
                + numberOfProgramsThatNeededTwoFixupAttempts
                + numberOfProgramsThatNeededThreeFixupAttempts
        }

        init(corpus: [Program], mode: CorpusImportMode) {
            self.corpusToImport = corpus.reversed()
            self.importMode = mode
            self.totalNumberOfProgramsToImport = corpus.count
        }

        var isFinished: Bool { return corpusToImport.isEmpty }

        mutating func nextProgram() -> Program {
            assert(!isFinished)
            numberOfProgramsProcessedSoFar += 1
            return corpusToImport.removeLast()
        }

        mutating func notifyImportOutcome(_ result: ImportResult, fixupAttempts: Int) {
            switch result {
            case .imported:
                numberOfProgramsThatExecutedSuccessfullyDuringImport += 1
                numberOfProgramsThatWereImport += 1
                switch fixupAttempts {
                case 0: break
                case 1: numberOfProgramsThatNeededOneFixupAttempt += 1
                case 2: numberOfProgramsThatNeededTwoFixupAttempts += 1
                case 3: numberOfProgramsThatNeededThreeFixupAttempts += 1
                default: fatalError("Unexpected number of fixup rounds: \(fixupAttempts)")
                }
            case .dropped:
                numberOfProgramsThatExecutedSuccessfullyDuringImport += 1
            case .needsWasm:
                numberOfProgramsRequiringWasmButDisabled += 1
            case .needsBundles:
                numberOfProgramsRequiringBundlesButDisabled += 1
            case .failed(let outcome):
                switch outcome {
                case .crashed, .succeeded, .differential: break
                case .failed: numberOfProgramsThatFailedDuringImport += 1
                case .timedOut: numberOfProgramsThatTimedOutDuringImport += 1
                }
            }
        }

        func progress() -> Double {
            return Double(numberOfProgramsProcessedSoFar) / Double(totalNumberOfProgramsToImport)
        }
    }
}
