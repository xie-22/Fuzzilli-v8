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

/// Corpus with AFL++-style energy allocation (5A).
///
/// Each sample p receives a mutation energy
///
///   E(p) = min(Emax, Ebase * D(p) / sqrt(T(p)) * 2^Rarity(p))
///
/// where D(p) is the program depth (approximated by its instruction count),
/// T(p) its execution time in milliseconds, and Rarity(p) is 1 until the
/// program has been selected for mutation for the first time. Deep, fast,
/// and fresh programs are therefore mutated most often, maximizing the
/// number of executions per wall-clock second.
public class EnergyCorpus: ComponentBase, Collection, Corpus {
    private let minSize: Int
    private let minMutationsPerSample: Int
    private let energyBase: Double
    private let energyMax: Double

    private var programs: RingBuffer<Program>
    private var ages: RingBuffer<Int>
    private var energies: RingBuffer<Double>
    private var isFresh: RingBuffer<Bool>

    private var totalEntryCounter = 0

    public init(
        minSize: Int, maxSize: Int, minMutationsPerSample: Int,
        energyBase: Double = 100.0, energyMax: Double = 1000.0
    ) {
        assert(minSize >= 1)
        assert(maxSize >= minSize)
        assert(energyMax >= energyBase)

        self.minSize = minSize
        self.minMutationsPerSample = minMutationsPerSample
        self.energyBase = energyBase
        self.energyMax = energyMax

        self.programs = RingBuffer(maxSize: maxSize)
        self.ages = RingBuffer(maxSize: maxSize)
        self.energies = RingBuffer(maxSize: maxSize)
        self.isFresh = RingBuffer(maxSize: maxSize)

        super.init(name: "EnergyCorpus")
    }

    override func initialize() {
        if !fuzzer.config.staticCorpus {
            fuzzer.timers.scheduleTask(every: 30 * Minutes, cleanup)
        }
    }

    public var size: Int {
        return programs.count
    }

    public var isEmpty: Bool {
        return size == 0
    }

    public var supportsFastStateSynchronization: Bool {
        return true
    }

    private func computeEnergy(of program: Program, executionTime: TimeInterval) -> Double {
        // Base energy WITHOUT the rarity factor and WITHOUT the Emax clamp.
        // The full formula E = min(Emax, base * 2^Rarity) is evaluated at
        // selection time in randomElementForMutating, where the Rarity flag
        // is known. Keeping rarity/clamp here would apply rarity twice.
        let depth = Double(Swift.max(1, program.size))
        let timeMs = Swift.max(1.0, executionTime * 1000.0)
        return energyBase * depth / timeMs.squareRoot()
    }

    public func add(_ program: Program, _ aspects: ProgramAspects) {
        addInternal(program, aspects: aspects)
    }

    public func addInternal(_ program: Program, aspects: ProgramAspects) {
        guard program.size > 0 else { return }
        // Defense in depth: never admit a statically invalid program, as it
        // would break state synchronization with worker nodes.
        do {
            try program.code.check(checkVisibility: true)
        } catch {
            logger.verbose("Discarding statically invalid program from corpus: \(error)")
            return
        }
        if program.containsEmptyWasmModule {
            logger.verbose("Discarding program with an empty WASM module from corpus")
            return
        }
        prepareProgramForInclusion(program, index: totalEntryCounter)
        programs.append(program)
        ages.append(0)
        energies.append(computeEnergy(of: program, executionTime: aspects.execTime))
        isFresh.append(true)

        totalEntryCounter += 1
    }

    /// Returns a random program from this corpus for use in splicing to another program.
    public func randomElementForSplicing() -> Program {
        assert(programs.count > 0)
        let idx = Int.random(in: 0..<programs.count)
        return programs[idx]
    }

    /// Returns the next program to mutate, selected by energy, and marks the
    /// selected program as no longer fresh (its Rarity drops to 0).
    public func randomElementForMutating() -> Program {
        assert(programs.count > 0)

        func effectiveWeight(_ i: Int) -> Double {
            // E = min(Emax, base * 2^Rarity), Rarity == 1 for fresh programs.
            return Swift.min(energyMax, energies[i] * (isFresh[i] ? 2.0 : 1.0))
        }

        var totalEnergy = 0.0
        for i in 0..<energies.count {
            totalEnergy += effectiveWeight(i)
        }

        var value = Double.random(in: 0..<totalEnergy)
        var idx = 0
        for i in 0..<energies.count {
            value -= effectiveWeight(i)
            if value <= 0 {
                idx = i
                break
            }
            idx = i
        }

        ages[idx] += 1
        isFresh[idx] = false

        let program = programs[idx]
        assert(!program.isEmpty)
        return program
    }

    public func allPrograms() -> [Program] {
        return Array(programs)
    }

    public func exportState() throws -> Data {
        let res = try encodeProtobufCorpus(programs)
        logger.info("Successfully serialized \(programs.count) programs")
        return res
    }

    public func importState(_ buffer: Data) throws {
        let newPrograms = try decodeProtobufCorpus(buffer, logger: logger)
        programs.removeAll()
        ages.removeAll()
        energies.removeAll()
        isFresh.removeAll()
        for program in newPrograms {
            // Use a neutral execution time (100ms) for imported programs
            // instead of 0: a 0 would yield T=1ms and inflate their energy
            // relative to freshly discovered samples.
            addInternal(program, aspects: ProgramAspects(outcome: .succeeded, execTime: 0.1))
        }
    }

    private func cleanup() {
        assert(!fuzzer.config.staticCorpus)
        var newPrograms = RingBuffer<Program>(maxSize: programs.maxSize)
        var newAges = RingBuffer<Int>(maxSize: ages.maxSize)
        var newEnergies = RingBuffer<Double>(maxSize: energies.maxSize)
        var newIsFresh = RingBuffer<Bool>(maxSize: isFresh.maxSize)

        for i in 0..<programs.count {
            let remaining = programs.count - i
            if ages[i] < minMutationsPerSample || remaining <= (minSize - newPrograms.count) {
                newPrograms.append(programs[i])
                newAges.append(ages[i])
                newEnergies.append(energies[i])
                newIsFresh.append(isFresh[i])
            }
        }

        logger.info("Corpus cleanup finished: \(self.programs.count) -> \(newPrograms.count)")
        programs = newPrograms
        ages = newAges
        energies = newEnergies
        isFresh = newIsFresh
    }

    public var startIndex: Int {
        return programs.startIndex
    }

    public var endIndex: Int {
        return programs.endIndex
    }

    public subscript(index: Int) -> Program {
        return programs[index]
    }

    public func index(after i: Int) -> Int {
        return i + 1
    }
}
