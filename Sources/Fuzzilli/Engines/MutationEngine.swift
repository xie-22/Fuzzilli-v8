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

/// The core fuzzer responsible for generating and executing programs.
public class MutationEngine: FuzzEngine {
    // The number of consecutive mutations to apply to a sample.
    private let numConsecutiveMutations: Int

    public init(numConsecutiveMutations: Int) {
        self.numConsecutiveMutations = numConsecutiveMutations
        super.init(name: "MutationEngine")
    }

    /// Perform one round of fuzzing.
    ///
    /// High-level fuzzing algorithm:
    ///
    ///     let parent = pickSampleFromCorpus()
    ///     repeat N times:
    ///         let current = mutate(parent)
    ///         execute(current)
    ///         if current produced crashed:
    ///             output current
    ///         elif current resulted in a runtime exception or a time out:
    ///             // do nothing
    ///         elif current produced new, interesting behaviour:
    ///             minimize and add to corpus
    ///         else
    ///             parent = current
    ///
    ///
    /// This ensures that samples will be mutated multiple times as long
    /// as the intermediate results do not cause a runtime exception.
    public override func fuzzOne() {
        // Defensive guard: sampling an empty corpus traps in
        // Int.random(in: 0..<0). This can happen if every imported seed
        // crashes and therefore none is added to the corpus.
        guard !fuzzer.corpus.isEmpty else {
            logger.warning(
                "Cannot mutate: corpus is empty (e.g. all imported seeds crashed). Skipping round."
            )
            return
        }
        var parent = fuzzer.corpus.randomElementForMutating()
        parent = prepareForMutating(parent)
        parent.checkOrDie(onFailure: "Parent program is statically invalid")

        for _ in 0..<numConsecutiveMutations {
            // TODO: factor out code shared with the HybridEngine?
            var mutator = fuzzer.mutators.randomElement()!
            let maxAttempts = 10
            var mutatedProgram: Program? = nil
            for _ in 0..<maxAttempts {
                if let result = mutator.mutate(parent, for: fuzzer) {
                    do {
                        // Strict check: visibility violations (e.g. a Return
                        // referencing a variable from a closed scope, produced
                        // by PropertyAccessorMutator / ProbingMutator /
                        // ExplorationMutator / CodeGenMutator) are un-liftable
                        // and are discarded here - consistent with the corpus
                        // and decode paths (both use checkVisibility=true).
                        try result.code.check(checkVisibility: true)
                    } catch {
                        mutator.failedToGenerate()
                        logger.verbose(
                            "Program after \(mutator.name) is statically invalid, discarding mutation: \(error)"
                        )
                        mutator = fuzzer.mutators.randomElement()!
                        continue
                    }
                    if result.exceedsComplexityLimit {
                        // Hard complexity circuit breaker (Task 4): discard
                        // mutations that blow past the size/depth limits.
                        mutator.failedToGenerate()
                        logger.verbose(
                            "Program after \(mutator.name) exceeds complexity limits (size \(result.size), depth \(result.maxBlockDepth)), discarding mutation"
                        )
                        mutator = fuzzer.mutators.randomElement()!
                        continue
                    }
                    // Success!
                    result.contributors.formUnion(parent.contributors)
                    mutator.addedInstructions(result.size - parent.size)
                    mutatedProgram = result
                    break
                } else {
                    // Try a different mutator.
                    mutator.failedToGenerate()
                    mutator = fuzzer.mutators.randomElement()!
                }
            }

            guard let program = mutatedProgram else {
                logger.warning(
                    "Could not mutate sample, giving up. Sample:\n\(FuzzILLifter().lift(parent))")
                continue
            }

            assert(program !== parent)
            let outcome = execute(program)

            // Mutate the program further if it succeeded.
            if .succeeded == outcome {
                parent = program
            }
        }
    }

    /// Pre-processing of programs to facilitate mutations on them.
    private func prepareForMutating(_ program: Program) -> Program {
        let b = fuzzer.makeBuilder()
        b.buildPrefix()
        b.append(program)
        return b.finalize()
    }
}
