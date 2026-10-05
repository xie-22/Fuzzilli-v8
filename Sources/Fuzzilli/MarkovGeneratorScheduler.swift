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

/// Feedback-driven CodeGenerator scheduler implementing the Markov weight
/// update rule (5A):
///
///   W_g(t+1) = W_g(t) * (1 + alpha*log(1+I_g) + beta*log(1+C_g) + gamma*log(1+D_g))
///
/// where I_g / C_g / D_g are the generator's cumulative interesting / crashing /
/// differential sample counts (read from its Contributor statistics). The log
/// transform avoids the cold-start bias of ratio-based feedback: a generator
/// with 1 crash out of 5 samples gets the same boost as one with 1 crash out
/// of 500, and the boost grows sub-linearly with the count.
///
/// Effective weights are recomputed every `refreshInterval` seconds and cached,
/// so the hot `pick` path is an O(1) dictionary lookup instead of an O(parts)
/// scan per candidate.
public class MarkovGeneratorScheduler {
    /// Weight of the interesting-sample feedback.
    public let alpha: Double

    /// Weight of the crashing-sample feedback.
    public let beta: Double

    /// Weight of the differential-sample feedback.
    public let gamma: Double

    /// How often the cached effective weights are refreshed (seconds).
    private let refreshInterval: TimeInterval

    private struct Entry {
        let generator: CodeGenerator
        let baseWeight: Double
    }

    private var entries: [ObjectIdentifier: Entry] = [:]
    private var cachedWeights: [ObjectIdentifier: Double] = [:]
    private var lastRefresh = Date.distantPast

    public init(
        generators: WeightedList<CodeGenerator>,
        alpha: Double = 1.0,
        beta: Double = 20.0,
        gamma: Double = 20.0,
        refreshInterval: TimeInterval = 30.0
    ) {
        self.alpha = alpha
        self.beta = beta
        self.gamma = gamma
        self.refreshInterval = refreshInterval
        for (generator, weight) in generators.iteratorWithWeights() {
            entries[ObjectIdentifier(generator)] = Entry(
                generator: generator, baseWeight: Double(weight))
        }
    }

    /// The current effective weight of a generator: its static base weight
    /// multiplied by the feedback factor, clamped to [0.1, 10]x the base
    /// weight so that no single generator can starve the others.
    public func effectiveWeight(of generator: CodeGenerator) -> Double {
        refreshIfStale()
        if let cached = cachedWeights[ObjectIdentifier(generator)] {
            return cached
        }
        guard let entry = entries[ObjectIdentifier(generator)] else { return 1.0 }
        return computeWeight(entry)
    }

    /// Select one of the candidate generators, weighted by their effective
    /// weights. Falls back to uniform selection if no feedback is available.
    public func pick(from candidates: [CodeGenerator]) -> CodeGenerator {
        assert(!candidates.isEmpty)
        refreshIfStale()
        let weights = candidates.map { cachedWeights[ObjectIdentifier($0)] ?? 1.0 }
        let total = weights.reduce(0, +)
        var value = Double.random(in: 0..<total)
        for (candidate, weight) in zip(candidates, weights) {
            value -= weight
            if value <= 0 {
                return candidate
            }
        }
        return candidates.last!
    }

    private func refreshIfStale() {
        guard Date().timeIntervalSince(lastRefresh) >= refreshInterval else { return }
        for (id, entry) in entries {
            cachedWeights[id] = computeWeight(entry)
        }
        lastRefresh = Date()
    }

    private func computeWeight(_ entry: Entry) -> Double {
        // Single pass over the generator's stubs to avoid multiple reduce()
        // passes (and their closure allocations).
        var interesting = 0
        var crashing = 0
        var differentials = 0
        for part in entry.generator.parts {
            interesting += part.interestingSamples
            crashing += part.crashingSamples
            differentials += part.differentialSamples
        }

        guard interesting + crashing + differentials > 0 else {
            return entry.baseWeight
        }

        // Count-based log feedback: no cold-start bias from ratios.
        let factor = 1.0
            + alpha * log(1.0 + Double(interesting))
            + beta * log(1.0 + Double(crashing))
            + gamma * log(1.0 + Double(differentials))
        let multiplier = Swift.min(10.0, Swift.max(0.1, factor))
        return entry.baseWeight * multiplier
    }
}
