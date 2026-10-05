// Copyright 2025 Google LLC
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

// The TypeGroupReducer removes unused type definition. A type definition is considered unused if it
// is not used by any other operation but the WasmEndTypeGroup and if the corresponding output
// of the WasmEndTypeGroup is not used anywhere inside the program.
//
// This reducer preserves the invariant that each type defined inside a type group is also exposed
// by the WasmEndTypeGroup operation.
// Note that a WasmResolveForwardReference(v0, v1) makes v1 used and prevents its removal by this
// reducer. However, the GenericInstructionReducer will try to remove the
// WasmResolveForwardReference, so this is not an issue.
struct WasmTypeGroupReducer: Reducer {
    func reduce(with helper: MinimizationHelper) {
        var useCount = VariableMap<Int>()
        var definitions = VariableMap<Int>()

        // Count all usages of Wasm type definitions.
        for instr in helper.code {
            if instr.op is WasmTypeOperation {
                for output in instr.outputs {
                    useCount[output] = 0
                    definitions[output] = instr.index
                }
            }

            if instr.op is WasmEndTypeGroup {
                // Propagate usage counts from the input to the output variables. Note that the
                // WasmEndTypeGroup ends the scope in which the inputs are defined (meaning there)
                // can't be any usages after the WasmEndTypeGroup instruction.
                for (input, output) in zip(instr.inputs, instr.outputs) {
                    useCount[output] = useCount[input]!
                }
            } else {
                // Any usage but the WasmEndTypeGroup should be tracked.
                // (This includes WasmResolveForwardReference.)
                for input in instr.inputs {
                    useCount[input]? += 1
                }
            }
        }

        if definitions.isEmpty {
            return
        }

        // Create replacements for WasmEndTypeGroup and collect type definitions to remove.
        var toRemove = IndexSet()
        var endTypeGroupReplacements = [Int: Instruction]()

        for instr in helper.code {
            guard case .wasmEndTypeGroup = instr.op.opcode else { continue }

            let keptInoutsMap = zip(instr.inputs, instr.outputs).filter { useCount[$0.1]! > 0 }
            if keptInoutsMap.count == instr.inputs.count { continue }

            let unusedInputs =
                zip(instr.inputs, instr.outputs).filter { useCount[$0.1]! == 0 }.map { $0.0 }
            for input in unusedInputs {
                toRemove.insert(definitions[input]!)
            }

            let newInouts = keptInoutsMap.map { $0.0 } + keptInoutsMap.map { $0.1 }
            endTypeGroupReplacements[instr.index] = Instruction(
                WasmEndTypeGroup(typesCount: keptInoutsMap.count), inouts: newInouts)
        }

        if toRemove.isEmpty {
            return
        }

        var newCode = Code(
            helper.code
                .filter { !toRemove.contains($0.index) }
                .map { endTypeGroupReplacements[$0.index] ?? $0 }, isBundle: helper.code.isBundle)

        newCode.renumberVariables()
        helper.testAndCommit(newCode)
    }
}
