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
import Testing

@testable import Fuzzilli

/// Regression tests for the malformed string engine (Task 6).
@Suite
struct MalformedStringTests {
    @Test func testPoolInitialization() {
        // The pool must not be empty and must not contain empty entries.
        #expect(malformedStringPool.count >= 40)
        for s in malformedStringPool {
            #expect(!s.isEmpty)
        }
    }

    @Test func testPoolStringsLiftAndExecute() throws {
        // End-to-end pipeline check: every pool string must survive
        // FuzzIL lifting and execute successfully in the test JS shell.
        guard let shell = ProcessInfo.processInfo.environment["FUZZILLI_TEST_SHELL"]
        else {
            // Execution tests require a JS shell (e.g. a fuzzilli-enabled d8).
            return
        }
        let engine = JavaScriptExecutor(
            withExecutablePath: shell,
            arguments: ["--fuzzing", "--allow-natives-syntax", "--harmony-temporal"],
            env: [])
        let lifter = JavaScriptLifter(ecmaVersion: .es6, environment: JavaScriptEnvironment())
        let fuzzer = makeMockFuzzer(
            config: Configuration(logLevel: .error), environment: JavaScriptEnvironment())

        // Program building must happen on the fuzzer's dispatch queue.
        try fuzzer.sync {
            for s in malformedStringPool {
                let b = fuzzer.makeBuilder()
                let v = b.loadString(s)
                b.callMethod("normalize", on: v, withArgs: [b.loadString("NFKC")])
                let program = b.finalize()
                let js = lifter.lift(program)
                let result = try engine.executeScript(js)
                #expect(
                    result.isSuccess,
                    "lifted program failed to execute for pool string \(s.debugDescription): \(result.error)"
                )
            }
        }
    }
}
