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

/// Malformed / invisible / cross-language boundary string engine (Task 6).
///
/// The default StringGenerator only produces well-formed literals, leaving
/// V8's string subsystem (string flattening, cons-strings, internalized
/// strings, the RegExp JIT, and Unicode normalization) largely untouched.
/// This generator feeds the following high-risk string classes into the
/// most string-sensitive V8 APIs:
///
///  - length-mutating case pairs (ß, ﬁ, İ, ı, ǰ, final sigma),
///  - zero-width, bidi and format control characters,
///  - boundary scalars (NUL, U+FFFF, U+10FFFF, replacement char),
///  - multi-level combining sequences, ZWJ emoji and flag grapheme clusters.
///
/// Interaction targets: Unicode normalize(), case conversions, malformed
/// property keys, RegExp patterns/inputs, Intl.Collator, Intl.Segmenter and
/// the d8 string builtins (externalizeString / isOneByteString).

/// The pool of high-risk string literals.
public let malformedStringPool: [String] = [
    // Valid non-BMP pair (control)
    "\u{1F4A9}",
    // Case-expansion / length-mutating characters
    "\u{00DF}", "\u{1E9E}", "\u{FB00}", "\u{FB01}", "\u{FB02}", "\u{FB03}",
    "\u{0130}", "\u{0131}", "\u{01F0}", "\u{03C2}", "\u{0149}",
    // Zero-width and format control characters
    "\u{200B}", "\u{200C}", "\u{200D}", "\u{FEFF}", "\u{00AD}", "\u{2060}",
    "\u{200E}", "\u{200F}",
    // Bidi control characters
    "\u{202A}", "\u{202B}", "\u{202C}", "\u{202D}", "\u{202E}",
    "\u{2066}", "\u{2067}", "\u{2068}", "\u{2069}", "\u{061C}",
    // Boundary scalars and control bytes
    "\u{0000}", "\u{0001}", "\u{001F}", "\u{007F}", "\u{0085}",
    "\u{FFFF}", "\u{FFFD}", "\u{FFFE}", "\u{10FFFF}",
    // Multi-level combining sequences (grapheme clusters)
    "e\u{0300}\u{0301}\u{0308}\u{0323}",
    "a\u{0300}\u{0301}\u{0302}\u{0303}\u{0304}",
    // ZWJ emoji sequence (family)
    "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F466}",
    // Flag (regional indicator pair)
    "\u{1F1E6}\u{1F1E8}",
    // Hangul jamo cluster
    "\u{1100}\u{1161}\u{11A8}",
    // Devanagari conjunct (ka + virama + ZWJ + ssa)
    "\u{0915}\u{094D}\u{200D}\u{0937}",
    // Arabic presentation forms + combining marks
    "\u{0645}\u{0651}\u{0670}\u{064E}",
]

public let MalformedStringGenerator = CodeGenerator(
    "MalformedStringGenerator"
) { b in
    let s = b.loadString(malformedStringPool.randomElement()!)
    let s2 = b.loadString(malformedStringPool.randomElement()!)

    switch Int.random(in: 0..<9) {
    case 0:
        // Unicode normalization across all four forms.
        let form = ["NFC", "NFD", "NFKC", "NFKD"].randomElement()!
        b.callMethod("normalize", on: s, withArgs: [b.loadString(form)])

    case 1:
        // Case conversions; some of these change string length (e.g. ß -> SS).
        let method =
            ["toUpperCase", "toLowerCase", "toLocaleUpperCase", "toLocaleLowerCase"]
            .randomElement()!
        b.callMethod(method, on: s)

    case 2:
        // Malformed strings as property keys: forces V8 to internalize odd
        // strings in the string table.
        let key1 = malformedStringPool.randomElement()!
        let key2 = malformedStringPool.randomElement()!
        let o = b.buildObjectLiteral { obj in
            obj.addProperty(key1, as: b.loadInt(1))
        }
        b.getProperty(key2, of: o)

    case 3:
        // RegExp JIT with a malformed pattern.
        let re = b.loadRegExp(malformedStringPool.randomElement()!, b.randomRegExpPatternAndFlags().1)
        b.callMethod("test", on: re, withArgs: [s])

    case 4:
        // RegExp operations with malformed input strings.
        let re2 = b.loadRegExp("a*", b.randomRegExpPatternAndFlags().1)
        if probability(0.3) {
            b.callMethod("split", on: s, withArgs: [re2])
        } else {
            // NOTE: "matchAll" omitted - it throws a TypeError unless the
            // RegExp has the global flag.
            let method = ["match", "search"].randomElement()!
            b.callMethod(method, on: s, withArgs: [re2])
        }

    case 5:
        // Intl.Collator comparison of two boundary strings.
        let intl = b.createNamedVariable(forBuiltin: "Intl")
        let collator = b.construct(b.getProperty("Collator", of: intl), withArgs: [])
        b.callMethod("compare", on: collator, withArgs: [s, s2])

    case 6:
        // Intl.Segmenter grapheme-boundary segmentation.
        let intl = b.createNamedVariable(forBuiltin: "Intl")
        let segmenter = b.construct(b.getProperty("Segmenter", of: intl), withArgs: [])
        let segments = b.callMethod("segment", on: segmenter, withArgs: [s])
        b.callMethod("containing", on: segments, withArgs: [b.loadInt(0)])

    case 7:
        // d8 string builtins (externalizeString / isOneByteString). These are
        // profile-provided builtins; this generator is registered through the
        // v8/v8Differential profiles' additionalCodeGenerators.
        let builtinName =
            ["externalizeString", "isOneByteString", "createExternalizableString"].randomElement()!
        let builtin = b.createNamedVariable(forBuiltin: builtinName)
        b.callFunction(builtin, withArgs: [s])

    default:
        // String methods that touch cons-strings and flattening.
        let method =
            [
                "concat", "repeat", "includes", "startsWith", "endsWith", "at",
                "charAt", "charCodeAt", "codePointAt", "localeCompare", "indexOf",
            ].randomElement()!
        switch method {
        case "repeat":
            b.callMethod(method, on: s, withArgs: [b.loadInt(Int64.random(in: 0...10))])
        case "at", "charAt", "charCodeAt", "codePointAt":
            b.callMethod(method, on: s, withArgs: [b.loadInt(Int64.random(in: 0...8))])
        case "indexOf":
            b.callMethod(method, on: s, withArgs: [s2])
        default:
            b.callMethod(method, on: s, withArgs: [s2])
        }
    }
}
