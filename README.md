# Fuzzilli-v8

Fuzzilli-v8 is a **V8-specific deeply customized version** built on [Google Project Zero Fuzzilli](https://github.com/googleprojectzero/fuzzilli).

Originally maintained as a private advanced customization, it has been tuned for V8 internals — parser, JIT, Wasm, Temporal — and optimized around **bug bounty (Zero day) workflows**: enhanced mutation, coverage evaluation, differential fuzzing, corpus scheduling, and crash reproduction.

## CVEs/zero-day vulnerabilities/issues findings discovered after open-source release.
Pending announcement

## Usage
If you need information on usage, please visit: [Usage.md](https://github.com/xie-22/Fuzzilli-v8/blob/main/Usage.md)
## Command-Line Arguments

### Basic Configuration

| Argument | Description | Default Value |
|---|---|---|
| `--profile=name` | Select a pre-configured profile. Available values: `v8`, `v8Sandbox`, `v8Differential`, `v8Dumpling`, `v8holefuzzing`, `spidermonkey`, `jsc`, `qjs`, `qtjs`, `duktape`, `jerryscript`, `njs`, `xs`, `serenity` | Required |
| `--jobs=n` | Total number of fuzzing jobs. | Launch 1 master instance and n-1 worker instances | 1 |
| `--engine=name` | Fuzzing engine: `mutation` (default, stable), `hybrid`, `multi` | `mutation` |
| `--corpus=name` | Corpus scheduler: `basic` (default), `markov`, `energy` (AFL++ style energy allocation) | `basic` |
| `--logLevel=level` | Log level: `verbose`, `info`, `warning`, `error`, `fatal` | `info` |
| `--tag=tag` | Instance tag; written to `settings.json` and crash samples; can be used to record the target version | None |
| `--additionalArguments=args` | Additional arguments passed to the JS engine; separate multiple arguments with commas | None |
| `--argumentRandomization` | Enable JS engine argument randomization | Disabled |

### Runtime and Iterations

| Parameter | Description | Default Value |
|---|---|---|
| `--maxIterations=n` | Maximum number of iterations | Unlimited |
| `--maxRuntimeInHours=n` | Maximum runtime in hours | Unlimited |
| `--timeout=n` | Execution timeout (milliseconds), or a range like `200,400` (actual value determined at startup) | Profile-dependent |
| `--corpusGenerationIterations=n` | Number of rounds without discovering new samples before switching from corpus generation to main fuzzing | 100 |
| `--consecutiveMutations=n` | Number of consecutive mutations per sample | 5 |

### Corpus Management

| Parameter | Description | Default Value |
|---|---|---|
| `--minMutationsPerSample=n` | Minimum mutations per sample before discarding from the corpus | 25 |
| `--minCorpusSize=n` | Minimum number of samples in the corpus | 1000 |
| `--maxCorpusSize=n` | Maximum number of samples in the corpus; oldest samples are discarded if the limit is exceeded | 2000 |
| `--markovDropoutRate=p` | Proportion of low-marginality samples in the Markov scheduler not selected in a given round | 0.10 |
| `--staticCorpus` | Mutate only the existing corpus to find crashes; do not add new samples | Disabled |
| `--importCorpus=path` | Import an existing `.fzil` corpus directory as the initial corpus | None |
| `--corpusImportMode=mode` | Import mode: `default` (keep interesting samples and minimize), `full` (keep all successfully executed samples, no minimization), `unminimized` (keep interesting samples but do not minimize) | `default` |

### Storage and Resumption

| Parameter | Description | Default |
|---|---|---|
| `--storagePath=path` | Storage path for output files (crashes, corpus, etc.) | None |
| `--resume` | If the storage path exists, resume by importing programs from the `corpus/` subdirectory | Disabled |
| `--overwrite` | If the storage path exists, clear it and start over | Disabled |
| `--exportStatistics` | Periodically export fuzzing statistics to disk; requires `--storagePath` | Disabled |
| `--statisticsExportInterval=n` | Statistics export interval (in minutes); requires `--exportStatistics` | 10 |

### Minimization and Reproducibility

| Parameter | Description | Default |
|---|---|---|
| `--minimizationLimit=p` | Minimum percentage of original instructions to retain when minimizing interesting programs | 0.0 |
| `--minimizationTimeout=n` | Maximum wall-clock time (in seconds) for minimizing a single program | 20 |
| `--reproducibilityRuns=n` | Number of consecutive successful reproductions required to classify a crash or differential finding as deterministic | 3 |
| `--diagnostics` | Save programs that fail or time out, and track the execution of the current REPRL instance | Off |
| `--inspect` | Write out a `.fuzzil.history` file for each interesting or crashing program, recording the generation process | Off |

### Wasm Support

| Argument | Description | Default |
|---|---|---|
| `--wasm` | Enable Wasm CodeGenerators | Off |
| `--enable-wasm` | Alias ​​for `--wasm` | Off |
| `--wasm-opt-path=path` | Path to the `wasm-opt` binary; enables Binaryen Wasm generation | None |

### Differential Fuzzing and Special Modes

| Argument | Description | Default |
|---|---|---|
| `--forDifferentialFuzzing` | Enable additional features for external differential fuzzing | Off |
| `--bundle` | Generate a bundle containing multiple JS scripts and modules | Off |
| `--swarmTesting` | Enable Swarm Testing; each process randomly selects weights for code generators | Off |
| `--skip-startup-tests` | Skip startup crash/timeout tests; useful when sanitizers interfere with signal handling | Off |
| `--fast-start` | Alias ​​for `--skip-startup-tests` | Off |

### Distributed Fuzzing

| Argument | Description | Default |
|---|---|---|
| `--instanceType=type` | Instance type: `root`, `leaf`, `intermediate`, `standalone` | `standalone` |
| `--bindTo=host:port` | Bind address for root or intermediate nodes | `127.0.0.1:1337` |
| `--connectTo=host:port` | Address of the parent instance for leaf or intermediate nodes | `127.0.0.1:1337` |
| `--corpusSyncMode=mode` | Corpus synchronization mode: `up` (send parent nodes only), `down` (send child nodes only), `full` (bidirectional, default), `none` (no sharing) | `full` |

> Note: It is recommended to run distributed fuzzing in an isolated network. Worker threads (`--jobs=X`) always fully synchronize the corpus.

### Handling Configuration Conflicts

Conflicting or incompatible options do not abort the process; a warning is printed, and safe default values ​​are used. For example:

- `--resume` takes precedence over `--overwrite`
- `--maxRuntimeInHours` takes precedence over `--maxIterations`
- Size options incompatible with the corpus fall back to the `basic` scheduler


## Disclaimer

- This project is intended for **authorized security testing and research only**. 
- Please comply with all applicable laws and the target platform's testing policies. 
- `Fuzzilli-v8` is based on the upstream Fuzzilli project; please follow its license and retain original copyright notices.
