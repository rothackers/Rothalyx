# Fuzzing

Zara ships with sanitizer-backed corpus runners for parser and trace-ingestion coverage. The goal is to catch hostile-input bugs before they ship, not to optimize for vanity fuzzing numbers.

## Current Runners

- `zara_loader_corpus_runner`  
  Exercises binary loading, section mapping, symbol population, and rebasing against a corpus of valid and malformed binaries.
- `zara_trace_corpus_runner`  
  Exercises trace parsing against valid, truncated, oversized, and malformed trace inputs.

## Build

Use the sanitizer preset:

```bash
cmake --preset asan-fuzz
cmake --build --preset asan-fuzz
```

## Prepare a Corpus

```bash
./fuzz/prepare_corpus.sh /tmp/zara-fuzz-corpus
```

That creates:

- `loader/`  
  Seed binaries, malformed inputs, truncations, and mutated samples.
- `trace/`  
  Valid traces plus malformed-address and oversized-label cases.

## Run a Quick Pass

```bash
./build/asan-fuzz/fuzz/zara_loader_corpus_runner /tmp/zara-fuzz-corpus/loader --repeat 5
./build/asan-fuzz/fuzz/zara_trace_corpus_runner /tmp/zara-fuzz-corpus/trace --repeat 10
```

Malformed inputs are expected to be rejected cleanly. A crash, sanitizer finding, or unexpected termination is a failure.

## Sustained Campaign

```bash
./fuzz/run_sustained_campaign.sh ./build/asan-fuzz /tmp/zara-fuzz-corpus /tmp/zara-fuzz-out
```

Useful overrides:

```bash
ZARA_FUZZ_REPEAT_LOADER=50 \
ZARA_FUZZ_REPEAT_TRACE=100 \
./fuzz/run_sustained_campaign.sh
```

The wrapper prepares a corpus, runs both replay runners, and writes timestamped logs under the chosen output directory.

## Sanitizer Note

If sanitizer binaries are run under a tracer or in a restricted sandbox, LeakSanitizer may refuse to start. In that case, keep ASan and UBSan enabled and disable leak detection for that session:

```bash
ASAN_OPTIONS=detect_leaks=0 ./fuzz/run_sustained_campaign.sh
```

## Release Guidance

- keep adversarial corpora separate from benchmarks
- run the sanitizer preset after parser or trace-ingestion changes
- keep a small daily corpus and a larger pre-release corpus
- treat sanitizer findings as release blockers until triaged
