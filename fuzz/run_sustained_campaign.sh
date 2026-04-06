#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="${1:-$repo_root/build/asan-fuzz}"
corpus_root="${2:-/tmp/zara-fuzz-corpus}"
output_root="${3:-/tmp/zara-fuzz-out}"
loader_repeat="${ZARA_FUZZ_REPEAT_LOADER:-25}"
trace_repeat="${ZARA_FUZZ_REPEAT_TRACE:-50}"
prepare_corpus="${ZARA_FUZZ_PREPARE_CORPUS:-1}"

loader_runner="$build_dir/fuzz/zara_loader_corpus_runner"
trace_runner="$build_dir/fuzz/zara_trace_corpus_runner"

if [[ "$prepare_corpus" != "0" ]]; then
    "$repo_root/fuzz/prepare_corpus.sh" "$corpus_root"
fi

if [[ ! -x "$loader_runner" ]]; then
    echo "missing loader runner: $loader_runner" >&2
    exit 1
fi
if [[ ! -x "$trace_runner" ]]; then
    echo "missing trace runner: $trace_runner" >&2
    exit 1
fi

mkdir -p "$output_root"
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
log_path="$output_root/campaign-$timestamp.log"

{
    echo "Zara sustained sanitizer campaign"
    echo "  build: $build_dir"
    echo "  corpus: $corpus_root"
    echo "  output: $output_root"
    echo "  loader repeat: $loader_repeat"
    echo "  trace repeat: $trace_repeat"
    echo

    "$loader_runner" "$corpus_root/loader" --repeat "$loader_repeat"
    echo
    "$trace_runner" "$corpus_root/trace" --repeat "$trace_repeat"
} > "$log_path" 2>&1

echo "Campaign log written to $log_path"
sed -n '1,200p' "$log_path"
