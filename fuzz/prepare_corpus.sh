#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out_root="${1:-/tmp/zara-fuzz-corpus}"
loader_dir="$out_root/loader"
trace_dir="$out_root/trace"

rm -rf "$out_root"
mkdir -p "$loader_dir" "$trace_dir"

sample_bin="$repo_root/tests/fixtures/sample.bin"
if [[ ! -f "$sample_bin" ]]; then
    echo "missing seed fixture: $sample_bin" >&2
    exit 1
fi

cp "$sample_bin" "$loader_dir/raw-sample.bin"
head -c 1 "$sample_bin" > "$loader_dir/raw-sample-trunc-1.bin"
head -c 7 "$sample_bin" > "$loader_dir/raw-sample-trunc-7.bin"
cp "$sample_bin" "$loader_dir/raw-sample-bitflip-0.bin"
printf '\xff' | dd of="$loader_dir/raw-sample-bitflip-0.bin" bs=1 seek=0 count=1 conv=notrunc status=none
cp "$sample_bin" "$loader_dir/raw-sample-append-junk.bin"
printf '\x00\xff\x7fELFPEMACHO' >> "$loader_dir/raw-sample-append-junk.bin"

printf '\x7fELF\x02\x01\x01\x00' > "$loader_dir/truncated-elf.bin"
dd if=/dev/zero of="$loader_dir/truncated-pe.bin" bs=1 count=64 status=none
printf 'MZ' | dd of="$loader_dir/truncated-pe.bin" bs=1 seek=0 conv=notrunc status=none
printf '\xf0\xff\xff\x7f' | dd of="$loader_dir/truncated-pe.bin" bs=1 seek=60 conv=notrunc status=none
printf '\xcf\xfa\xed\xfe\x07\x00\x00\x01' > "$loader_dir/truncated-macho.bin"

cat > "$trace_dir/valid.trace" <<'EOF'
input=seed-01
crash=0x40117d
cover=0x40117d
cover=0x401181
0x401198
EOF

cat > "$trace_dir/comments.trace" <<'EOF'
# coverage-only trace

input=coverage-seed
# comment line
cover=0x401000
cover=0x40100A
0x40100F
EOF

cat > "$trace_dir/invalid-address.trace" <<'EOF'
input=bad-addr
crash=0x40117d
cover=0xGGGG
EOF

{
    printf 'input='
    head -c 5000 /dev/zero | tr '\0' 'A'
    printf '\n'
} > "$trace_dir/oversized-label.trace"

echo "Prepared fuzz corpora in $out_root"
echo "  loader seeds: $(find "$loader_dir" -type f | wc -l | tr -d ' ')"
echo "  trace seeds:  $(find "$trace_dir" -type f | wc -l | tr -d ' ')"
