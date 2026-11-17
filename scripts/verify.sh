#!/usr/bin/env bash
set -euo pipefail

echo "=== 1. Checking Code Formatting ==="
cargo fmt --all -- --check

echo "=== 2. Running Clippy Lints ==="
cargo clippy --all-targets -- -D warnings

echo "=== 3. Running Unit Tests ==="
cargo test --all-targets

echo "=== 4. Validating metadata.toml ==="
python3 -c '
import tomllib

with open("metadata.toml", "rb") as f:
    m = tomllib.load(f)

# Check description length
desc = m.get("description", "")
assert len(desc) <= 79, f"Description too long: {len(desc)} characters (max 79)"
print(f"  Description length: {len(desc)} characters (valid)")

# Check no active SKIP checksums
for key in ["sha256sums", "sha512sums", "sha1sums", "md5sums"]:
    sums = m.get(key, [])
    assert not any(s.strip().upper() == "SKIP" for s in sums), f"Found SKIP in {key}!"

# Check platform tables
build = m.get("build", {})
for plat, pcfg in build.items():
    for key in ["sha256sums", "sha512sums", "sha1sums", "md5sums"]:
        sums = pcfg.get(key, [])
        assert not any(s.strip().upper() == "SKIP" for s in sums), f"Found SKIP in [build.{plat}].{key}!"

print("  No SKIP checksums found in active configuration.")
'

echo "=== All Verification Checks Passed Successfully! ==="
