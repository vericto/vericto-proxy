#!/bin/sh
# Write THIRD_PARTY_LICENSES for the vericto-proxy binary.
#   usage: third-party/build-notices.sh <output file>   (run from the repository root)
#
# The file is cargo-about's report on the Rust crates (third-party/about.toml and
# about.hbs) followed by third-party/pg_query-bundled.txt, which covers the C code
# pg_query compiles in. That second part is maintained by hand, so the script
# refuses to run when it describes a different pg_query version than Cargo.lock.
set -eu

out=${1:?usage: build-notices.sh <output file>}
bundled=third-party/pg_query-bundled.txt

locked=$(awk '/^name = "pg_query"$/ { getline; gsub(/^version = "|"$/, ""); print; exit }' Cargo.lock)
recorded=$(sed -n 's/^pg_query version: //p' "$bundled")
if [ -z "$locked" ] || [ "$locked" != "$recorded" ]; then
    echo "build-notices: $bundled describes pg_query '$recorded' but Cargo.lock has '$locked'." >&2
    echo "build-notices: update its license texts and version line for the new release." >&2
    exit 1
fi

cargo about generate --locked --fail -c third-party/about.toml -o "$out" third-party/about.hbs
printf '\n' >> "$out"
cat "$bundled" >> "$out"
