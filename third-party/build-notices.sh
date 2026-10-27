#!/bin/sh
# SPDX-FileCopyrightText: 2026 Vericto S.A.S.
# SPDX-License-Identifier: FSL-1.1-ALv2

# Write THIRD_PARTY_LICENSES for the vericto-proxy binary.
#   usage: third-party/build-notices.sh <output file>   (run from the repository root)
#
# The file is cargo-about's report on the Rust crates (third-party/about.toml and
# about.hbs) followed by third-party/pg_query-bundled.txt and
# third-party/mimalloc-bundled.txt, which cover the C code pg_query and
# libmimalloc-sys compile in. Those parts are maintained by hand, so the script
# refuses to run when one describes a different crate version than Cargo.lock.
set -eu

out=${1:?usage: build-notices.sh <output file>}

# check <bundled notice file> <crate>: the file must describe the version of the
# crate that Cargo.lock pins (it says so on a "<crate> version: " line).
check() {
    locked=$(awk -v name="name = \"$2\"" '$0 == name { getline; gsub(/^version = "|"$/, ""); print; exit }' Cargo.lock)
    recorded=$(sed -n "s/^$2 version: //p" "$1")
    if [ -z "$locked" ] || [ "$locked" != "$recorded" ]; then
        echo "build-notices: $1 describes $2 '$recorded' but Cargo.lock has '$locked'." >&2
        echo "build-notices: update its license texts and version line for the new release." >&2
        exit 1
    fi
}
check third-party/pg_query-bundled.txt pg_query
check third-party/mimalloc-bundled.txt libmimalloc-sys

cargo about generate --locked --fail -c third-party/about.toml -o "$out" third-party/about.hbs
for bundled in third-party/pg_query-bundled.txt third-party/mimalloc-bundled.txt; do
    printf '\n' >> "$out"
    cat "$bundled" >> "$out"
done
