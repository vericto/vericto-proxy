// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! `vericto-proxy --version` (and `-V`) prints the version on stdout and exits
//! without starting the proxy, even with no UPSTREAM_HOST: the Homebrew
//! formula's `test do` runs it.

use std::process::Command;

#[test]
fn version_flag_prints_the_version_and_exits() {
    for flag in ["--version", "-V"] {
        let out = Command::new(env!("CARGO_BIN_EXE_vericto-proxy"))
            .arg(flag)
            .env_clear()
            .output()
            .unwrap();
        assert!(out.status.success(), "{flag}: {out:?}");
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("vericto-proxy {}\n", env!("CARGO_PKG_VERSION")),
            "{flag}"
        );
        assert!(out.stderr.is_empty(), "{flag}: nothing on stderr");
    }
}
