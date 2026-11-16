// SPDX-FileCopyrightText: 2026 Vericto S.A.S.
// SPDX-License-Identifier: AGPL-3.0-only

//! The database URL in the OS credential store (5.2.0, "hard mode"): macOS
//! Keychain, the Secret Service on Linux (GNOME Keyring, KWallet), Windows
//! Credential Manager. `--database-url-keychain <name>` reads it at startup;
//! `vericto-proxy mcp credential set|delete|test <name>` stores, removes and
//! checks it, so the URL never has to sit in a file, in the agent's MCP
//! configuration or in its environment.
//!
//! An entry is named `account` (under the service [`DEFAULT_SERVICE`]) or
//! `service/account`. The secret is never printed, logged or echoed back:
//! errors name the entry, never its value.

use std::collections::HashMap;
use std::io::{IsTerminal, Read};
use std::sync::Mutex;

/// The keychain service entries are stored under when the name gives none.
pub const DEFAULT_SERVICE: &str = "vericto-proxy";

/// The longest secret accepted (a database URL with a long password and TLS
/// file paths stays far below it).
pub const MAX_SECRET_BYTES: usize = 8 * 1024;

/// A keychain entry: `account` under `service`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntryName {
    pub service: String,
    pub account: String,
}

impl EntryName {
    /// `account` or `service/account`: 1 to 128 characters each, letters,
    /// digits and `. _ - @ :` (no spaces, no other `/`).
    pub fn parse(raw: &str) -> Result<Self, String> {
        let raw = raw.trim();
        let (service, account) = match raw.split_once('/') {
            Some((s, a)) => (s, a),
            None => (DEFAULT_SERVICE, raw),
        };
        let ok = |s: &str| {
            !s.is_empty()
                && s.len() <= 128
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@' | ':'))
        };
        if !ok(service) || !ok(account) {
            return Err(format!(
                "{raw:?} is not a keychain entry name: use `name` or `service/name`, 1 to 128 \
                 letters, digits or . _ - @ : each"
            ));
        }
        Ok(Self {
            service: service.to_string(),
            account: account.to_string(),
        })
    }

    /// `service/account`, as logs and `whoami` name it.
    pub fn display(&self) -> String {
        format!("{}/{}", self.service, self.account)
    }

    /// The shortest name that means this entry on the command line.
    pub fn cli_name(&self) -> String {
        if self.service == DEFAULT_SERVICE {
            self.account.clone()
        } else {
            self.display()
        }
    }
}

/// A credential store. The OS one is [`OsStore`]; tests use [`MemoryStore`].
pub trait SecretStore: Send + Sync {
    /// The secret, `None` when there is no such entry.
    fn get(&self, name: &EntryName) -> Result<Option<String>, String>;
    fn set(&self, name: &EntryName, secret: &str) -> Result<(), String>;
    /// Whether there was an entry to delete.
    fn delete(&self, name: &EntryName) -> Result<bool, String>;
    /// What it is, for messages ("macOS Keychain" …).
    fn backend(&self) -> &'static str;
}

/// The OS credential store, through the `keyring` crate (the `keychain`
/// feature, on by default).
pub struct OsStore;

/// The name of the OS store on this platform.
pub fn os_backend_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else if cfg!(target_os = "windows") {
        "Windows Credential Manager"
    } else if cfg!(any(
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd"
    )) {
        "Secret Service (secret-tool: GNOME Keyring / KWallet)"
    } else {
        "OS credential store"
    }
}

#[cfg(all(feature = "keychain", any(target_os = "macos", target_os = "windows")))]
mod os {
    use super::EntryName;

    /// Runs `f` on a thread of its own: the Secret Service client blocks on a
    /// runtime of its own, which cannot start on a tokio worker thread.
    fn off_runtime<T: Send>(f: impl FnOnce() -> T + Send) -> T {
        std::thread::scope(|s| {
            s.spawn(f)
                .join()
                .unwrap_or_else(|_| panic!("the keychain thread panicked"))
        })
    }

    fn describe(e: &keyring::Error) -> String {
        // Never the secret: keyring's errors carry the platform's message,
        // the entry's attributes at most.
        match e {
            keyring::Error::NoStorageAccess(_) => {
                "the credential store is not available (locked, or no Secret Service running: \
                 on a server or in a container use --database-url-file)"
                    .to_string()
            }
            keyring::Error::PlatformFailure(_) => {
                "the credential store refused the request (it may be locked, or access was denied)"
                    .to_string()
            }
            keyring::Error::BadEncoding(_) => "the stored entry is not UTF-8 text".to_string(),
            keyring::Error::TooLong(..) => "the value is too long for the credential store".to_string(),
            keyring::Error::Invalid(..) => "the entry name is not valid for this store".to_string(),
            keyring::Error::Ambiguous(_) => {
                "several entries match this name in the credential store; delete them and store it again"
                    .to_string()
            }
            keyring::Error::NoEntry => "no such entry".to_string(),
            _ => "the credential store failed".to_string(),
        }
    }

    pub fn get(name: &EntryName) -> Result<Option<String>, String> {
        off_runtime(|| {
            let entry =
                keyring::Entry::new(&name.service, &name.account).map_err(|e| describe(&e))?;
            match entry.get_password() {
                Ok(s) => Ok(Some(s)),
                Err(keyring::Error::NoEntry) => Ok(None),
                Err(e) => Err(describe(&e)),
            }
        })
    }

    pub fn set(name: &EntryName, secret: &str) -> Result<(), String> {
        off_runtime(|| {
            let entry =
                keyring::Entry::new(&name.service, &name.account).map_err(|e| describe(&e))?;
            entry.set_password(secret).map_err(|e| describe(&e))
        })
    }

    pub fn delete(name: &EntryName) -> Result<bool, String> {
        off_runtime(|| {
            let entry =
                keyring::Entry::new(&name.service, &name.account).map_err(|e| describe(&e))?;
            match entry.delete_credential() {
                Ok(()) => Ok(true),
                Err(keyring::Error::NoEntry) => Ok(false),
                Err(e) => Err(describe(&e)),
            }
        })
    }
}

#[cfg(all(feature = "keychain", unix, not(target_os = "macos")))]
mod os {
    //! Linux and the BSDs: the Secret Service through `secret-tool`.
    use super::{EntryName, SecretTool};

    pub fn get(name: &EntryName) -> Result<Option<String>, String> {
        SecretTool::system().get(name)
    }
    pub fn set(name: &EntryName, secret: &str) -> Result<(), String> {
        SecretTool::system().set(name, secret)
    }
    pub fn delete(name: &EntryName) -> Result<bool, String> {
        SecretTool::system().delete(name)
    }
}

#[cfg(not(all(feature = "keychain", any(unix, target_os = "windows"))))]
mod os {
    use super::EntryName;

    const OFF: &str = "this build has no keychain support (built without the `keychain` feature); \
                       use --database-url-file";

    pub fn get(_: &EntryName) -> Result<Option<String>, String> {
        Err(OFF.to_string())
    }
    pub fn set(_: &EntryName, _: &str) -> Result<(), String> {
        Err(OFF.to_string())
    }
    pub fn delete(_: &EntryName) -> Result<bool, String> {
        Err(OFF.to_string())
    }
}

/// The Secret Service (GNOME Keyring, KWallet) through libsecret's
/// `secret-tool` (package `libsecret-tools` on Debian and Ubuntu,
/// `libsecret` on Fedora and Arch). The secret travels on the tool's stdin
/// and stdout only, never on a command line; the entry is the attributes
/// `service` and `account`, plus `application=vericto-proxy`.
#[cfg(unix)]
#[cfg_attr(target_os = "macos", allow(dead_code))]
pub struct SecretTool {
    program: std::path::PathBuf,
}

#[cfg(unix)]
#[cfg_attr(target_os = "macos", allow(dead_code))]
impl SecretTool {
    /// `/usr/bin/secret-tool` when it exists, else `secret-tool` on PATH.
    pub fn system() -> Self {
        let fixed = std::path::Path::new("/usr/bin/secret-tool");
        Self {
            program: if fixed.exists() {
                fixed.to_path_buf()
            } else {
                "secret-tool".into()
            },
        }
    }

    /// A given program (the tests' stand-in).
    pub fn at(program: impl Into<std::path::PathBuf>) -> Self {
        Self {
            program: program.into(),
        }
    }

    fn run(
        &self,
        args: &[&str],
        name: &EntryName,
        stdin: Option<&str>,
    ) -> Result<std::process::Output, String> {
        use std::io::Write;
        use std::process::{Command, Stdio};
        let mut cmd = Command::new(&self.program);
        cmd.args(args)
            .args(["service", &name.service, "account", &name.account])
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if args.first() == Some(&"store") {
            cmd.args(["application", "vericto-proxy"]);
        }
        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "secret-tool is not installed (package libsecret-tools on Debian and Ubuntu, \
                 libsecret on Fedora and Arch); install it, or use --database-url-file"
                    .to_string()
            } else {
                format!("secret-tool could not be started ({})", e.kind())
            }
        })?;
        if let (Some(s), Some(mut i)) = (stdin, child.stdin.take()) {
            i.write_all(s.as_bytes())
                .map_err(|e| format!("cannot write to secret-tool ({})", e.kind()))?;
        }
        child
            .wait_with_output()
            .map_err(|e| format!("secret-tool failed ({})", e.kind()))
    }

    /// secret-tool's stderr, which names the D-Bus failure, never a secret.
    fn failure(out: &std::process::Output) -> String {
        let e = String::from_utf8_lossy(&out.stderr);
        let e = e.trim();
        if e.is_empty() {
            "the Secret Service refused the request (is the keyring unlocked?)".to_string()
        } else {
            format!(
                "the Secret Service failed ({}); on a server or in a container use --database-url-file",
                e.chars().take(200).collect::<String>()
            )
        }
    }

    pub fn get(&self, name: &EntryName) -> Result<Option<String>, String> {
        let out = self.run(&["lookup"], name, None)?;
        if out.status.success() {
            let s = String::from_utf8(out.stdout)
                .map_err(|_| "the stored entry is not UTF-8 text".to_string())?;
            return Ok(Some(s.trim_end_matches(['\n', '\r']).to_string()));
        }
        // `lookup` exits 1 without a message when nothing matches.
        if out.stderr.iter().all(u8::is_ascii_whitespace) {
            return Ok(None);
        }
        Err(Self::failure(&out))
    }

    pub fn set(&self, name: &EntryName, secret: &str) -> Result<(), String> {
        let label = format!("vericto-proxy database URL ({})", name.display());
        let out = self.run(&["store", "--label", &label], name, Some(secret))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(Self::failure(&out))
        }
    }

    pub fn delete(&self, name: &EntryName) -> Result<bool, String> {
        let existed = self.get(name)?.is_some();
        if !existed {
            return Ok(false);
        }
        let out = self.run(&["clear"], name, None)?;
        if out.status.success() {
            Ok(true)
        } else {
            Err(Self::failure(&out))
        }
    }
}

impl SecretStore for OsStore {
    fn get(&self, name: &EntryName) -> Result<Option<String>, String> {
        os::get(name)
    }
    fn set(&self, name: &EntryName, secret: &str) -> Result<(), String> {
        os::set(name, secret)
    }
    fn delete(&self, name: &EntryName) -> Result<bool, String> {
        os::delete(name)
    }
    fn backend(&self) -> &'static str {
        os_backend_name()
    }
}

/// An in-memory store: the mock backend of the tests (CI has no keychain).
#[derive(Default)]
pub struct MemoryStore {
    entries: Mutex<HashMap<EntryName, String>>,
}

impl SecretStore for MemoryStore {
    fn get(&self, name: &EntryName) -> Result<Option<String>, String> {
        Ok(self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .cloned())
    }
    fn set(&self, name: &EntryName, secret: &str) -> Result<(), String> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name.clone(), secret.to_string());
        Ok(())
    }
    fn delete(&self, name: &EntryName) -> Result<bool, String> {
        Ok(self
            .entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(name)
            .is_some())
    }
    fn backend(&self) -> &'static str {
        "in-memory test store"
    }
}

/// A store in one JSON file, for the end-to-end tests of the debug binary
/// (`VERICTO_MCP_TEST_KEYCHAIN_FILE`). Never compiled into a release build.
#[cfg(debug_assertions)]
pub struct FileStore(pub std::path::PathBuf);

#[cfg(debug_assertions)]
impl FileStore {
    fn load(&self) -> HashMap<String, String> {
        std::fs::read_to_string(&self.0)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    fn save(&self, m: &HashMap<String, String>) -> Result<(), String> {
        std::fs::write(&self.0, serde_json::to_string(m).unwrap_or_default())
            .map_err(|e| format!("cannot write the test store ({})", e.kind()))
    }
}

#[cfg(debug_assertions)]
impl SecretStore for FileStore {
    fn get(&self, name: &EntryName) -> Result<Option<String>, String> {
        Ok(self.load().get(&name.display()).cloned())
    }
    fn set(&self, name: &EntryName, secret: &str) -> Result<(), String> {
        let mut m = self.load();
        m.insert(name.display(), secret.to_string());
        self.save(&m)
    }
    fn delete(&self, name: &EntryName) -> Result<bool, String> {
        let mut m = self.load();
        let had = m.remove(&name.display()).is_some();
        self.save(&m)?;
        Ok(had)
    }
    fn backend(&self) -> &'static str {
        "test store file"
    }
}

/// The store this process uses: the OS store; in a debug build, the file
/// `VERICTO_MCP_TEST_KEYCHAIN_FILE` names when it is set (the end-to-end
/// tests, which must never touch the developer's keychain).
pub fn process_store() -> Box<dyn SecretStore> {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("VERICTO_MCP_TEST_KEYCHAIN_FILE") {
        return Box::new(FileStore(p.into()));
    }
    Box::new(OsStore)
}

/// Exit codes of `vericto-proxy mcp credential …` (the CLI's `guard install
/// --hard` reads them).
pub mod exit {
    /// Done; for `test`, connected (see `read_only` in the JSON).
    pub const OK: i32 = 0;
    /// Bad arguments, an invalid URL, or the store failed.
    pub const USAGE: i32 = 1;
    /// No such entry.
    pub const NOT_FOUND: i32 = 2;
    /// `test --require-read-only`: the role can write (or it could not be
    /// verified).
    pub const CAN_WRITE: i32 = 3;
    /// `test`: the database could not be reached or refused the login.
    pub const UNAVAILABLE: i32 = 4;
}

/// Reads the secret for `credential set`: from the terminal without echo
/// (prompt on stderr), or all of stdin when it is a pipe. The trailing newline
/// is dropped.
pub fn read_secret_from_stdin() -> Result<String, String> {
    let raw = if std::io::stdin().is_terminal() {
        rpassword::prompt_password("Database URL (input hidden): ")
            .map_err(|e| format!("cannot read the URL from the terminal ({})", e.kind()))?
    } else {
        let mut buf = String::new();
        std::io::stdin()
            .take(MAX_SECRET_BYTES as u64 + 1)
            .read_to_string(&mut buf)
            .map_err(|e| format!("cannot read the URL from stdin ({})", e.kind()))?;
        buf
    };
    let s = raw.trim_end_matches(['\n', '\r']).trim().to_string();
    if s.is_empty() {
        return Err("no URL on stdin".to_string());
    }
    if s.len() > MAX_SECRET_BYTES {
        return Err(format!("the URL is longer than {MAX_SECRET_BYTES} bytes"));
    }
    if s.contains('\n') {
        return Err("stdin holds more than one line; send the URL alone".to_string());
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_default_to_the_vericto_service() {
        let n = EntryName::parse("shop").unwrap();
        assert_eq!(n.service, DEFAULT_SERVICE);
        assert_eq!(n.account, "shop");
        assert_eq!(n.display(), "vericto-proxy/shop");
        assert_eq!(n.cli_name(), "shop");
        let n = EntryName::parse("acme-db/prod.ro@eu").unwrap();
        assert_eq!(n.service, "acme-db");
        assert_eq!(n.account, "prod.ro@eu");
        assert_eq!(n.cli_name(), "acme-db/prod.ro@eu");
        for bad in ["", "a b", "a/b/c", "/x", "x/", "naïve", &"x".repeat(129)] {
            assert!(EntryName::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_memory_store_round_trips() {
        let s = MemoryStore::default();
        let n = EntryName::parse("t").unwrap();
        assert_eq!(s.get(&n).unwrap(), None);
        s.set(&n, "postgres://u:p@localhost/x").unwrap();
        assert_eq!(
            s.get(&n).unwrap().as_deref(),
            Some("postgres://u:p@localhost/x")
        );
        assert!(s.delete(&n).unwrap());
        assert!(!s.delete(&n).unwrap());
    }

    /// The `secret-tool` protocol, against a stand-in script that keeps
    /// entries in a directory (the real tool needs a Linux session bus).
    #[cfg(unix)]
    #[test]
    fn secret_tool_round_trips_through_stdin_and_stdout() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("secret-tool");
        let log = dir.path().join("argv.log");
        std::fs::write(
            &tool,
            format!(
                r#"#!/bin/sh
echo "$@" >> '{log}'
cmd="$1"; shift
[ "$cmd" = store ] && shift 2
key="$1_$2_$3_$4"
f='{dir}'/"$key"
case "$cmd" in
  lookup) [ -f "$f" ] || exit 1; cat "$f"; echo ;;
  store) cat > "$f" ;;
  clear) rm -f "$f" ;;
esac
"#,
                log = log.display(),
                dir = dir.path().display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
        let st = SecretTool::at(&tool);
        let n = EntryName::parse("shop").unwrap();
        assert_eq!(st.get(&n).unwrap(), None);
        st.set(&n, "mysql://u:s3cret@127.0.0.1/x").unwrap();
        assert_eq!(
            st.get(&n).unwrap().as_deref(),
            Some("mysql://u:s3cret@127.0.0.1/x")
        );
        assert!(st.delete(&n).unwrap());
        assert!(!st.delete(&n).unwrap());
        // The secret never appears on a command line.
        let argv = std::fs::read_to_string(&log).unwrap();
        assert!(!argv.contains("s3cret"), "{argv}");
        assert!(
            argv.contains("service vericto-proxy account shop"),
            "{argv}"
        );
        // A tool that is missing says how to install it.
        let e = SecretTool::at(dir.path().join("nope")).get(&n).unwrap_err();
        assert!(e.contains("libsecret"), "{e}");
    }

    /// The real OS store, only when `VERICTO_TEST_KEYCHAIN=1` (a developer
    /// machine with an unlocked keychain; CI has none). Uses a service name of
    /// its own, never an entry of the user's, and deletes it.
    #[test]
    fn the_os_store_round_trips_when_enabled() {
        if std::env::var("VERICTO_TEST_KEYCHAIN").as_deref() != Ok("1") {
            eprintln!("VERICTO_TEST_KEYCHAIN not set: skipping the OS keychain test");
            return;
        }
        let suffix = &uuid::Uuid::new_v4().simple().to_string()[..10];
        let n = EntryName::parse(&format!("vericto-proxy-test-{suffix}/db")).unwrap();
        let store = OsStore;
        assert_eq!(store.get(&n).unwrap(), None);
        store.set(&n, "mysql://u:s3cret@127.0.0.1:3306/x").unwrap();
        let got = store.get(&n);
        let deleted = store.delete(&n);
        assert_eq!(
            got.unwrap().as_deref(),
            Some("mysql://u:s3cret@127.0.0.1:3306/x")
        );
        assert!(deleted.unwrap());
        assert_eq!(store.get(&n).unwrap(), None);
    }
}
