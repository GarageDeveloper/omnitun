//! The completion scripts, run by the shells against the real binary and a
//! profiles file of their own.

use std::path::PathBuf;
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_omnitunctl");

const PROFILES: &str = r#"
[[profile]]
id = "00000000-0000-4000-8000-000000000001"
name = "paris"
protocol = "forti-ssl"
host = "vpn.example.com"

[[profile]]
id = "00000000-0000-4000-8000-000000000002"
name = "lyon office"
folder = "Sites"
protocol = "forti-ssl"
host = "vpn.example.com"

[[profile]]
id = "00000000-0000-4000-8000-000000000003"
name = "EU"
folder = "Clients/Acme"
protocol = "forti-ssl"
host = "vpn.example.com"

[[profile]]
id = "00000000-0000-4000-8000-000000000004"
name = "EU"
folder = "Clients/Beta"
protocol = "forti-ssl"
host = "vpn.example.com"
"#;

/// A folder holding a profiles file and the generated script.
struct Bench {
    dir: PathBuf,
}

impl Bench {
    fn new(shell: &str) -> Self {
        // Tests run in parallel: one folder each.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("omnitunctl-completions-{shell}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Built first, so a failure below still removes the folder.
        let bench = Self { dir };
        std::fs::write(bench.profiles(), PROFILES).unwrap();
        let script = Command::new(BIN).args(["completions", shell]).output().unwrap();
        assert!(script.status.success(), "{}", String::from_utf8_lossy(&script.stderr));
        std::fs::write(bench.script(), script.stdout).unwrap();
        bench
    }

    fn profiles(&self) -> PathBuf {
        self.dir.join("profiles.toml")
    }

    fn script(&self) -> PathBuf {
        self.dir.join("script")
    }
}

impl Drop for Bench {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn run(shell: &str, args: &[&str], code: &str) -> Vec<String> {
    let out = Command::new(shell).args(args).arg(code).output().unwrap();
    assert!(out.status.success(), "{shell}: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8(out.stdout).unwrap().lines().map(str::to_owned).collect()
}

/// What bash's completion function offers for `words`, the last one being
/// the word under the cursor, split as bash splits them (`--config=a` is
/// `--config`, `=`, `a`: `=` is in `COMP_WORDBREAKS`). The bench is `$HOME`.
fn bash_complete(bench: &Bench, words: &[&str]) -> Vec<String> {
    let quoted: Vec<String> = words.iter().map(|w| format!("'{w}'")).collect();
    let code = format!(
        "HOME='{}'\nsource '{}'\nCOMP_WORDS=('{BIN}' {})\nCOMP_CWORD={}\nCOMP_LINE=\"${{COMP_WORDS[*]}}\"\n\
         _omnitunctl '{BIN}' \"${{COMP_WORDS[COMP_CWORD]}}\" \"${{COMP_WORDS[COMP_CWORD-1]}}\"\n\
         printf '%s\\n' \"${{COMPREPLY[@]}}\"",
        bench.dir.display(),
        bench.script().display(),
        quoted.join(" "),
        words.len()
    );
    run("bash", &["--norc", "--noprofile", "-c"], &code)
}

fn config(bench: &Bench) -> String {
    bench.profiles().display().to_string()
}

#[test]
fn bash_offers_profile_names() {
    let bench = Bench::new("bash");
    let config = config(&bench);
    assert_eq!(
        bash_complete(&bench, &["--config", &config, "connect", ""]),
        ["paris", "lyon\\ office", "Clients/Acme/EU", "Clients/Beta/EU"]
    );
    assert_eq!(
        bash_complete(&bench, &["--config", &config, "connect", "paris", "Cl"]),
        ["Clients/Acme/EU", "Clients/Beta/EU"]
    );
    assert_eq!(bash_complete(&bench, &["--config", &config, "secret", "set", "ly"]), ["lyon\\ office"]);
    assert_eq!(bash_complete(&bench, &["--config", &config, "duplicate", "pa"]), ["paris"]);
}

#[test]
fn bash_reads_the_config_however_it_is_written() {
    let bench = Bench::new("bash");
    let config = config(&bench);
    assert_eq!(bash_complete(&bench, &["--config", "=", &config, "connect", "pa"]), ["paris"]);
    assert_eq!(bash_complete(&bench, &["--config", "~/profiles.toml", "connect", "pa"]), ["paris"]);
}

#[test]
fn bash_offers_files_for_path_options() {
    let bench = Bench::new("bash");
    let config = config(&bench);
    let prefix = format!("{}/pro", bench.dir.display());
    assert_eq!(bash_complete(&bench, &["--config", &prefix]), std::slice::from_ref(&config));
    assert_eq!(bash_complete(&bench, &["--config", &config, "export", "paris", "-o", &prefix]), [config]);
}

#[test]
fn bash_offers_subcommands() {
    let bench = Bench::new("bash");
    let offered = bash_complete(&bench, &["dis"]);
    assert_eq!(offered, ["disconnect"]);
}

fn has(program: &str) -> bool {
    Command::new(program).arg("-c").arg("true").status().is_ok_and(|s| s.success())
}

#[test]
fn zsh_offers_profile_names_from_the_given_file() {
    if !has("zsh") {
        eprintln!("zsh is not installed: zsh completions not checked");
        return;
    }
    let bench = Bench::new("zsh");
    let all = ["paris", "lyon office", "Clients/Acme/EU", "Clients/Beta/EU"];
    assert_eq!(zsh_complete(&bench, &format!("{BIN} --config {} connect ", config(&bench))), all);
    // The command is the binary, not what comes before it on the line.
    assert_eq!(zsh_complete(&bench, &format!("RUST_LOG=debug {BIN} --config {} connect ", config(&bench))), all);
    assert_eq!(zsh_complete(&bench, &format!("{BIN} --config ~/profiles.toml connect ")), all);
    assert_eq!(zsh_complete(&bench, &format!("{BIN} --config=~/profiles.toml connect ")), all);
}

/// What zsh's profile function offers for the command line `buffer`; the
/// bench is `$HOME`.
fn zsh_complete(bench: &Bench, buffer: &str) -> Vec<String> {
    // compadd and compdef only exist inside the completion system: stand-ins
    // that print what would be offered.
    let code = format!(
        "compadd() {{ while [[ $1 != -- ]]; do shift; done; shift; print -rl -- \"$@\" }}\n\
         compdef() {{ : }}\n\
         HOME='{}'\n\
         source '{}'\n\
         BUFFER=\"{buffer}\"\n\
         _omnitunctl_profiles",
        bench.dir.display(),
        bench.script().display(),
    );
    run("zsh", &["-f", "-c"], &code)
}

#[test]
fn scripts_are_valid_shell() {
    for (shell, check) in [("bash", "bash"), ("zsh", "zsh")] {
        if !has(check) {
            eprintln!("{check} is not installed: {shell} script not checked");
            continue;
        }
        let bench = Bench::new(shell);
        let out = Command::new(check).arg("-n").arg(bench.script()).output().unwrap();
        assert!(out.status.success(), "{shell}: {}", String::from_utf8_lossy(&out.stderr));
    }
}
