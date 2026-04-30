//! End-to-end CLI smoke test using the actual `freenet-git` binary
//! against a temp identity bundle path. Exercises the offline commands.
//!
//! Network commands (`create --publish-to`) live in the e2e harness.

use std::process::{Command, Stdio};

fn binary_path() -> std::path::PathBuf {
    let mut p = std::env::current_exe().expect("current_exe");
    // .../target/debug/deps/cli_smoke-XXXX -> .../target/debug/deps
    p.pop(); // pop test binary name
    if p.ends_with("deps") {
        p.pop();
    }
    p.join("freenet-git")
}

fn cli(bundle_path: &std::path::Path, passphrase: &str) -> Command {
    let mut cmd = Command::new(binary_path());
    cmd.env("FREENET_GIT_IDENTITY", bundle_path);
    // Tests run without a TTY, so the prompt env var path is required.
    cmd.env("FREENET_GIT_PASSPHRASE", passphrase);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn run(mut cmd: Command) -> std::process::Output {
    cmd.spawn()
        .expect("spawn")
        .wait_with_output()
        .expect("wait")
}

#[test]
fn init_identity_creates_bundle_and_whoami_reads_it() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("id.bundle");

    let mut init = cli(&bundle, "correct horse");
    init.args([
        "init-identity",
        "--name",
        "Tester",
        "--email",
        "tester@example.com",
    ]);
    let out = run(init);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "init-identity failed; stderr: {stderr}"
    );
    assert!(
        stdout.contains("Generated ed25519 keypair"),
        "got stdout: {stdout}"
    );
    assert!(stdout.contains("freenet:id:"), "got stdout: {stdout}");
    assert!(bundle.exists(), "bundle file should have been written");

    let mut whoami = cli(&bundle, "correct horse");
    whoami.arg("whoami");
    let out = run(whoami);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "whoami failed; stderr: {stderr}");
    assert!(
        stdout.contains("Tester <tester@example.com>"),
        "got stdout: {stdout}"
    );
    assert!(stdout.contains("freenet:id:"), "got stdout: {stdout}");
}

#[test]
fn whoami_with_wrong_passphrase_fails() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("id.bundle");

    let mut init = cli(&bundle, "right-passphrase");
    init.args(["init-identity", "--name", "X", "--email", "x@e.com"]);
    assert!(run(init).status.success());

    let mut whoami = cli(&bundle, "wrong-passphrase");
    whoami.arg("whoami");
    let out = run(whoami);
    assert!(!out.status.success(), "wrong passphrase should fail");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("decrypt")
            || stderr.contains("Decryption")
            || stderr.contains("decryption"),
        "expected decrypt error, got: {stderr}"
    );
}

#[test]
fn init_identity_rejects_overwriting_existing_bundle() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("id.bundle");
    std::fs::write(&bundle, b"placeholder").unwrap();

    let mut init = cli(&bundle, "x");
    init.args(["init-identity", "--name", "X", "--email", "x@e.com"]);
    let out = run(init);
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("refusing to overwrite"),
        "expected refusal, got: {stderr}"
    );
}

#[test]
fn create_repo_prints_url_and_writes_temp_artifacts() {
    let dir = tempfile::tempdir().unwrap();
    let bundle = dir.path().join("id.bundle");

    // 1. init identity.
    let mut init = cli(&bundle, "pw");
    init.args(["init-identity", "--name", "Owner", "--email", "o@e.com"]);
    assert!(run(init).status.success());

    // 2. write a tiny stand-in WASM file. The CLI does not execute it, it
    //    just hashes the bytes to derive the contract id, so any bytes
    //    work for this test.
    let fake_wasm = dir.path().join("repo.wasm");
    std::fs::write(&fake_wasm, b"fake-wasm-bytes-for-id-derivation").unwrap();

    // 3. run `create` without --publish-to. With no registered repos and
    //    a passphrase that lets us re-write the bundle, the command
    //    succeeds and prints a freenet:... URL.
    let mut create = cli(&bundle, "pw");
    create.args([
        "create",
        "--name",
        "demo",
        "--description",
        "a demo repo",
        "--repo-wasm",
    ]);
    create.arg(&fake_wasm);
    let out = run(create);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "create failed; stderr: {stderr}");
    assert!(stdout.contains("URL:"), "got stdout: {stdout}");
    assert!(stdout.contains("freenet:"), "got stdout: {stdout}");
    assert!(
        stdout.contains("Registered repo"),
        "should record in bundle: {stdout}"
    );
}
