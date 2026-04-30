//! `git-remote-freenet` — Git remote helper for `freenet:` URLs.
//!
//! Drop this binary on `PATH` and `git clone freenet:<id>` works
//! natively. Git invokes us with two args (remote name, URL) and speaks
//! the [git-remote-helpers protocol] over stdin/stdout.
//!
//! [git-remote-helpers protocol]: https://git-scm.com/docs/gitremote-helpers
//!
//! # Phase 1.0 caveats
//!
//! - Single-writer only: only the repo owner can push. The helper loads
//!   the local identity bundle and uses its key to sign ref-updates and
//!   bundle-add records.
//! - SinglePack only: `ChunkedPack` records in `object_index` are
//!   reported as "this ref needs a newer freenet-git" and skipped.
//! - On push, the helper packs all new objects in one `git pack-objects`
//!   call. No incremental delta-pack optimization yet.
//! - Fetch downloads every pack referenced in `object_index`. No
//!   per-object reachability shortcut yet.

#![deny(unsafe_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use freenet_git_cli::ids::pack_contract_id;
use freenet_git_cli::url;
use freenet_git_cli::wsclient::{self, DEFAULT_WS_URL};
use freenet_git_identity::{default_bundle_path, read_bundle};
use freenet_git_types::signing::{sign_bundle_record, sign_ref_entry};
use freenet_git_types::{update_state as ts_update_state, CommitHash, ObjectBundle, RepoState};
use freenet_stdlib::prelude::ContractInstanceId;

/// Default 60s for any single WS round-trip.
const WS_TIMEOUT: Duration = Duration::from_secs(60);

fn main() -> ExitCode {
    init_tracing();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:?}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        bail!(
            "git-remote-freenet expects exactly 2 arguments (remote name, URL); got {}",
            args.len()
        );
    }
    let _remote_name = &args[0];
    let url_str = &args[1];

    let contract_id = url::parse(url_str).with_context(|| format!("parse remote URL {url_str}"))?;

    let env = HelperEnv::from_env(contract_id)?;

    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();

    let mut input = String::new();
    loop {
        input.clear();
        let n = stdin.read_line(&mut input)?;
        if n == 0 {
            // EOF — git closed the pipe.
            return Ok(());
        }
        let line = input.trim_end_matches('\n');

        if line.is_empty() {
            // git uses blank lines as command terminators; just loop.
            continue;
        }

        if line == "capabilities" {
            writeln!(stdout, "fetch")?;
            writeln!(stdout, "push")?;
            writeln!(stdout)?;
            stdout.flush()?;
            continue;
        }
        if line == "list" || line == "list for-push" {
            handle_list(&env, &mut stdout)?;
            continue;
        }
        if let Some(args) = line.strip_prefix("fetch ") {
            // Collect this fetch and any subsequent fetch lines until blank.
            let mut wants: Vec<(String, String)> = vec![split_fetch(args)?];
            loop {
                input.clear();
                let n = stdin.read_line(&mut input)?;
                if n == 0 {
                    break;
                }
                let line = input.trim_end_matches('\n');
                if line.is_empty() {
                    break;
                }
                let args = line
                    .strip_prefix("fetch ")
                    .ok_or_else(|| anyhow!("expected fetch line, got {line:?}"))?;
                wants.push(split_fetch(args)?);
            }
            handle_fetch(&env, &wants, &mut stdout)?;
            continue;
        }
        if let Some(args) = line.strip_prefix("push ") {
            let mut pushes: Vec<String> = vec![args.to_string()];
            loop {
                input.clear();
                let n = stdin.read_line(&mut input)?;
                if n == 0 {
                    break;
                }
                let line = input.trim_end_matches('\n');
                if line.is_empty() {
                    break;
                }
                let args = line
                    .strip_prefix("push ")
                    .ok_or_else(|| anyhow!("expected push line, got {line:?}"))?;
                pushes.push(args.to_string());
            }
            handle_push(&env, &pushes, &mut stdout)?;
            continue;
        }

        bail!("unknown remote helper command: {line:?}");
    }
}

fn split_fetch(args: &str) -> Result<(String, String)> {
    let mut parts = args.splitn(2, ' ');
    let sha = parts.next().ok_or_else(|| anyhow!("fetch missing sha"))?;
    let name = parts.next().ok_or_else(|| anyhow!("fetch missing name"))?;
    Ok((sha.to_string(), name.to_string()))
}

struct HelperEnv {
    contract_id: ContractInstanceId,
    ws_url: String,
    git_dir: PathBuf,
    identity_path: PathBuf,
    repo_wasm_path: Option<PathBuf>,
    pack_wasm_path: Option<PathBuf>,
}

impl HelperEnv {
    fn from_env(contract_id: ContractInstanceId) -> Result<Self> {
        let ws_url =
            std::env::var("FREENET_GIT_WS_URL").unwrap_or_else(|_| DEFAULT_WS_URL.to_string());
        let git_dir = PathBuf::from(std::env::var("GIT_DIR").unwrap_or_else(|_| ".git".into()));
        let identity_path = std::env::var("FREENET_GIT_IDENTITY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_bundle_path());
        let repo_wasm_path = std::env::var("FREENET_GIT_REPO_WASM")
            .ok()
            .map(PathBuf::from);
        let pack_wasm_path = std::env::var("FREENET_GIT_PACK_WASM")
            .ok()
            .map(PathBuf::from);
        Ok(Self {
            contract_id,
            ws_url,
            git_dir,
            identity_path,
            repo_wasm_path,
            pack_wasm_path,
        })
    }
}

fn handle_list<W: Write>(env: &HelperEnv, out: &mut W) -> Result<()> {
    let runtime = build_runtime()?;
    let state = runtime.block_on(async {
        let mut api = wsclient::connect(&env.ws_url).await?;
        let bytes = wsclient::get_state(&mut api, env.contract_id, false, WS_TIMEOUT).await?;
        Ok::<_, anyhow::Error>(RepoState::from_bytes(&bytes)?)
    })?;

    // Emit refs.
    for (name, entry) in &state.refs {
        let hex = hex::encode(entry.target);
        writeln!(out, "{hex} {name}")?;
    }
    // Emit HEAD as a symref pointer if default_branch is set.
    if let Some(default) = &state.default_branch {
        writeln!(out, "@{} HEAD", default.value)?;
    }
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn handle_fetch<W: Write>(env: &HelperEnv, wants: &[(String, String)], out: &mut W) -> Result<()> {
    let pack_wasm_path = env
        .pack_wasm_path
        .as_ref()
        .ok_or_else(|| anyhow!("FREENET_GIT_PACK_WASM not set — required to GET pack contracts"))?;
    let pack_wasm = std::fs::read(pack_wasm_path)
        .with_context(|| format!("read pack-contract wasm from {}", pack_wasm_path.display()))?;

    let runtime = build_runtime()?;
    runtime.block_on(async {
        let mut api = wsclient::connect(&env.ws_url).await?;

        let state_bytes = wsclient::get_state(&mut api, env.contract_id, false, WS_TIMEOUT).await?;
        let state = RepoState::from_bytes(&state_bytes)?;

        // Phase 1.0: fetch every SinglePack bundle referenced in
        // object_index. The git index-pack step below will simply ignore
        // packs that contain no objects we need, so this is correct
        // (just suboptimal).
        let mut single_packs: Vec<[u8; 32]> = Vec::new();
        let mut chunked_skipped = 0usize;
        for (_id, record) in &state.object_index {
            match &record.bundle {
                ObjectBundle::SinglePack { pack_hash, .. } => single_packs.push(*pack_hash),
                ObjectBundle::ChunkedPack { .. } => chunked_skipped += 1,
            }
        }
        if chunked_skipped > 0 {
            eprintln!(
                "warning: {chunked_skipped} ChunkedPack bundle(s) skipped — Phase 1.0 \
                 git-remote-freenet only consumes SinglePack. Some refs may not be \
                 fully fetched.",
            );
        }

        let pack_dir = env.git_dir.join("objects").join("pack");
        std::fs::create_dir_all(&pack_dir)?;

        for hash in &single_packs {
            let pack_bytes = wsclient::get_pack(&mut api, &pack_wasm, *hash, WS_TIMEOUT).await?;
            // Re-verify content addressing locally — the contract did
            // it on the network side but we don't trust the path
            // between here and there.
            let actual = *blake3::hash(&pack_bytes).as_bytes();
            if actual != *hash {
                bail!(
                    "pack content hash mismatch: got {} expected {}",
                    hex::encode(actual),
                    hex::encode(hash),
                );
            }
            install_pack(&env.git_dir, &pack_bytes)?;
        }

        let _ = wants;
        Ok::<_, anyhow::Error>(())
    })?;

    // Empty line: success.
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn install_pack(git_dir: &std::path::Path, pack_bytes: &[u8]) -> Result<()> {
    // Hand the pack to git index-pack via stdin so it computes the
    // index and renames the files into place atomically.
    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .arg("index-pack")
        .arg("--stdin")
        .arg("--keep")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn git index-pack")?;
    {
        let mut stdin = child.stdin.take().expect("piped");
        stdin.write_all(pack_bytes)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("git index-pack failed: {}", out.status);
    }
    Ok(())
}

fn handle_push<W: Write>(env: &HelperEnv, pushes: &[String], out: &mut W) -> Result<()> {
    let repo_wasm_path = env.repo_wasm_path.as_ref().ok_or_else(|| {
        anyhow!("FREENET_GIT_REPO_WASM not set — required for sign-domain key + UPDATE")
    })?;
    let pack_wasm_path = env.pack_wasm_path.as_ref().ok_or_else(|| {
        anyhow!("FREENET_GIT_PACK_WASM not set — required to PUT new pack contracts")
    })?;
    let _repo_wasm = std::fs::read(repo_wasm_path)
        .with_context(|| format!("read repo-contract wasm from {}", repo_wasm_path.display()))?;
    let pack_wasm = std::fs::read(pack_wasm_path)
        .with_context(|| format!("read pack-contract wasm from {}", pack_wasm_path.display()))?;

    // Decrypt identity once (asks for the passphrase via FREENET_GIT_PASSPHRASE
    // or, in interactive use, via a separate `freenet-git` invocation; we
    // don't prompt from inside the helper because git owns stdin/stdout).
    let pw = std::env::var("FREENET_GIT_PASSPHRASE").map_err(|_| {
        anyhow!(
            "FREENET_GIT_PASSPHRASE must be set when using git push freenet:... — \
             the helper cannot prompt because git owns stdin/stdout"
        )
    })?;
    let bundle = read_bundle(&env.identity_path, &pw)
        .with_context(|| format!("decrypt identity bundle at {}", env.identity_path.display()))?;
    let signing = bundle.signing_key()?;

    let runtime = build_runtime()?;
    let result = runtime.block_on(async {
        let mut api = wsclient::connect(&env.ws_url).await?;

        let state_bytes = wsclient::get_state(&mut api, env.contract_id, false, WS_TIMEOUT).await?;
        let state = RepoState::from_bytes(&state_bytes)?;

        // Recover RepoParams by reading the state's owner from the
        // bundle (the public key) and the repo_nonce from the bundle's
        // registry. We expect the URL the user is pushing to to be
        // present in the registry; if not, we fall back to scanning.
        let repo_url = url::format(&env.contract_id);
        let registry_entry = bundle
            .repos
            .iter()
            .find(|r| r.last_known_url == repo_url)
            .ok_or_else(|| {
                anyhow!(
                    "no entry for {repo_url} in identity bundle registry — was this \
                     repo created with this identity?",
                )
            })?;
        let repo_nonce: [u8; 16] = registry_entry
            .repo_nonce
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("registry repo_nonce is wrong length"))?;
        let params = freenet_git_types::RepoParams {
            owner: signing.verifying_key().to_bytes(),
            repo_nonce,
        };

        let mut delta = RepoState::default();
        let mut ok_lines: Vec<String> = Vec::new();
        let mut error_lines: Vec<String> = Vec::new();

        for spec in pushes {
            // git sends `<src>:<dst>`; src may have a leading '+' for force.
            let (src, dst) = parse_push_spec(spec)?;
            if src.is_empty() {
                error_lines.push(format!("error {dst} delete-ref not supported in Phase 1.0"));
                continue;
            }
            let new_target = git_resolve_ref(&env.git_dir, &src)?;

            // Determine "have" = current target if any, so pack-objects
            // can produce a thin pack from <have>..<new_target>.
            let prev = state.refs.get(&dst).map(|e| hex::encode(e.target));
            let pack_bytes = match build_pack(&env.git_dir, prev.as_deref(), &new_target) {
                Ok(b) => b,
                Err(e) => {
                    error_lines.push(format!("error {dst} {e}"));
                    continue;
                }
            };

            // PUT the pack contract.
            let pack_key =
                wsclient::put_pack(&mut api, pack_wasm.clone(), pack_bytes.clone(), WS_TIMEOUT)
                    .await?;
            let pack_hash = *blake3::hash(&pack_bytes).as_bytes();
            let pack_id_check = pack_contract_id(&pack_wasm, &pack_bytes);
            debug_assert_eq!(pack_key.id(), &pack_id_check);

            // Sign the bundle-add record.
            let bundle_obj = ObjectBundle::SinglePack {
                pack_hash,
                size_bytes: pack_bytes.len() as u64,
            };
            let bundle_id = bundle_obj.id();
            let record = sign_bundle_record(&params, &signing, bundle_obj, 0);
            delta.object_index.insert(bundle_id, record);

            // Sign the ref update.
            let new_seq = state.refs.get(&dst).map(|e| e.update_seq).unwrap_or(0) + 1;
            let target_arr: CommitHash = parse_sha1(&new_target)?;
            let entry = sign_ref_entry(&params, &signing, &dst, target_arr, new_seq, 0);
            delta.refs.insert(dst.clone(), entry);
            ok_lines.push(format!("ok {dst}"));
        }

        if delta.object_index.is_empty() && delta.refs.is_empty() {
            return Ok::<_, anyhow::Error>((ok_lines, error_lines));
        }

        // Local sanity: validate the merged state would pass before
        // committing it to the network.
        let merged = ts_update_state(&params, &state, &delta)
            .map_err(|e| anyhow!("local update_state rejected our delta: {e}"))?;
        let _ = merged;

        // UPDATE the repo contract with the signed delta.
        wsclient::update_state(
            &mut api,
            env.contract_id,
            bincode::serialize(&delta)?,
            WS_TIMEOUT,
        )
        .await?;

        Ok::<_, anyhow::Error>((ok_lines, error_lines))
    })?;

    let (ok_lines, error_lines) = result;
    for line in &ok_lines {
        writeln!(out, "{line}")?;
    }
    for line in &error_lines {
        writeln!(out, "{line}")?;
    }
    writeln!(out)?;
    out.flush()?;

    Ok(())
}

fn parse_push_spec(spec: &str) -> Result<(String, String)> {
    let (force_stripped, _force) = match spec.strip_prefix('+') {
        Some(rest) => (rest, true),
        None => (spec, false),
    };
    let mut parts = force_stripped.splitn(2, ':');
    let src = parts.next().unwrap_or("").to_string();
    let dst = parts
        .next()
        .ok_or_else(|| anyhow!("push spec missing destination"))?
        .to_string();
    Ok((src, dst))
}

fn git_resolve_ref(git_dir: &std::path::Path, refname: &str) -> Result<String> {
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["rev-parse", "--verify", refname])
        .output()
        .context("spawn git rev-parse")?;
    if !out.status.success() {
        bail!(
            "git rev-parse {refname} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn build_pack(git_dir: &std::path::Path, have: Option<&str>, want: &str) -> Result<Vec<u8>> {
    // We pipe the rev-list into pack-objects --stdin --revs --thin so
    // git decides which objects need to be in the pack.
    let mut rev_list = Command::new("git");
    rev_list.arg("--git-dir").arg(git_dir);
    rev_list.args(["rev-list", "--objects", want]);
    if let Some(h) = have {
        rev_list.arg(format!("^{h}"));
    }
    let rev_list_out = rev_list
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .context("spawn git rev-list")?;
    if !rev_list_out.status.success() {
        bail!("git rev-list failed: {}", rev_list_out.status);
    }

    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["pack-objects", "--stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn git pack-objects")?;
    {
        let mut stdin = child.stdin.take().expect("piped");
        // Strip the path part: pack-objects only wants the SHA on each line.
        for line in BufReader::new(rev_list_out.stdout.as_slice()).lines() {
            let line = line?;
            let sha = line.split(' ').next().unwrap_or("");
            if !sha.is_empty() {
                writeln!(stdin, "{sha}")?;
            }
        }
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("git pack-objects failed: {}", out.status);
    }
    Ok(out.stdout)
}

fn parse_sha1(hex_str: &str) -> Result<CommitHash> {
    let bytes = hex::decode(hex_str).context("decode commit sha")?;
    let arr: [u8; 20] = bytes.as_slice().try_into().map_err(|_| {
        anyhow!(
            "commit sha must be 20 bytes (got {} hex chars)",
            hex_str.len()
        )
    })?;
    Ok(arr)
}

fn build_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}
