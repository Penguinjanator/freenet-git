//! `freenet-git` companion CLI. Phase 1.0 commands:
//!
//! - `init-identity` / `whoami` / `export-identity` / `import-identity`
//!   — work today (offline; just bundle management).
//! - `create` — derives the repo contract id locally, builds the initial
//!   signed state, and prints the URL. Network publish is gated on the
//!   `--publish-to <ws-url>` flag (TODO: implement WS API call).
//! - `info` — prints the contents of a repo's signed state (TODO: needs
//!   WS API GET).
//! - `subscribe`, `subscriptions`, `status`, `rename`, `rescue` — coming
//!   in follow-up commits once the WS API plumbing lands.

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use freenet_git_cli::ids::{fresh_repo_nonce, repo_contract_id};
use freenet_git_cli::state_init::initial_repo_state;
use freenet_git_cli::url;
use freenet_git_cli::wsclient::{self, DEFAULT_WS_URL};
use freenet_git_identity::{
    default_bundle_path, read_bundle, seal, write_bundle, DecryptedBundle, RepoRegistryEntry,
};
use freenet_git_types::RepoParams;

#[derive(Debug, Parser)]
#[command(
    name = "freenet-git",
    version,
    about = "Companion CLI for hosting and consuming git repositories on Freenet"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Path to the identity bundle. Defaults to
    /// `$XDG_CONFIG_HOME/freenet/git-identity.bundle` (or `~/.config/...`).
    #[arg(long, env = "FREENET_GIT_IDENTITY", global = true)]
    identity_path: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Generate a fresh ed25519 identity and write it to a passphrase-
    /// encrypted bundle on disk.
    InitIdentity {
        /// Display name to embed in the bundle.
        #[arg(long)]
        name: String,
        /// Email to embed in the bundle.
        #[arg(long)]
        email: String,
    },
    /// Print the identity stored in the bundle.
    Whoami,
    /// Re-encrypt the bundle to the given output path. Useful for moving
    /// the identity to a new machine.
    ExportIdentity {
        /// Path to write the exported bundle.
        out: PathBuf,
    },
    /// Replace the local bundle with the one at `from` (decrypted with the
    /// supplied passphrase, re-encrypted in place).
    ImportIdentity {
        /// Path to read the source bundle.
        from: PathBuf,
    },
    /// Derive the contract URL for a brand-new repo, build its initial
    /// signed state, and publish it to a local Freenet node.
    Create {
        /// Display name for the repo.
        #[arg(long)]
        name: String,
        /// Description.
        #[arg(long, default_value = "")]
        description: String,
        /// Default branch.
        #[arg(long, default_value = "refs/heads/main")]
        default_branch: String,
        /// Path to the compiled repo-contract WASM.
        #[arg(long)]
        repo_wasm: PathBuf,
        /// WebSocket URL of a local Freenet node. Defaults to the
        /// stdlib's standard endpoint
        /// (`ws://127.0.0.1:50509/v1/contract/command?encodingProtocol=native`).
        /// Pass `--no-publish` to skip the network call and just print
        /// the would-be URL.
        #[arg(long)]
        publish_to: Option<String>,
        /// Skip the network PUT entirely. Useful for `--dry-run`-style
        /// previews or for hand-off to `fdev publish`.
        #[arg(long, conflicts_with = "publish_to")]
        no_publish: bool,
        /// Override the default 180-second confirmation timeout. First-PUT
        /// against a busy gateway can take ~60s for the host to relay the
        /// confirmation; 180s gives 3x headroom.
        #[arg(long, default_value = "180")]
        publish_timeout_secs: u64,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:?}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let bundle_path = cli.identity_path.unwrap_or_else(default_bundle_path);
    match cli.cmd {
        Cmd::InitIdentity { name, email } => init_identity(&bundle_path, name, email),
        Cmd::Whoami => whoami(&bundle_path),
        Cmd::ExportIdentity { out } => export_identity(&bundle_path, &out),
        Cmd::ImportIdentity { from } => import_identity(&bundle_path, &from),
        Cmd::Create {
            name,
            description,
            default_branch,
            repo_wasm,
            publish_to,
            no_publish,
            publish_timeout_secs,
        } => create_repo(
            &bundle_path,
            &name,
            &description,
            &default_branch,
            &repo_wasm,
            publish_to.as_deref(),
            no_publish,
            Duration::from_secs(publish_timeout_secs),
        ),
    }
}

fn init_identity(path: &std::path::Path, name: String, email: String) -> Result<()> {
    if path.exists() {
        bail!(
            "identity bundle already exists at {} -- refusing to overwrite. \
             Move or delete it first if you really want a new identity.",
            path.display()
        );
    }

    let pw = prompt_passphrase_with_confirm("Passphrase for new identity")?;
    let bundle = DecryptedBundle::new(name, email);
    write_bundle(&bundle, &pw, path).with_context(|| format!("write {}", path.display()))?;
    println!("Generated ed25519 keypair.");
    println!("Public key: {}", bundle.id_string());
    println!("Bundle written to: {}", path.display());
    Ok(())
}

fn whoami(path: &std::path::Path) -> Result<()> {
    let bundle = open_bundle_with_prompt(path)?;
    println!("{} <{}>", bundle.name, bundle.email);
    println!("{}", bundle.id_string());
    if !bundle.repos.is_empty() {
        println!();
        println!("Repos in registry:");
        for r in &bundle.repos {
            println!("  {} -> {}", r.display_name, r.last_known_url);
        }
    }
    Ok(())
}

fn export_identity(path: &std::path::Path, out: &std::path::Path) -> Result<()> {
    let bundle = open_bundle_with_prompt(path)?;
    let pw = prompt_passphrase_with_confirm("Passphrase for exported bundle")?;
    let bytes = seal(&bundle, &pw)?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out, bytes)?;
    println!("Wrote bundle to {}", out.display());
    Ok(())
}

fn import_identity(local_path: &std::path::Path, from: &std::path::Path) -> Result<()> {
    let pw_in = prompt_passphrase("Passphrase for source bundle")?;
    let bundle = read_bundle(from, &pw_in)
        .with_context(|| format!("read source bundle at {}", from.display()))?;
    if local_path.exists() {
        bail!(
            "local identity bundle already exists at {} -- refusing to overwrite",
            local_path.display()
        );
    }
    let pw_out = prompt_passphrase_with_confirm("Passphrase for new local bundle")?;
    write_bundle(&bundle, &pw_out, local_path)?;
    println!(
        "Imported identity {} into {}",
        bundle.id_string(),
        local_path.display()
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_repo(
    bundle_path: &std::path::Path,
    name: &str,
    description: &str,
    default_branch: &str,
    repo_wasm_path: &std::path::Path,
    publish_to: Option<&str>,
    no_publish: bool,
    publish_timeout: Duration,
) -> Result<()> {
    let bundle = open_bundle_with_prompt(bundle_path)?;
    let signing = bundle.signing_key()?;
    let owner = signing.verifying_key().to_bytes();

    let repo_wasm = std::fs::read(repo_wasm_path)
        .with_context(|| format!("read repo-contract wasm from {}", repo_wasm_path.display()))?;

    let nonce = fresh_repo_nonce();
    let params = RepoParams {
        owner,
        repo_nonce: nonce,
    };
    let initial_state = initial_repo_state(&params, &signing, name, description, default_branch);

    let contract_id = repo_contract_id(&repo_wasm, &params);
    let repo_url = url::format(&contract_id);

    let git_url = url::format_git_url(&contract_id);
    println!("Repo prepared:");
    println!("  Name:        {name}");
    println!("  Description: {description}");
    println!("  Default ref: {default_branch}");
    println!("  Owner:       {}", bundle.id_string());
    println!("  URL:         {repo_url}");
    println!("  git URL:     {git_url}");
    println!();
    println!(
        "Initial signed state size: {} bytes",
        initial_state.to_bytes().len()
    );

    if no_publish {
        // Hand-off mode: write artefacts for fdev publish.
        let parameters_path = format!("/tmp/freenet-git-params-{}.bin", nonce_hex(&nonce));
        let state_path = format!("/tmp/freenet-git-state-{}.bin", nonce_hex(&nonce));
        std::fs::write(&parameters_path, params.to_bytes())?;
        std::fs::write(&state_path, initial_state.to_bytes())?;
        println!();
        println!("--no-publish: skipped network PUT.");
        println!("  parameters: {parameters_path}");
        println!("  state:      {state_path}");
        println!();
        println!("To publish manually, e.g. with fdev:");
        println!(
            "  fdev publish --code {} --parameters {parameters_path} contract --state {state_path}",
            repo_wasm_path.display()
        );
        return register_in_bundle(bundle, bundle_path, &nonce, &repo_url, name);
    }

    let ws_url = publish_to.unwrap_or(DEFAULT_WS_URL).to_string();
    println!();
    println!("Publishing to {ws_url} ...");

    let key = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?
        .block_on(async {
            let mut api = wsclient::connect(&ws_url).await?;
            wsclient::put_contract(
                &mut api,
                repo_wasm,
                params.to_bytes(),
                initial_state.to_bytes(),
                publish_timeout,
            )
            .await
        })
        .with_context(|| format!("PUT to {ws_url}"))?;

    println!("PUT confirmed by host. Contract key: {}", key.id());

    register_in_bundle(bundle, bundle_path, &nonce, &repo_url, name)
}

fn register_in_bundle(
    bundle: DecryptedBundle,
    bundle_path: &std::path::Path,
    nonce: &[u8; 16],
    repo_url: &str,
    name: &str,
) -> Result<()> {
    let mut bundle_with_repo = bundle;
    bundle_with_repo.repos.push(RepoRegistryEntry {
        repo_nonce: nonce.to_vec(),
        last_known_url: repo_url.to_string(),
        display_name: name.to_string(),
    });
    let pw = prompt_passphrase("Passphrase to update bundle (registry entry)")?;
    write_bundle(&bundle_with_repo, &pw, bundle_path)?;
    println!();
    println!("Registered repo in identity bundle.");
    Ok(())
}

fn open_bundle_with_prompt(path: &std::path::Path) -> Result<DecryptedBundle> {
    if !path.exists() {
        bail!(
            "no identity bundle at {} -- run `freenet-git init-identity` first",
            path.display()
        );
    }
    let pw = prompt_passphrase("Passphrase")?;
    let bundle =
        read_bundle(path, &pw).with_context(|| format!("decrypt bundle at {}", path.display()))?;
    Ok(bundle)
}

/// Read a passphrase. For interactive use, prompts on the controlling
/// TTY via `rpassword`. For non-interactive use (CI, tests, scripts),
/// `FREENET_GIT_PASSPHRASE` short-circuits the prompt — required because
/// rpassword fails outright when no TTY is attached.
fn prompt_passphrase(prompt: &str) -> Result<String> {
    if let Ok(pw) = std::env::var("FREENET_GIT_PASSPHRASE") {
        if pw.is_empty() {
            bail!("empty FREENET_GIT_PASSPHRASE");
        }
        return Ok(pw);
    }
    let pw = rpassword::prompt_password(format!("{prompt}: "))?;
    if pw.is_empty() {
        bail!("empty passphrase");
    }
    Ok(pw)
}

fn prompt_passphrase_with_confirm(prompt: &str) -> Result<String> {
    // Single env var fills both prompts in non-interactive mode.
    let pw = prompt_passphrase(prompt)?;
    if std::env::var("FREENET_GIT_PASSPHRASE").is_ok() {
        return Ok(pw);
    }
    let confirm = rpassword::prompt_password("Confirm passphrase: ")?;
    if pw != confirm {
        bail!("passphrases did not match");
    }
    Ok(pw)
}

fn nonce_hex(nonce: &[u8; 16]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(32);
    for b in nonce {
        let _ = write!(s, "{b:02x}");
    }
    s
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
