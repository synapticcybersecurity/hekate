use clap::{Parser, Subcommand};

mod api;
mod commands;
mod crypto;
#[cfg(unix)]
mod daemon;
mod manifest;
mod org_cipher_manifest;
mod org_sync;
mod policies;
mod prompt;
mod state;
mod totp;

/// hekate — command-line client.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Register a new account on a hekate server.
    Register(commands::register::Args),
    /// Log in to a hekate server. Saves tokens locally.
    Login(commands::login::Args),
    /// Show local session state (server, user, token expiry).
    Status,
    /// Clear local session state.
    Logout,
    /// List vault items (decrypted names).
    List(commands::list::Args),
    /// Show a single decrypted vault item.
    Show(commands::show::Args),
    /// Create a new vault item.
    Add(commands::add::Args),
    /// Edit an existing vault item.
    Edit(commands::edit::Args),
    /// Move a cipher to trash (soft delete).
    Delete(commands::delete::Args),
    /// Restore a cipher from trash.
    Restore(commands::restore::Args),
    /// Permanently delete a cipher (writes a tombstone).
    Purge(commands::purge::Args),
    /// Pull deltas from the server and report what changed.
    Sync(commands::sync::Args),
    /// Generate a cryptographically random password.
    Generate(commands::generate::Args),
    /// Subscribe to /push/v1/stream and print events as they arrive.
    Watch(commands::watch::Args),
    /// Manage Personal Access Tokens.
    Token(commands::token::Args),
    /// Manage outbound webhook subscriptions.
    Webhook(commands::webhook::Args),
    /// Start a per-user daemon that caches the unwrapped account key.
    /// Subsequent commands skip the master-password prompt + Argon2id
    /// derivation. Unix-only.
    Unlock(commands::unlock::Args),
    /// Tell the unlock daemon to wipe its key and exit.
    Lock,
    /// Account lifecycle: change-password, delete, export.
    Account(commands::account::Args),
    /// CLI-local preferences (e.g. strict-manifest mode for `sync`).
    Config(commands::config::Args),
    /// SSH agent backed by stored ssh-key ciphers (Ed25519 only). Unix-only.
    SshAgent(commands::ssh_agent::Args),
    /// TOFU pubkey pinning — `hekate peer {fetch,pins,fingerprint,verify,unpin}`.
    Peer(commands::peer::Args),
    /// Organizations — `hekate org {create,list}` (M4.0); invite/accept land in M4.1+.
    Org(commands::org::Args),
    /// Move a personal cipher into an org (M4.5a). Re-keys client-side
    /// under the org symmetric key.
    MoveToOrg(commands::move_cipher::MoveToOrgArgs),
    /// Move an org-owned cipher into your personal vault (M4.5a).
    /// Re-keys client-side under your account_key.
    MoveToPersonal(commands::move_cipher::MoveToPersonalArgs),
    /// Attachments — `hekate attach {upload, download, list, delete}` (M2.24).
    Attach(commands::attach::Args),
    /// Sends — ephemeral encrypted text/file shares (M2.25).
    /// `hekate send {create-text, list, delete, disable, enable, open}`.
    Send(commands::send::Args),
    /// Import a vault from another password manager (M2.27).
    /// `hekate import bitwarden <file>` is the first format; 1Password
    /// / KeePass / LastPass land later.
    Import(commands::import::Args),
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Register(args) => commands::register::run(args),
        Command::Login(args) => commands::login::run(args),
        Command::Status => commands::status::run(),
        Command::Logout => commands::logout::run(),
        Command::List(args) => commands::list::run(args),
        Command::Show(args) => commands::show::run(args),
        Command::Add(args) => commands::add::run(args),
        Command::Edit(args) => commands::edit::run(args),
        Command::Delete(args) => commands::delete::run(args),
        Command::Restore(args) => commands::restore::run(args),
        Command::Purge(args) => commands::purge::run(args),
        Command::Sync(args) => commands::sync::run(args),
        Command::Generate(args) => commands::generate::run(args),
        Command::Watch(args) => commands::watch::run(args),
        Command::Token(args) => commands::token::run(args),
        Command::Webhook(args) => commands::webhook::run(args),
        Command::Unlock(args) => commands::unlock::run(args),
        Command::Lock => commands::lock::run(),
        Command::Account(args) => commands::account::run(args),
        Command::Config(args) => commands::config::run(args),
        Command::SshAgent(args) => commands::ssh_agent::run(args),
        Command::Peer(args) => commands::peer::run(args),
        Command::Org(args) => commands::org::run(args),
        Command::MoveToOrg(args) => commands::move_cipher::run_to_org(args),
        Command::MoveToPersonal(args) => commands::move_cipher::run_to_personal(args),
        Command::Attach(args) => commands::attach::run(args),
        Command::Send(args) => commands::send::run(args),
        Command::Import(args) => commands::import::run(args),
    }
}
