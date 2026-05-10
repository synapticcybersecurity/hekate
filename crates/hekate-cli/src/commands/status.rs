use anyhow::Result;

use crate::{daemon, state};

pub fn run() -> Result<()> {
    match state::load()? {
        None => {
            println!("Not logged in. Run `hekate login` or `hekate register`.");
            println!("State path: {}", state::state_path()?.display());
        }
        Some(st) => {
            let now = chrono::Utc::now();
            let access_state = match chrono::DateTime::parse_from_rfc3339(&st.tokens.expires_at) {
                Ok(exp) => {
                    if exp <= now {
                        "expired (will refresh on next call)".to_string()
                    } else {
                        let remaining = exp.signed_duration_since(now);
                        format!("valid for {} min", remaining.num_minutes().max(0))
                    }
                }
                Err(_) => "unknown expiry".to_string(),
            };

            println!("Server:        {}", st.server_url);
            println!("User:          {}", st.user.email);
            println!("Access token:  {access_state}");
            println!(
                "Refresh token: present ({} chars)",
                st.tokens.refresh_token.len()
            );
            println!("State path:    {}", state::state_path()?.display());

            #[cfg(unix)]
            print_daemon_status();
        }
    }
    Ok(())
}

#[cfg(unix)]
fn print_daemon_status() {
    if daemon::client::is_running() {
        match daemon::client::status() {
            Ok(s) => println!(
                "Unlock daemon: running (pid {}, {} s remaining)",
                s.pid, s.remaining_secs
            ),
            Err(_) => println!("Unlock daemon: socket present but not responding"),
        }
    } else {
        println!("Unlock daemon: not running (commands will prompt for master password)");
    }
}
