//! `hekate lock` — tells the daemon to wipe its key and exit.

use anyhow::Result;

use crate::daemon;

pub fn run() -> Result<()> {
    if !daemon::client::is_running() {
        println!("(no daemon running)");
        return Ok(());
    }
    daemon::client::shutdown()?;
    println!("✓ Daemon shut down.");
    Ok(())
}
