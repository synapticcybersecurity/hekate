//! Password input. Uses `rpassword` (echo suppression on /dev/tty) when
//! interactive; falls back to plain stdin when not, so the CLI is
//! scriptable for CI and smoke tests.

use std::io::{self, BufRead, IsTerminal, Write};

use anyhow::Result;

pub fn password(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    if io::stdin().is_terminal() {
        Ok(rpassword::read_password()?)
    } else {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        Ok(line
            .trim_end_matches('\n')
            .trim_end_matches('\r')
            .to_string())
    }
}

/// Read a single non-secret line from the user. Used for TOTP codes,
/// recovery codes, and similar inputs where echo suppression would be
/// unhelpful. Trims the trailing newline.
pub fn line(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    let mut buf = String::new();
    io::stdin().lock().read_line(&mut buf)?;
    Ok(buf
        .trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string())
}
