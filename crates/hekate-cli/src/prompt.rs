//! Password input. Uses `rpassword` (echo suppression on /dev/tty) when
//! interactive; falls back to plain stdin when not, so the CLI is
//! scriptable for CI and smoke tests.

use std::io::{self, BufRead, IsTerminal, Write};

use anyhow::Result;
use zeroize::{Zeroize, Zeroizing};

/// Read a secret (master password, KDBX/export passphrase) without echo
/// when interactive. Returns it in a `Zeroizing<String>` so the plaintext
/// is wiped from memory on drop (E3, issue #18) — it's the crown-jewel
/// secret and must not linger after the master key is derived.
pub fn password(prompt: &str) -> Result<Zeroizing<String>> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    if io::stdin().is_terminal() {
        Ok(Zeroizing::new(rpassword::read_password()?))
    } else {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        let trimmed = Zeroizing::new(
            line.trim_end_matches('\n')
                .trim_end_matches('\r')
                .to_string(),
        );
        // Wipe the intermediate read buffer; only the Zeroizing copy survives.
        line.zeroize();
        Ok(trimmed)
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
