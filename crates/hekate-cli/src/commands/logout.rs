use anyhow::Result;

use crate::state;

pub fn run() -> Result<()> {
    if state::delete()? {
        println!(
            "✓ Cleared local state at {}",
            state::state_path()?.display()
        );
    } else {
        println!("(no local state to clear)");
    }
    Ok(())
}
