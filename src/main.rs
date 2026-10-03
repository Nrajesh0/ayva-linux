/*
 * Ayva Notes & Smart Tasks - Fedora GNOME 44+
 * Entry Point and Hardened Runtime Initialization
 */

pub mod crypto;

fn main() {
    println!("Initializing Ayva for Fedora GNOME 44+...");

    // Step 1: Harden process against core dumping & unprivileged ptrace memory scraping
    match crypto::memlock::disable_core_dumps() {
        Ok(_) => println!("[Security] PR_SET_DUMPABLE set to 0 (Core dumps disabled, ptrace blocked)"),
        Err(e) => eprintln!("[Security Warning] Failed to set PR_SET_DUMPABLE: {}", e),
    }

    match crypto::memlock::is_dumpable() {
        Ok(dumpable) => {
            println!("[Security] Process dumpable flag: {}", if dumpable { "ENABLED (Insecure)" } else { "DISABLED (Hardened)" });
        }
        Err(e) => eprintln!("[Security Warning] Check dumpable failed: {}", e),
    }

    println!("Ayva runtime initialization complete.");
}
