# Ayva Linux (Focus by Rj)

> Hardened, native **Fedora GNOME 44+ (Wayland)** note-taking and smart task management application built in **Rust** and **Libadwaita / GTK 4**.

Derived from the original Android application [Ayva (`Nrajesh0/Ayva`)](https://github.com/Nrajesh0/Ayva), re-engineered from the ground up for maximum desktop security, memory safety, and visual fidelity.

---

## Highlights

* **Notesnook-Grade Security Architecture**:
  * **Memory Hardening**: Kernel-level `prctl(PR_SET_DUMPABLE, 0)` blocks `systemd-coredump` memory dumps on crash and denies unprivileged `ptrace` inspection.
  * **Zero Swap Leakage**: Sensitive cryptographic buffers are locked into physical RAM via `libc::mlock()` to prevent swapping to disk or Fedora's `zram-swap`.
  * **Memory Zeroization**: Strict `ZeroizeOnDrop` lifecycle wipes key buffers immediately upon deallocation.
  * **Envelope Encryption**: Per-note **XChaCha20-Poly1305** envelope encryption with 192-bit nonces.
  * **Memory-Hard KDF**: Desktop-tuned **Argon2id** (`m=64MB`, `t=3`, `p=4`, 32-byte salt).
  * **Domain Separation**: RFC 5869 HKDF derives separated keys for database, payload envelope, and HMAC signing.
  * **BIP-39 Emergency Recovery**: 12-word mnemonic phrase backup.
  * **Sandboxed Execution**: Networkless Flatpak (`--unshare=network`, `--socket=wayland`) ensures absolute immunity against remote data exfiltration.
* **1:1 Ayva Visual Fidelity**:
  * **Midnight Obsidian Glass**: Window background `#0E1116`, card surface `#151921`, glass borders `rgba(255, 255, 255, 0.08)`.
  * **4 Accent Palettes**: Calm Sage (`#6E9987`), Arctic Slate (`#6B8EA8`), Dusk Heather (`#8A82A5`), and Dusty Rose (`#B57E82`).
  * **9 Note Category Tints**: Distinct ambient colors for Study, Notes, Groceries, Ideas, and more.
* **Smart Natural Language Tasks**:
  * Real-time NLP date and recurrence parser ported from Ayva's `SmartDateParser.kt`.
  * Extracts tasks, dates, recurring rules, tags (`#tag`), and priorities (`!high`) on the fly.
* **Rich Block-Based Notes**:
  * Structured Notesnook block model: rich text (Pango spans), tables, syntax-highlighted code (`GtkSourceView 5`), callout boxes, and KaTeX math formulas.

---

## Project Structure

```text
ayva-linux/
├── Cargo.toml                  # Rust dependencies & configuration
├── PROGRESS.md                 # Batch-by-batch roadmap & verification log
├── src/
│   ├── main.rs                 # Hardened runtime entry point
│   ├── lib.rs                  # Library crate root
│   ├── crypto/                 # Memory locking, KDF, envelopes, BIP-39
│   ├── db/                     # SQLCipher encrypted persistence
│   ├── parser/                 # Smart NLP task & date parser
│   └── ui/                     # Libadwaita windows, cards, editors, themes
└── tests/
    └── security_tests.rs       # Kernel isolation & memory zeroization tests
```

---

## Building & Testing

### Prerequisites
* Rust 1.90+ (`rustc`, `cargo`)
* GCC / C toolchain
* GTK 4 & Libadwaita development libraries

### Running Tests
```bash
cargo test
```

### Running the App
```bash
cargo run
```

---

## License

All rights reserved © 2026 Focus by Rj / Rajesh (`github.com/Nrajesh0`).
