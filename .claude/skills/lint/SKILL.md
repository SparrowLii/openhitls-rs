---
name: lint
description: Run clippy and format checks. Use when the user asks to lint, check code quality, or verify clippy compliance.
allowed-tools: Bash(RUSTFLAGS=*), Bash(cargo fmt:*), Bash(cargo clippy:*)
---

Run clippy and rustfmt checks for the openHiTLS-rs workspace.

## Behavior

Run both checks sequentially:

1. **Clippy** (zero warnings required):
   ```
   RUSTFLAGS="-D warnings" cargo clippy --workspace --all-features --all-targets
   ```

2. **Format check**:
   ```
   cargo fmt --all -- --check
   ```

3. Report results:
   - If both pass: confirm clean status
   - If clippy fails: list all warnings/errors with file locations
   - If fmt fails: list files that need formatting and suggest running `cargo fmt --all`
