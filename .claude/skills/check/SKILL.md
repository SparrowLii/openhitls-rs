---
name: check
description: Run the full build-test-lint-format pipeline. Use when the user wants a complete verification before committing or after major changes.
allowed-tools: Bash(cargo build:*), Bash(cargo test:*), Bash(RUSTFLAGS=*), Bash(cargo fmt:*), Bash(cargo clippy:*)
---

Run the complete verification pipeline for openHiTLS-rs.

## Behavior

Execute all 4 steps sequentially. Stop and report on the first failure.

### Step 1: Build
```
cargo build --workspace --all-features
```

### Step 2: Test
```
cargo test --workspace --all-features
```
Report pass/fail/ignored counts. Expected: 2585 passed, 40 ignored.

### Step 3: Clippy
```
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-features --all-targets
```
Must produce zero warnings.

### Step 4: Format
```
cargo fmt --all -- --check
```
Must report no formatting differences.

## Output

Provide a summary table:

| Step | Status | Details |
|------|--------|---------|
| Build | PASS/FAIL | ... |
| Test | PASS/FAIL | X passed, Y failed, Z ignored |
| Clippy | PASS/FAIL | N warnings |
| Format | PASS/FAIL | N files need formatting |
