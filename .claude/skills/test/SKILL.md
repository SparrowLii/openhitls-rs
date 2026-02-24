---
name: test
description: Run tests for the workspace or a specific crate. Use when the user asks to run tests, verify changes, or check test counts.
argument-hint: "[crate-name]"
allowed-tools: Bash(cargo test:*)
---

Run tests for the openHiTLS-rs workspace.

## Usage

- `/test` — run full workspace tests
- `/test hitls-crypto` — run tests for a specific crate
- `/test hitls-tls` — run tests for TLS crate

## Behavior

1. If `$ARGUMENTS` is empty, run:
   ```
   cargo test --workspace --all-features
   ```

2. If `$ARGUMENTS` specifies a crate name, run:
   ```
   cargo test -p $ARGUMENTS --all-features
   ```

3. After tests complete, report:
   - Total passed / failed / ignored counts
   - Compare against expected counts from the table below
   - Flag any unexpected failures

## Expected Test Counts

| Crate | Expected Tests | Ignored |
|-------|---------------|---------|
| hitls-crypto | 652 | 31 |
| hitls-tls | 1164 | 0 |
| hitls-pki | 349 | 1 |
| hitls-bignum | 49 | 0 |
| hitls-utils | 53 | 0 |
| hitls-auth | 33 | 0 |
| hitls-cli | 117 | 5 |
| hitls-integration-tests | 125 | 3 |
| **Total workspace** | **2585** | **40** |

If test counts differ from expected, explicitly note the delta and whether it indicates new tests or regressions.
