---
name: security-review
description: Review code for cryptographic security patterns. Use when reviewing crypto code, checking for security violations, or auditing sensitive modules.
argument-hint: "[file-or-crate]"
context: fork
agent: Explore
allowed-tools: Read, Grep, Glob
---

Review $ARGUMENTS for cryptographic security patterns in the openHiTLS-rs codebase.

Use ultrathink to carefully reason about each security check.

## Security Checklist

### 1. Zeroize on Drop
All types holding secret material MUST have `#[derive(Zeroize)]` and `#[zeroize(drop)]`:
- Private keys, session keys, pre-master secrets
- Intermediate hash states used in key derivation
- DRBG internal state (V, K, seed)
- Password/passphrase buffers

Search for: struct fields named `key`, `secret`, `private`, `seed`, `entropy`, `pms`, `master_secret`
Verify: each has `Zeroize` derive and `zeroize(drop)` attribute

### 2. Constant-Time Comparisons
All cryptographic comparisons MUST use `subtle::ConstantTimeEq`, never `==`:
- MAC verification (HMAC, CMAC, GMAC)
- Signature verification final comparison
- Password/token comparison
- Certificate fingerprint matching

Search for: `== ` adjacent to variables named `tag`, `mac`, `digest`, `hash`, `signature`, `verify`
Flag any direct `==` comparison on cryptographic values

### 3. Unsafe Code Audit
Unsafe code is ONLY allowed in `hitls-bignum` and `hitls-crypto`:
- Check for `unsafe` blocks in other crates
- For allowed crates: verify each unsafe block has a SAFETY comment
- Check for unchecked indexing, pointer casts, transmute

### 4. Error Handling
Library code MUST NOT panic:
- Search for `unwrap()`, `expect()`, `panic!()`, `unreachable!()` in non-test code
- All public APIs must return `Result<T, CryptoError>` or `Result<T, TlsError>`
- Exception: `unreachable!()` in exhaustive match arms is acceptable

### 5. Random Generation
- Must use `getrandom` crate, never `rand`
- Check for `rand::` imports in non-test code
- DRBG seeding must use `get_system_entropy()` or `getrandom`

### 6. Feature Gate Compliance
- Each algorithm module must be behind `#[cfg(feature = "...")]`
- Check that conditional compilation is correct and complete

## Output Format

Report findings as:

| Category | File:Line | Severity | Finding |
|----------|-----------|----------|---------|
| Zeroize | path:42 | HIGH/MED/LOW/OK | Description |

Summarize: X files checked, Y issues found (Z high severity).
