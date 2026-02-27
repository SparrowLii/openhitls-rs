# Performance Comparison: openHiTLS (C) vs openHiTLS-rs (Rust)

> **Date**: 2026-02-27 (full refresh) | **Platform**: Apple M4, macOS 15.4, 10 cores, 16 GB RAM

---

## 1. Executive Summary

Comprehensive benchmarks across 60+ cryptographic algorithms comparing the original C openHiTLS against the Rust rewrite. All Rust numbers from a single fresh Criterion run (rustc 1.93.0, 2026-02-27).

| Category | Verdict | Detail |
|----------|---------|--------|
| **AES (CBC/CTR/GCM)** | **Rust 1.4–8.2x faster** | Both use ARM Crypto Extension; Rust benefits from better pipeline utilization and LTO |
| **ChaCha20-Poly1305** | **Rust 1.4x faster** | Rust 477 MB/s vs C 344 MB/s |
| **Hash (SHA-256/384/512)** | **Rust 1.7–4.2x faster** | SHA-256 HW 4.2x; SHA-512/384 HW 1.7–2.7x |
| **SM3** | **C 1.6x faster** | No hardware acceleration available |
| **HMAC** | **Rust 1.0–6.8x faster** | HMAC-SHA256 6.8x; HMAC-SHA512 2.6x; HMAC-SM3 near parity |
| **SM4 (CBC/GCM)** | **Rust at parity to 1.7x faster** | T-table optimization + hardware GHASH |
| **ECDSA P-256** | **C 1.0–1.4x faster** | P-256 fast path: sign C 1.4x, verify at parity |
| **ECDH P-256** | **Rust 1.1x faster** | P-256 fast path reaches parity |
| **Ed25519 / X25519** | **Near parity** | Precomputed comb: sign Rust 1.4x faster; verify/X25519 C 1.1x faster |
| **SM2** | **Rust 2.5–6.7x faster** | Specialized Montgomery field + precomputed comb table |
| **RSA-2048** | **Rust-only data** | C RSA not registered in benchmark binary |
| **ML-KEM (Kyber)** | **C 3–8x faster** | Improved from 6–18x after NEON NTT |
| **ML-DSA (Dilithium)** | **C 2.6–8.6x faster** | NEON NTT helped but SHAKE sampling dominates |
| **DH (FFDHE)** | **C 4.3–11.6x faster** | CIOS Montgomery improved from 7–12x |

**Bottom line**: Symmetric ciphers (AES, ChaCha20, SM4) and hashes (SHA-256/384/512) are **faster in Rust** across the board. ECDSA P-256 has reached **near-parity with C** (verify within 3%, sign within 1.4x). Asymmetric operations using generic BigNum (DH, PQC) remain slower due to the assembly inner-loop gap.

---

## 2. Test Environment

| Item | Specification |
|------|---------------|
| **CPU** | Apple M4 (ARM64, 10 cores, AES + SHA2 + SHA512 Crypto Extension) |
| **RAM** | 16 GB |
| **OS** | macOS 15.4 (Darwin 25.3.0, arm64) |
| **C Compiler** | Apple Clang 17.0.0 (`-O2`, static link) |
| **C Build** | CMake Release, `libhitls_crypto.a` static library |
| **Rust Compiler** | rustc 1.93.0 (2026-01-19) |
| **Rust Build** | `--release`, LTO enabled, `codegen-units=1` |
| **Rust Benchmark** | Criterion 0.5 (100 samples, statistical analysis, 95% CI) |
| **C Benchmark** | Custom framework (`clock_gettime`, 5,000–10,000 iterations) |

**Note**: CPU frequency scaling is managed by macOS on Apple Silicon. Benchmarks were run with minimal background load. Criterion provides statistical outlier detection; C benchmarks report single-run mean.

---

## 3. Results

### 3.1 Hash Functions (8 KB payload)

| Algorithm | C (MB/s) | Rust (MB/s) | Ratio (R/C) | Notes |
|-----------|----------|-------------|-------------|-------|
| SHA-256 | 571.7 | 2,372 | **4.15** | **HW accel (SHA-NI), Rust 4.2x faster!** |
| SHA-384 | 540.7 | 1,465 | **2.71** | **HW accel (SHA-512 CE), Rust 2.7x faster** |
| SHA-512 | 885.7 | 1,461 | **1.65** | **HW accel (SHA-512 CE), Rust 1.7x faster** |
| SM3 | 528.0 | 323 | **0.61** | No HW accel; C 1.6x faster |

<details>
<summary>Methodology</summary>

- **C**: `openhitls_benchmark_static -t 10000 -l 8192` — SHA-256: 69,792 ops/s, SHA-512: 108,120 ops/s, SM3: 64,448 ops/s; SHA-384 fresh: 65,987 ops/s
- **Rust**: Criterion median — SHA-256: 3.45 µs, SHA-384: 5.59 µs, SHA-512: 5.61 µs, SM3: 25.33 µs
- MB/s = 8192 / (time_µs × 1e-6) / 1e6
</details>

**Analysis**: All three SHA-2 variants now use hardware acceleration in Rust: SHA-256 via ARMv8 SHA-NI (Phase P136), SHA-512/384 via ARMv8.2 SHA-512 Crypto Extensions (Phase P166). SHA-256 achieves a remarkable **4.2x speedup over C**, suggesting the C implementation may not fully utilize SHA-NI. SM3 retains a 1.6x gap to C (no hardware acceleration available for SM3).

---

### 3.2 Symmetric Ciphers (8 KB payload)

| Algorithm | C Enc (MB/s) | Rust Enc (MB/s) | C Dec (MB/s) | Rust Dec (MB/s) | Ratio (Enc) | Ratio (Dec) |
|-----------|-------------|-----------------|-------------|-----------------|-------------|-------------|
| AES-128-CBC | 324.6 | 908 | 331.3 | 2,701 | **2.80** | **8.15** |
| AES-256-CBC | 237.2 | 788 | 261.9 | 2,010 | **3.32** | **7.68** |
| AES-128-CTR | 315.0 | 1,407 | — | — | **4.47** | — |
| AES-256-CTR | 243.4 | 1,133 | — | — | **4.65** | — |
| AES-128-GCM | 155.7 | 802 | 165.8 | 803 | **5.15** | **4.84** |
| AES-256-GCM | 144.4 | 720 | 142.4 | 739 | **4.99** | **5.19** |
| ChaCha20-Poly1305 | 344.1 | 477 | 333.0 | 481 | **1.39** | **1.44** |
| SM4-CBC | 119.9 | 122 | 127.1 | 160 | **1.02** | **1.26** |
| SM4-GCM | 87.6 | 149 | 87.6 | 150 | **1.70** | **1.71** |

> Ratio > 1.0 = Rust faster. CTR mode is symmetric (encrypt = decrypt).

**Analysis**:
- **AES-CBC**: Rust is 2.8–8.2x faster. The massive decrypt advantage comes from CBC decrypt being parallelizable — the Rust AES-NI implementation pipelines multiple `AESDEC` instructions. Encrypt also benefits from better instruction scheduling.
- **AES-CTR**: Rust 4.5–4.7x faster — CTR mode naturally allows parallel block encryption.
- **AES-GCM**: Rust 4.8–5.2x faster — both encryption (AES-NI) and authentication (GHASH PMULL) are hardware-accelerated in Rust. This is significantly better than earlier measurements.
- **ChaCha20-Poly1305**: Rust ~1.4x faster — NEON SIMD optimization for the quarter-round operations.
- **SM4-CBC**: Rust at parity for encrypt (1.02x) and 1.26x faster for decrypt. Phase P155 T-table optimization achieved 2.4x block-level speedup.
- **SM4-GCM**: Rust 1.7x faster — T-table SM4 combined with hardware-accelerated GHASH (ARMv8 PMULL) outperforms C's software SM4 + GHASH.

---

### 3.3 MAC Algorithms (8 KB payload)

| Algorithm | C (MB/s) | Rust (MB/s) | Ratio (R/C) | Notes |
|-----------|----------|-------------|-------------|-------|
| HMAC-SHA256 | 319.8 | 2,178 | **6.81** | **Rust 6.8x faster!** (follows SHA-256 HW speedup) |
| HMAC-SHA512 | 507.7 | 1,313 | **2.59** | **Rust 2.6x faster** (follows SHA-512 HW speedup) |
| HMAC-SM3 | 327.7 | 315 | **0.96** | Near parity |
| CMAC-AES128 | 280.7 | — | — | Rust CMAC benchmark pending |
| GMAC-AES128 | 365.6 | — | — | Rust GMAC benchmark pending |
| SipHash-64 | 1,141.5 | — | — | Not implemented in hitls-crypto |

<details>
<summary>C fresh data (5000 iterations)</summary>

- HMAC-SHA256: 39,026 ops/s → 319.8 MB/s
- HMAC-SHA512: 61,973 ops/s → 507.7 MB/s
- HMAC-SM3: 40,000 ops/s → 327.7 MB/s
- CMAC-AES128: 34,264 ops/s → 280.7 MB/s
- GMAC-AES128: 44,610 ops/s → 365.6 MB/s
- SipHash-64: 139,268 ops/s → 1,141.5 MB/s
</details>

**Analysis**: HMAC performance directly follows the underlying hash. HMAC-SHA256 is now **6.8x faster in Rust** thanks to SHA-256 hardware acceleration. HMAC-SHA512 is **2.6x faster** thanks to SHA-512 CE. HMAC-SM3 is near parity (0.96x), as SM3 itself has no hardware acceleration but the HMAC overhead is minimal.

---

### 3.4 Asymmetric / Public Key Operations

| Algorithm | Operation | C (ops/s) | Rust (ops/s) | Ratio (R/C) | Notes |
|-----------|-----------|----------|-------------|-------------|-------|
| ECDSA P-256 | Sign | 26,848 | 18,657 | **0.695** | P-256 fast path, C 1.44x faster |
| ECDSA P-256 | Verify | 10,473 | 10,187 | **0.973** | **Near parity!** (C only 1.03x faster) |
| ECDH P-256 | Key Derive | 13,584 | 14,927 | **1.099** | **Rust 1.1x faster!** |
| Ed25519 | Sign | 66,193 | 91,324 | **1.38** | **Rust 1.4x faster** (P167 precomputed comb) |
| Ed25519 | Verify | 24,016 | 21,947 | **0.914** | C 1.09x faster |
| X25519 | DH | 49,594 | 45,521 | **0.918** | C 1.09x faster |
| SM2 | Sign | 2,560 | 17,195 | **6.72** | **Rust 6.7x faster!** (P157 specialized field) |
| SM2 | Verify | 4,527 | 11,537 | **2.55** | **Rust 2.5x faster!** |
| SM2 | Encrypt | 1,283 | 6,551 | **5.11** | **Rust 5.1x faster!** |
| SM2 | Decrypt | 2,584 | 13,531 | **5.24** | **Rust 5.2x faster!** |
| RSA-2048 | Sign (PSS) | — | 852 | — | C RSA not in benchmark binary |
| RSA-2048 | Verify (PSS) | — | 24,141 | — | — |
| RSA-2048 | Encrypt (OAEP) | — | 23,704 | — | — |
| RSA-2048 | Decrypt (OAEP) | — | 821 | — | — |

**Analysis**:
- **ECDSA P-256**: The P-256 fast path (Phase P152) brought massive improvement. Verify is now **within 3% of C** (10,187 vs 10,473 ops/s). Sign is C 1.44x faster. This represents a ~45x improvement from the initial generic BigNum implementation.
- **ECDH P-256**: Rust is now **1.1x faster than C** (14,927 vs 13,584 ops/s). The dedicated Montgomery field arithmetic with precomputed base table outperforms C for key derivation.
- **Ed25519/X25519**: Phase P167 precomputed comb table gives Ed25519 sign a 1.4x advantage over C. Verify and X25519 are slightly slower (C ~1.1x faster), likely due to C's optimized field multiply.
- **SM2**: Phase P157 specialized field arithmetic makes SM2 **dramatically faster in Rust** across all operations — sign 6.7x, verify 2.5x, encrypt 5.1x, decrypt 5.2x faster than C. The C implementation appears to use a generic ECC path for SM2.
- **RSA-2048**: C RSA benchmark is declared but not registered in the C benchmark binary's `g_benchs[]` array.

---

### 3.5 Post-Quantum Cryptography

| Algorithm | Operation | C (ops/s) | Rust (ops/s) | Ratio (R/C) |
|-----------|-----------|----------|-------------|-------------|
| ML-KEM-512 | KeyGen | 92,755 | 21,073 | **0.227** |
| ML-KEM-512 | Encaps | 167,182 | 24,716 | **0.148** |
| ML-KEM-512 | Decaps | 125,729 | 40,112 | **0.319** |
| ML-KEM-768 | KeyGen | 38,814 | 13,860 | **0.357** |
| ML-KEM-768 | Encaps | 119,805 | 16,984 | **0.142** |
| ML-KEM-768 | Decaps | 86,794 | 25,582 | **0.295** |
| ML-KEM-1024 | KeyGen | 32,864 | 9,790 | **0.298** |
| ML-KEM-1024 | Encaps | 91,958 | 11,739 | **0.128** |
| ML-KEM-1024 | Decaps | 65,644 | 17,542 | **0.267** |
| ML-DSA-44 | KeyGen | 25,553 | 3,395 | **0.133** |
| ML-DSA-44 | Sign | 7,413 | 2,811 | **0.379** |
| ML-DSA-44 | Verify | 20,882 | 4,232 | **0.203** |
| ML-DSA-65 | KeyGen | 14,894 | 1,727 | **0.116** |
| ML-DSA-65 | Sign | 4,566 | 1,621 | **0.355** |
| ML-DSA-65 | Verify | 12,998 | 2,252 | **0.173** |
| ML-DSA-87 | KeyGen | 8,563 | 1,037 | **0.121** |
| ML-DSA-87 | Sign | 3,517 | 1,050 | **0.299** |
| ML-DSA-87 | Verify | 7,018 | 1,172 | **0.167** |

**Analysis**: PQC performance improved significantly after NEON NTT vectorization (Phases P153/P156):
- **ML-KEM**: C is 3–8x faster (improved from 6–18x). Decaps improved the most (up to 3.1x from initial measurement). The remaining gap is primarily SHAKE-128 sampling and non-vectorized basemul.
- **ML-DSA**: C is 2.6–8.6x faster. Sign benefits most from the NTT improvement since it's the most compute-heavy operation. KeyGen/verify are dominated by SHAKE-128 sampling in ExpandA (~70–90% of total time).

---

### 3.6 Diffie-Hellman Key Exchange

| Group | C KeyGen (ops/s) | Rust KeyGen (ops/s) | C Derive (ops/s) | Rust Derive (ops/s) | Ratio (KeyGen) | Ratio (Derive) |
|-------|-------------------|---------------------|-------------------|---------------------|----------------|----------------|
| FFDHE-2048 | 1,219 | 237 | 997 | 231 | **0.194** | **0.232** |
| FFDHE-3072 | 489 | 62 | 467 | 64 | **0.127** | **0.137** |
| FFDHE-4096 | 290 | 25 | 288 | 26 | **0.086** | **0.090** |
| FFDHE-6144 | 136 | — | 133 | — | — | — |
| FFDHE-8192 | 41 | — | 40 | — | — | — |

**Analysis**: After Phase P154 (CIOS Montgomery), C is 4.3–11.6x faster for DH operations. The gap increases with key size because the O(n^2) inner loop is unchanged — C uses hand-tuned assembly (`bn_mul_mont`) with optimized carry chains while Rust compiles `u128` operations to equivalent `umulh`+`mul` instructions. DH is rarely the bottleneck in modern TLS (ECDHE is strongly preferred).

---

### 3.7 ECDH Multi-Curve (C reference)

| Curve | C KeyGen (ops/s) | C Derive (ops/s) | Rust Derive (ops/s) | Ratio (Derive) |
|-------|-------------------|-------------------|---------------------|----------------|
| P-224 | 86,438 | 30,903 | — | — |
| P-256 | 41,174 | 13,584 | 14,927 | **1.099** |
| P-384 | 1,041 | 969 | — | — |
| P-521 | 12,182 | 5,059 | — | — |
| brainpoolP256r1 | 2,524 | 2,574 | — | — |
| brainpoolP384r1 | 981 | 1,001 | — | — |
| brainpoolP512r1 | 503 | 487 | — | — |

**Analysis**: P-256 ECDH is now **faster in Rust** (14,927 vs 13,584 ops/s) thanks to the dedicated P-256 field arithmetic. C shows dramatic performance disparity — P-224 (87K keygen) and P-256 (41K) are vastly faster than P-384 (1K), suggesting P-224 and P-256 have specialized field implementations while P-384 uses a generic path.

---

### 3.8 SLH-DSA / SPHINCS+ (C reference)

| Parameter Set | KeyGen (ops/s) | Sign (ops/s) | Verify (ops/s) |
|--------------|----------------|-------------|----------------|
| SLH-DSA-SHA2-128S | 7.2 | 0.60 | 1,069 |
| SLH-DSA-SHAKE-128S | 7.8 | 0.89 | 731 |
| SLH-DSA-SHA2-128F | 500 | 18.4 | 374 |
| SLH-DSA-SHAKE-128F | 515 | 19.0 | 379 |
| SLH-DSA-SHA2-192S | 2.7 | 0.56 | 763 |
| SLH-DSA-SHA2-192F | 198 | 12.7 | 282 |
| SLH-DSA-SHA2-256S | 4.4 | 0.57 | 542 |
| SLH-DSA-SHA2-256F | 72.9 | 6.3 | 253 |

**Analysis**: SLH-DSA is inherently slow — the "S" (small signature) parameter sets achieve <1 sign/s. The "F" (fast) variants trade larger signatures for ~20–30x faster signing. These are C reference numbers; Rust SLH-DSA benchmarks are pending but expected to show similar performance patterns since both implementations are hash-based with no hardware acceleration opportunity.

---

### 3.9 BigNum Arithmetic (Rust only)

| Operation | 256-bit | 512-bit | 1024-bit | 2048-bit | 4096-bit |
|-----------|---------|---------|----------|----------|----------|
| Multiply | 56.4 ns | 116.3 ns | 337.7 ns | 983.0 ns | 3,770 ns |
| Add | 40.1 ns | 51.9 ns | 85.6 ns | 153.0 ns | 270.8 ns |

**Modular exponentiation** (Phase P154 CIOS Montgomery):

| Operation | Time |
|-----------|------|
| mod_exp 1024-bit | 595 µs |
| mod_exp 2048-bit | 4.33 ms |
| mod_exp 4096-bit | 36.4 ms |

---

## 4. Performance Heatmap

```
                        C faster <------------------> Rust faster
                        x12    x8     x4    1.0    x2     x5    x8

DH-4096 keygen          ████████████████████░░░░░░░░░░░░░░░░░░░░░  C x11.6
ML-DSA-87 keygen        ██████████████████░░░░░░░░░░░░░░░░░░░░░░░  C x8.3
ML-KEM-768 encaps       █████████████████░░░░░░░░░░░░░░░░░░░░░░░░  C x7.1
DH-2048 keygen          ██████████████░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x5.1
ML-DSA-44 sign          ███████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x2.6
SM3                     ██████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.6
ECDSA P-256 sign        █████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.44
X25519 DH               ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.09
Ed25519 verify          ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.09
ECDSA P-256 verify      ████████░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░  C x1.03
SM4-CBC enc             ░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░░  R x1.02
ECDH P-256              ░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░░  R x1.10
SM4-CBC dec             ░░░░░░░░░░░░░░░░░░░░░░█░░░░░░░░░░░░░░░░░░  R x1.26
Ed25519 sign            ░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░  R x1.38
ChaCha20-Poly1305       ░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░░  R x1.39
SHA-512                 ░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░  R x1.65
SM4-GCM                 ░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░░░  R x1.70
SM2 verify              ░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░  R x2.55
HMAC-SHA512             ░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░░  R x2.59
SHA-384                 ░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░  R x2.71
AES-128-CBC enc         ░░░░░░░░░░░░░░░░░░░░░░░░░░██░░░░░░░░░░░░░  R x2.80
SHA-256                 ░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░  R x4.15
AES-128-CTR             ░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░░  R x4.47
AES-128-GCM enc         ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░  R x5.15
SM2 encrypt             ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░  R x5.11
SM2 decrypt             ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░████░░░░░░░░  R x5.24
SM2 sign                ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░█████░░░░░░  R x6.72
HMAC-SHA256             ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░█████░░░░░░  R x6.81
AES-128-CBC dec         ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░██████░  R x8.15
```

---

## 5. Performance Optimization Roadmap (Phase P136–P167)

All optimization tasks are tracked as numbered phases using unified global numbering (Phase PN), ordered by priority and TLS handshake impact.

### Phase Overview

| Phase | Optimization | Current Gap | Target | Effort | Status |
|-------|-------------|-------------|--------|--------|--------|
| **P152** | P-256 deep optimization (precomputed table + specialized reduction) | 16–32x → 1.0–1.4x | 2–3x | High | **Complete** |
| **P153** | ML-KEM SIMD NTT vectorization | 6–18x → 3–8x | 2–3x | High | **Complete** |
| **P154** | BigNum CIOS fused multiply+reduce + pre-allocated buffer | 7–12x → 4.3–11.6x | 2–3x | High | **Complete** |
| **P155** | SM4 T-table lookup optimization | 2.2–2.4x → 1.0x | ~1x | Medium | **Complete** |
| **P156** | ML-DSA SIMD NTT vectorization | 2–6x → 2.6–8.6x | NTT 2.3x; E2E ~1.02x | Medium | **Complete** |
| **P157** | SM2 specialized field arithmetic | 2.8–6.1x → Rust 2.5–6.7x FASTER | 18–25x | Medium | **Complete** |
| **P166** | SHA-512 hardware acceleration (ARMv8.2 SHA512) | 1.35x → Rust 1.7x faster | ~1x | Low | **Complete** |
| **P167** | Ed25519 precomputed base table | 2x → Rust 1.4x faster | ~1.2x | Low | **Complete** |

---

### Phase P152 — P-256 Deep Optimization (Precomputed Table + Specialized Reduction) ✅ Complete

**Result**: ECDSA P-256 sign **21x speedup** (1179→55.6 µs), verify **14x speedup** (1423→102.5 µs)

**Optimizations implemented**:

| Optimization | Speedup | Detail |
|-------------|---------|--------|
| **Precomputed base table (comb method)** | ~5x sign | 64 groups x 16 affine points, lazy-initialized via `OnceLock`. Base point mul uses ~64 mixed additions, 0 doublings (vs 256 doublings + 48 additions). Batch inversion (Montgomery's trick) for efficient table generation. |
| **Dedicated `mont_sqr()`** | ~15% all ops | Exploits a[i]*a[j] = a[j]*a[i] symmetry: 10 u64xu64 multiplies (6 cross + 4 diagonal) vs 16 for schoolbook. |
| **P-256 specialized Montgomery reduction** | ~30% all ops | Exploits P[0]=-1 (carry=m, no multiply) and P[2]=0 (skip multiply): 8 multiplies per reduction vs 16 generic. |
| **Mixed Jacobian-affine addition** | ~25% table lookups | `p256_point_add_mixed`: 8 mul + 3 sqr (vs 12 mul + 4 sqr for full Jacobian). Used by comb table lookups. |
| **Separate k1*G + k2*Q for verify** | ~1.3x verify | Uses precomputed base table for k1*G (fast) + w=4 window for k2*Q, replacing bit-by-bit Shamir. |

**Benchmark results** (Apple M4, rustc 1.93.0):

| Operation | Before | After | Speedup | C Reference |
|-----------|--------|-------|---------|-------------|
| ECDSA P-256 sign | 1179 µs (848 ops/s) | 55.6 µs (~18,000 ops/s) | **21x** | 37.2 µs (26,848 ops/s) |
| ECDSA P-256 verify | 1423 µs (703 ops/s) | 102.5 µs (~9,756 ops/s) | **14x** | 94.1 µs (10,628 ops/s) |
| ECDH P-256 derive | ~1.1 ms | 72.4 µs (~13,800 ops/s) | **15x** | — |

**Fresh data (2026-02-27)**: ECDSA sign 53.60 µs (18,657 ops/s), verify 98.17 µs (10,187 ops/s), ECDH derive 66.99 µs (14,927 ops/s). Gap to C: sign 1.44x, verify 1.03x, ECDH Rust 1.10x FASTER.

---

### Phase P153 — ML-KEM SIMD NTT Vectorization ✅ Complete

**Result**: ML-KEM-768 encaps **2.0x speedup** (109→54.8 µs), decaps **2.6x speedup** (95→36.0 µs), keygen **2.3x speedup** (155→66.5 µs)

**Optimizations implemented**:

| Optimization | Speedup | Detail |
|-------------|---------|--------|
| **NEON 8-wide NTT/INTT butterflies** | ~2x NTT | `vqdmulhq_s16` + `vhsubq_s16` Montgomery trick processes 8 coefficients per SIMD op. Stages len>=8 fully vectorized; len=4 and len=2 use half-register and lane-extract fallback. |
| **NEON Barrett reduction** | ~2x reduce | Widening multiply (`vmlal_s16`) + shift-narrow (`vshrq_n_s32::<26>` + `vmovn_s32`) for 8-wide Barrett. Used in INTT and basemul accumulation. |
| **NEON polynomial utilities** | ~2x add/sub | `poly_add`, `poly_sub`, `to_mont`, `reduce_poly` vectorized (32 iterations x 8 elements). |
| **Batch SHAKE-128 squeeze** | ~1.5x sampling | `rej_sample` squeezes 504 bytes (3 SHAKE blocks) per call instead of 3 bytes, reducing ~200 Vec allocations to 1–2. |

**Benchmark results** (Apple M4, rustc 1.93.0):

| Operation | Before | After | Speedup |
|-----------|--------|-------|---------|
| ML-KEM-512 keygen | ~90 µs | 44.1 µs | **2.0x** |
| ML-KEM-512 encaps | ~79 µs | 37.7 µs | **2.1x** |
| ML-KEM-512 decaps | ~50 µs | 24.0 µs | **2.1x** |
| ML-KEM-768 keygen | ~155 µs | 66.5 µs | **2.3x** |
| ML-KEM-768 encaps | ~109 µs | 54.8 µs (18,248 ops/s) | **2.0x** |
| ML-KEM-768 decaps | ~95 µs | 36.0 µs | **2.6x** |
| ML-KEM-1024 keygen | ~199 µs | 93.5 µs | **2.1x** |
| ML-KEM-1024 encaps | ~189 µs | 78.4 µs | **2.4x** |
| ML-KEM-1024 decaps | ~160 µs | 52.9 µs | **3.0x** |

**Fresh data (2026-02-27)**: ML-KEM-768 encaps 58.88 µs (16,984 ops/s), decaps 39.09 µs (25,582 ops/s). Gap to C: encaps 7.1x, decaps 3.4x.

---

### Phase P154 — BigNum CIOS Fused Multiply+Reduce + Pre-allocated Buffer ✅ Complete

**Result**: DH-2048 keygen **1.25x speedup** (174→218 ops/s), RSA-2048 sign **1.11x speedup** (719→800 ops/s)

**Optimizations implemented**:

| Optimization | Speedup | Detail |
|-------------|---------|--------|
| **CIOS fused multiply+reduce** | ~1.2x | Coarsely Integrated Operand Scanning: fuses multiplication and Montgomery reduction into a single pass on an (n+2)-limb accumulator. Eliminates the 2n-limb intermediate product and saves one full pass over the data. |
| **Pre-allocated flat limb table** | ~1.05x | Exponentiation table stored as flat `Vec<u64>` (table_size x n) instead of `Vec<BigNum>`. Eliminates per-entry heap allocation and improves cache locality. |
| **Single conditional subtraction** | minor | Replaces while-loop modular correction with a single comparison + subtraction (CIOS guarantees result < 2N). |
| **Optimized squaring (sqr_limbs)** | ~1.1x sqr | Exploits a[i]*a[j] symmetry: n(n-1)/2 cross-products doubled via bit-shift + n diagonal terms, vs n^2 for schoolbook. Used in public `mont_sqr` API. |

**Benchmark results** (Apple M4, rustc 1.93.0):

| Operation | Before | After | Speedup | C Reference |
|-----------|--------|-------|---------|-------------|
| DH-2048 keygen | 5.75 ms (174 ops/s) | 4.59 ms (218 ops/s) | **1.25x** | 0.82 ms (1,219 ops/s) |
| DH-2048 derive | 5.78 ms (173 ops/s) | 4.41 ms (227 ops/s) | **1.31x** | 1.00 ms (997 ops/s) |
| DH-3072 keygen | 17.5 ms (57 ops/s) | 15.1 ms (66 ops/s) | **1.16x** | 2.04 ms (489 ops/s) |
| DH-3072 derive | 17.2 ms (58 ops/s) | 14.9 ms (67 ops/s) | **1.16x** | 2.14 ms (467 ops/s) |
| DH-4096 keygen | 40.0 ms (25 ops/s) | 36.3 ms (28 ops/s) | **1.12x** | 3.45 ms (290 ops/s) |
| DH-4096 derive | 40.0 ms (25 ops/s) | 35.2 ms (28 ops/s) | **1.12x** | 3.47 ms (288 ops/s) |
| RSA-2048 sign PSS | 1.39 ms (719 ops/s) | 1.25 ms (800 ops/s) | **1.11x** | — |
| RSA-2048 decrypt OAEP | 1.42 ms (704 ops/s) | 1.24 ms (808 ops/s) | **1.15x** | — |

**Fresh data (2026-02-27)**: DH-2048 keygen 4.22 ms (237 ops/s), derive 4.33 ms (231 ops/s). Gap to C: keygen 5.1x, derive 4.3x.

---

### Phase P155 — SM4 T-table Lookup Optimization ✅ Complete

**Result**: SM4-CBC encrypt **2.37x speedup** (50.8→120.2 MB/s, parity with C), SM4-GCM encrypt **3.09x speedup** (47.6→146.9 MB/s, 1.68x faster than C)

**Optimizations implemented**:

| Optimization | Speedup | Detail |
|-------------|---------|--------|
| **Compile-time T-tables (XBOX_0-3)** | ~1.9x block | `const fn` generates 4 x 256-entry u32 tables fusing SBOX + L-transform. Each round: 4 table lookups + 3 XOR (replaces 4 SBOX lookups + 4 rotations + 4 XOR). 4 KB total in .rodata. |
| **Compile-time KBOX_0-3** | ~1.2x keygen | Same approach for key expansion T'-tables using L' linear transform. 4 KB additional. |
| **4-way unrolled round loop** | ~1.1x all ops | Eliminates per-round `x.rotate_left(1)` by unrolling 4 rounds with explicit x0/x1/x2/x3 addressing. |
| **Precomputed decrypt round keys** | ~1.15x decrypt | `round_keys_dec` stored in `Sm4Key`, computed once in `new()`. Eliminates per-block `round_keys.reverse()` in `decrypt_block()`. |

**Benchmark results** (Apple M4, rustc 1.93.0):

| Operation | Before | After | Speedup | C Reference |
|-----------|--------|-------|---------|-------------|
| SM4 block encrypt | 202 ns | 106 ns | **1.91x** | — |
| SM4 block decrypt | 205 ns | 110 ns | **1.86x** | — |
| SM4-CBC encrypt @8KB | 161.1 µs (50.8 MB/s) | 68.2 µs (120.2 MB/s) | **2.37x** | 119.9 MB/s |
| SM4-CBC decrypt @8KB | 145.0 µs (56.5 MB/s) | 53.0 µs (154.5 MB/s) | **2.73x** | 127.1 MB/s |
| SM4-GCM encrypt @8KB | 172.3 µs (47.6 MB/s) | 55.8 µs (146.9 MB/s) | **3.09x** | 87.6 MB/s |
| SM4-GCM decrypt @8KB | 172.9 µs (47.4 MB/s) | 56.4 µs (145.3 MB/s) | **3.06x** | 87.6 MB/s |

---

### Phase P156 — ML-DSA SIMD NTT Vectorization ✅ Complete

**NTT micro-benchmark**: Forward NTT 2.31x (427→185 ns), Inverse NTT 2.54x (527→207 ns).

**End-to-end impact**: Modest (~2–5%) because NTT constitutes only ~3–4% of total ML-DSA operation time. The dominant cost is SHAKE-128 sampling in ExpandA.

**Implementation**: 4-wide `int32x4_t` NEON intrinsics for Montgomery multiply (`vqdmulhq_s32` + `vhsubq_s32`), forward/inverse NTT (len>=4 fully vectorized, len=2 half-register, len=1 scalar), Barrett reduction (`vmlsq_s32`), and 6 polynomial utility functions. Runtime dispatch via `is_aarch64_feature_detected!("neon")` with scalar fallback.

---

### Phase P157 — SM2 Specialized Field Arithmetic ✅ Complete

**Result**: SM2 sign **20.2x speedup** (1177→58.16 µs), verify **16.9x speedup** (1462→86.68 µs), encrypt **15.2x speedup** (2315→152.66 µs), decrypt **15.5x speedup** (1148→73.90 µs). **Rust now 2.5–6.7x faster than C**.

**Optimizations implemented** (mirrors Phase P152 P-256 approach):

| Optimization | Detail |
|-------------|--------|
| **4x u64 Montgomery field** | `Sm2FieldElement` with SM2 prime-specific reduction: N0=1 (P[0]=-1 mod 2^64), P[2]=-1 trick (subtraction instead of multiply). 8 multiplies per reduction vs 16 generic. |
| **Precomputed base table (comb method)** | 64 groups x 16 affine points, OnceLock-cached, batch inversion via Montgomery's trick. Base point mul: ~64 mixed additions, 0 doublings. |
| **a=-3 point doubling** | M = 3*(X+Z^2)*(X-Z^2) optimization, same as P-256 (SM2 also has a=-3). |
| **Mixed Jacobian-affine addition** | 8 mul + 3 sqr for table lookups (vs 12 mul + 4 sqr full Jacobian). |
| **Inversion chain (281 sqr + 17 mul)** | Optimized addition chain for SM2 p-2 using precomputed powers x1..x32. |

**Benchmark results** (Apple M4, rustc 1.93.0):

| Operation | Before | After | Speedup | C Reference | Rust/C |
|-----------|--------|-------|---------|-------------|--------|
| SM2 sign | 1177 µs (850 ops/s) | 58.16 µs (17,195 ops/s) | **20.2x** | 2,560 ops/s | **6.72x** |
| SM2 verify | 1462 µs (684 ops/s) | 86.68 µs (11,537 ops/s) | **16.9x** | 4,527 ops/s | **2.55x** |
| SM2 encrypt | 2315 µs (432 ops/s) | 152.66 µs (6,551 ops/s) | **15.2x** | 1,283 ops/s | **5.11x** |
| SM2 decrypt | 1148 µs (871 ops/s) | 73.90 µs (13,531 ops/s) | **15.5x** | 2,584 ops/s | **5.24x** |

---

### Phase P166 — SHA-512 Hardware Acceleration ✅ Complete

**Result**: SHA-512 **2.4x speedup** (662.8 → 1,578 MB/s), SHA-384 **3.9x speedup** (411 → 1,597 MB/s). **Rust now 1.7x faster than C** for SHA-512.

**Optimizations implemented**:

| Optimization | Detail |
|-------------|--------|
| **ARMv8.2-A SHA-512 Crypto Extensions** | `vsha512hq_u64`, `vsha512h2q_u64`, `vsha512su0q_u64`, `vsha512su1q_u64` intrinsics |
| **5-register rotation pattern** | Following Linux kernel sha512-ce-core.S: 40 drounds in 8 cycles of 5, with state rotation (s0,s1,s2,s3,s4) |
| **K+W halves swap** | `vextq_u64(kw, kw, 1)` before adding to state register |
| **Runtime feature detection** | `is_aarch64_feature_detected!("sha3")` with software fallback |

**Benchmark results** (Apple M4, rustc 1.93.0):

| Hash | Before (MB/s) | After (MB/s) | Speedup | C Reference (MB/s) | Rust/C |
|------|--------------|-------------|---------|-------------------|--------|
| SHA-512 (8KB) | 662.8 | 1,578 | **2.4x** | 885.7 | **1.78x** |
| SHA-384 (8KB) | 411.0 | 1,597 | **3.9x** | 540.7 | **2.95x** |

**Fresh data (2026-02-27)**: SHA-512 1,461 MB/s (1.65x vs C), SHA-384 1,465 MB/s (2.71x vs C).

---

### Phase P167 — Ed25519 Precomputed Base Table ✅ Complete

**Result**: Ed25519 sign **3.1x speedup** (29.7 → 9.5 µs), verify **1.5x speedup** (61.9 → 40.9 µs). **Rust now 1.4x faster than C** for sign.

**Optimizations implemented**:

| Optimization | Detail |
|-------------|--------|
| **Precomputed comb table** | 64 groups x 16 Niels points, OnceLock-cached, lazy-initialized |
| **Niels point form** | (Y+X, Y-X, 2d*T) — 7M per mixed addition vs 9M for full extended |
| **Comb method** | 63 mixed additions, 0 doublings (vs 255 doublings + ~64 additions in double-and-add) |
| **Constant-time table lookup** | `ct_select_niels` with conditional assignment to prevent timing leaks |

**Benchmark results** (Apple M4, rustc 1.93.0):

| Operation | Before (µs) | After (µs) | Speedup | C Reference | Rust/C |
|-----------|------------|-----------|---------|-------------|--------|
| Ed25519 sign | 29.7 | 9.5 | **3.1x** | 15.1 µs (66K ops/s) | **1.59x** |
| Ed25519 verify | 61.9 | 40.9 | **1.5x** | 41.6 µs (24K ops/s) | **1.02x** |

**Fresh data (2026-02-27)**: Ed25519 sign 10.95 µs (91,324 ops/s, Rust 1.38x vs C), verify 45.56 µs (21,947 ops/s, C 1.09x).

---

### Impact on TLS Handshake Latency

| Handshake Type | Before Optimization (Rust) | After All Phases | C Reference |
|---------------|---------------------------|-----------------|-------------|
| **ECDHE-P256 + AES-128-GCM** | ~3.8 ms | **~0.22 ms** | 0.21 ms |
| **X25519 + Ed25519 + AES-128-GCM** | ~0.10 ms | **~0.079 ms** | 0.077 ms |
| **ML-KEM-768 hybrid** | ~0.11 ms | ~0.059 ms | 0.008 ms |
| **FFDHE-2048** | ~5.8 ms | **~4.2 ms** | 0.82 ms |

A TLS 1.3 handshake with ECDHE-P256 + AES-128-GCM involves:
- 1 ECDH key derive (67.0 µs Rust vs ~73.6 µs C)
- 1 ECDSA P-256 verify (98.2 µs Rust vs ~95.5 µs C)
- 1 ECDSA P-256 sign (53.6 µs Rust vs ~37.2 µs C)
- HKDF/SHA-256 derivations (~negligible at small sizes)

**Total: ~219 µs Rust vs ~206 µs C** — within **1.06x** of C for a complete P-256 handshake.

For **X25519 + Ed25519 handshakes**: ~79 µs (Rust) vs ~77 µs (C) — **virtually identical!** This is the recommended key exchange for Rust deployments.

---

## 6. Detailed Methodology

### 6.1 C Benchmark Framework

The C benchmark (`openhitls_benchmark`) uses a custom framework:
- Pre-allocates data buffers and key contexts before timing
- Runs N iterations in a tight loop, measures wall-clock time via `clock_gettime(CLOCK_REALTIME)`
- Reports: `time_elapsed_ms`, `ops/s = iterations / (time_elapsed_ms / 1000)`
- Single-run mean (no statistical analysis)

**Command**: `./openhitls_benchmark_static -t <iterations> -l <payload_bytes>`

**Note**: RSA is declared (`extern BenchCtx RsaBenchCtx`) but **not registered** in the `g_benchs[]` array, so RSA C benchmarks cannot be run with the current binary.

### 6.2 Rust Criterion Framework

Criterion 0.5 provides:
- Automatic warm-up phase
- 100 statistical samples with confidence intervals (95% CI)
- Outlier detection and noise filtering
- Reports: median time per operation, throughput (MiB/s or GiB/s)

**Command**: `cargo bench -p hitls-crypto --all-features`

### 6.3 Comparability Notes

1. **Payload size**: All symmetric/hash comparisons use 8 KB (8192 bytes) payload
2. **Key setup**: Both frameworks pre-generate keys before timing; key generation is excluded
3. **Memory allocation**: Both allocate output buffers before the timing loop
4. **Compiler optimization**: C uses `-O2`, Rust uses release profile with LTO + `codegen-units=1`
5. **Hardware acceleration**: Both implementations compile with ARM Crypto Extension support enabled

### 6.4 Caveats

- **Single machine**: All results are from a single Apple M4. x86-64 results may differ (Intel SHA-NI, AVX2)
- **C build flags**: The `libhitls_crypto.a` was built via CMake; exact flags depend on the CMake configuration
- **Criterion overhead**: Criterion's statistical framework adds per-sample overhead (~microseconds), which may inflate small-operation times relative to the C benchmark's tight loop
- **No CPU pinning**: macOS does not support `taskset`-style CPU pinning on Apple Silicon; results may include scheduling jitter
- **Thermal throttling**: Full benchmark suite runs may exhibit ~5–10% slowdown in later tests due to sustained CPU load
- **C MAC/Hash fresh run**: Some C MAC/hash numbers were re-measured with 5000 iterations; original symmetric/hash C data used 10000 iterations

---

## 7. Performance Improvement Tracking

### Rust Performance Gains (all optimizations vs initial measurement)

| Algorithm | Initial (µs) | Current (µs) | Speedup |
|-----------|-------------|-------------|---------|
| SHA-256 @8KB | 42.25 | 3.45 | **12.2x** |
| SHA-512 @8KB | 26.95 | 5.61 | **4.80x** |
| SM3 @8KB | 39.77 | 25.33 | **1.57x** |
| ECDSA P-256 sign | 2,415 | 53.60 | **45.1x** |
| ECDSA P-256 verify | 2,439 | 98.17 | **24.8x** |
| Ed25519 sign | 56.1 | 10.95 | **5.12x** |
| Ed25519 verify | 163.3 | 45.56 | **3.58x** |
| X25519 DH | 47.5 | 21.97 | **2.16x** |
| SM2 sign | 2,331 | 58.16 | **40.1x** |
| SM2 verify | 2,439 | 86.68 | **28.1x** |
| RSA-2048 sign | 2,512 | 1,174 | **2.14x** |
| BigNum mul 2048-bit | 1,110 ns | 983 ns | **1.13x** |

**Root causes**: Hardware acceleration (SHA-256 SHA-NI, SHA-512 CE), specialized field arithmetic (P-256, SM2), precomputed tables (Ed25519, P-256, SM2), CIOS Montgomery, T-table SM4, NEON NTT, and rustc 1.93.0 codegen improvements.

---

## Appendix A: Raw Data Sources

| Source | File | Description |
|--------|------|-------------|
| Rust Criterion | `target/criterion/` | Full statistical reports (HTML + JSON) |
| Rust CLI speed | `cargo run --release -p hitls-cli -- speed all` | Quick throughput check |
| C cipher (8KB) | original session | AES/SM4/ChaCha20 encrypt/decrypt, 10000 iterations |
| C hash (multi-size) | original session | MD5/SHA/SM3 at 16B–16KB, 10000 iterations |
| C hash (fresh) | `Md*` -t 5000 | SHA-384, SM3 at 8KB |
| C MAC (8KB) | `Mac*` -t 5000 | HMAC/CMAC/GMAC/SipHash, 5000 iterations |
| C ECDSA | original session | P-256/384/521, 10000 iterations |
| C ECDH | `Ecdh*` -t 5000 | P-224/256/384/521 + Brainpool, 5000 iterations |
| C Ed25519/X25519 | original session | Sign/verify/DH, 10000 iterations |
| C SM2 | original session | KeyGen/sign/verify/enc/dec, 10000 iterations |
| C ML-KEM | original session | 512/768/1024, 10000 iterations |
| C ML-DSA | original session | 44/65/87, 10000 iterations |
| C DH | `Dh*` -t 1000 | RFC 2409/3526/7919 groups, 1000 iterations |
| C SM4-CBC | `Cipher*` -p sm4-cbc | SM4-CBC enc/dec, 5000 iterations |
| C SM4-GCM | `Cipher*` -p sm4-gcm | SM4-GCM enc/dec, 5000 iterations |

## Appendix B: Rust Benchmark Coverage

| File | Algorithms | Benchmarks |
|------|-----------|------------|
| `crates/hitls-crypto/benches/crypto_bench.rs` | AES, AES-GCM, AES-CBC, AES-CTR, ChaCha20-Poly1305, SHA-256/384/512, SM3, HMAC-SHA256/SHA512/SM3, SM4 (block + CBC + GCM), ECDSA P-256, ECDH P-256, Ed25519, X25519, SM2, RSA-2048, ML-KEM, ML-DSA, DH (FFDHE 2048/3072/4096), BigNum | 24 groups, ~80 benchmarks |
| `crates/hitls-cli/src/speed.rs` | AES-GCM, ChaCha20-Poly1305, SHA-256/384/512, SM3 | 6 algorithms |

## Appendix C: CLI Speed Quick Reference

```
Rust CLI speed (8KB payload, 3-second duration):
AES-128-GCM                  307.30 MB/s
AES-256-GCM                  304.61 MB/s
ChaCha20-Poly1305            631.70 MB/s
SHA-256                      394.68 MB/s
SHA-384                      598.30 MB/s
SM3                          365.73 MB/s
```

> Note: CLI `speed` results differ from Criterion due to measurement methodology (wall-clock throughput vs per-operation statistical sampling). CLI speed may amortize one-time costs differently.

## Appendix D: Full Criterion Median Times (2026-02-27 fresh run)

```
aes-128-cbc enc @8KB:     9,020    aes-128-cbc dec @8KB:     3,033
aes-256-cbc enc @8KB:    10,400    aes-256-cbc dec @8KB:     4,074
aes-128-ctr @8KB:         5,823    aes-256-ctr @8KB:         7,228
aes-128-gcm enc @8KB:    10,220    aes-128-gcm dec @8KB:    10,206
aes-256-gcm enc @8KB:    11,383    aes-256-gcm dec @8KB:    11,091
chacha20 enc @8KB:       17,159    chacha20 dec @8KB:       17,051
sha256 @8KB:              3,454    sha384 @8KB:              5,593
sha512 @8KB:              5,608    sm3 @8KB:                25,330
hmac-sha256 @8KB:         3,764    hmac-sha512 @8KB:         6,241
hmac-sm3 @8KB:           26,012
sm4-cbc enc @8KB:        66,944    sm4-cbc dec @8KB:        51,319
sm4-gcm enc @8KB:        54,876    sm4-gcm dec @8KB:        54,684
ecdsa-p256 sign:         53,596    ecdsa-p256 verify:       98,170
ecdh p256 derive:        66,990    x25519 dh:               21,970
ed25519 sign:            10,950    ed25519 verify:          45,560
sm2 sign:                58,160    sm2 verify:              86,680
sm2 encrypt:            152,660    sm2 decrypt:             73,900
rsa-2048 sign pss:    1,174,000    rsa-2048 verify pss:     41,420
rsa-2048 enc oaep:       42,190    rsa-2048 dec oaep:    1,219,000
dh-2048 keygen:       4,217,000    dh-2048 derive:       4,328,000
dh-3072 keygen:      16,020,000    dh-3072 derive:      15,540,000
dh-4096 keygen:      39,230,000    dh-4096 derive:      38,660,000
mlkem-512 keygen:        47,450    mlkem-512 encaps:        40,460
mlkem-512 decaps:        24,930
mlkem-768 keygen:        72,150    mlkem-768 encaps:        58,880
mlkem-768 decaps:        39,090
mlkem-1024 keygen:      102,140    mlkem-1024 encaps:       85,190
mlkem-1024 decaps:       57,010
mldsa-44 keygen:        294,520    mldsa-44 sign:          355,800
mldsa-44 verify:        236,300
mldsa-65 keygen:        578,970    mldsa-65 sign:          616,800
mldsa-65 verify:        444,050
mldsa-87 keygen:        964,680    mldsa-87 sign:          952,810
mldsa-87 verify:        852,930
bignum mul 256:              56    bignum mul 512:             116
bignum mul 1024:            338    bignum mul 2048:            983
bignum mul 4096:          3,770
bignum add 256:              40    bignum add 512:              52
bignum add 1024:             86    bignum add 2048:            153
bignum add 4096:            271
bignum mod_exp 1024:    594,940    bignum mod_exp 2048:  4,334,000
bignum mod_exp 4096:  36,440,000
```
