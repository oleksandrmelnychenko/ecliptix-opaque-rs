### Category 6: Post-Quantum KEM Migration (liboqs → Pure Rust)

> **STATUS: COMPLETED.** Both migrations are done: `libsodium-sys-stable` → pure Rust crates (`curve25519-dalek`, `sha2`, `hmac`, `argon2`, `crypto_secretbox`, `subtle`); `oqs` (liboqs) → `ml-kem` (0.2.3, FIPS 203). No C dependencies remain. This document is retained as historical reference.

The project previously used **`oqs` (Open Quantum Safe)** for Kyber-768, which had the **exact same C dependency problem** as sodiumoxide:
- Requires CMake at build time
- Compiles C/C++ code (liboqs) via FFI
- Cross-compilation breaks constantly
- CI needs `cmake`, `ninja`, C compiler on every platform
- WASM target impossible
- Windows builds are a nightmare (Visual Studio build tools, etc.)
- Every downstream user inherits this build pain

**This must be eliminated alongside sodiumoxide.**

#### 6.1 Current liboqs/oqs Usage Inventory

Map every PQ-related function call:

```
Find every:
- oqs::kem::* usage (KeyEncapsulation, Algorithm, Kem)
- Kyber-768 key generation
- Kyber-768 encapsulation (encrypt)
- Kyber-768 decapsulation (decrypt)
- Kyber ciphertext serialization/deserialization
- Kyber public key serialization/deserialization
- Kyber secret key storage (is it behind SecureMemoryHandle?)
- How Kyber output is combined with X25519 (hybrid construction)
```

Document exact sizes:
```
Kyber-768 via liboqs:
- Public key:    1184 bytes
- Secret key:    2400 bytes
- Ciphertext:    1088 bytes
- Shared secret:   32 bytes

VERIFY these match the replacement crate EXACTLY.
Size mismatch = wire format break = protocol incompatibility.
```

#### 6.2 Pure Rust PQ-KEM Options

Evaluate these replacements in order of preference:

**Option A: `ml-kem` (RustCrypto)**
```toml
[dependencies]
ml-kem = { version = "0.2", features = ["std"] }
```
- ✅ Pure Rust, no C, no CMake
- ✅ Part of RustCrypto ecosystem (consistent with rest of migration)
- ✅ Implements FIPS 203 (ML-KEM, the standardized version of Kyber)
- ✅ Covers ML-KEM-768 (equivalent security to Kyber-768)
- ⚠️ ML-KEM is the NIST standard name — Kyber was the submission name
- ⚠️ ML-KEM made small changes from original Kyber — **ciphertexts are NOT wire-compatible with draft Kyber**
- 🔴 **CRITICAL**: If the protocol already has deployed Kyber-768 ciphertexts in the wild (from liboqs), ML-KEM will NOT be able to decapsulate them. This is a breaking change.

**Option B: `pqc-kyber`**
```toml
[dependencies]
pqc-kyber = { version = "0.8", features = ["kyber768", "std"] }
```
- ✅ Pure Rust, no C, no CMake
- ✅ Implements original Kyber (round 3 submission) — NOT ML-KEM
- ✅ Wire-compatible with liboqs Kyber-768 output
- ⚠️ Smaller community, less audited than RustCrypto
- ⚠️ May not receive long-term maintenance (Kyber is "superseded" by ML-KEM)
- ⚠️ Verify constant-time properties — some operations may not be constant-time

**Option C: `safe-oqs` or `oqs-rs` with vendored static build**
- ❌ Still C code under the hood
- ❌ Still needs CMake
- ❌ Defeats the purpose — reject this option

**Decision Matrix:**

| Factor | `ml-kem` (RustCrypto) | `pqc-kyber` |
|---|---|---|
| Pure Rust | ✅ | ✅ |
| Audited | Partial (RustCrypto ecosystem) | Less |
| Wire compat with existing liboqs Kyber-768 | 🔴 NO — ML-KEM ≠ Kyber | ✅ YES |
| NIST standard compliant | ✅ FIPS 203 | ❌ Pre-standard |
| Long-term maintenance | ✅ RustCrypto team | ⚠️ Uncertain |
| Constant-time | ✅ (uses `crypto-common`) | ⚠️ Verify |
| `no_std` support | ✅ | ✅ |
| WASM support | ✅ | ✅ |

**Ask the author:**
1. Are there deployed peers or stored ciphertexts using liboqs Kyber-768?
   - YES → must use `pqc-kyber` for backward compat, then plan migration to ML-KEM later
   - NO → use `ml-kem` directly (FIPS 203, better long-term choice)
2. Is the protocol versioned? Can v2 use ML-KEM while v1 used Kyber?
   - YES → use `ml-kem`, version the protocol, both versions coexist during transition
   - NO → harder migration, need compat shim

#### 6.3 The Kyber vs ML-KEM Wire Format Difference — CRITICAL

```
Original Kyber-768 (liboqs, pqc-kyber):
- Uses "Kyber.CPAPKE" internally
- Specific compression parameters
- Ciphertext: 1088 bytes

ML-KEM-768 (FIPS 203, ml-kem crate):
- Modified from Kyber during standardization
- Changes to:
  - Hash function domain separation
  - Seed handling in key generation
  - Ciphertext format (subtle differences)
- Ciphertext: 1088 bytes (same size, DIFFERENT content for same input)

THESE ARE NOT INTERCHANGEABLE.
encaps(kyber_pk) → kyber_ct   → decaps with kyber_sk ✅
encaps(kyber_pk) → kyber_ct   → decaps with ml_kem_sk ❌ FAIL
encaps(ml_kem_pk) → ml_kem_ct → decaps with kyber_sk ❌ FAIL
```

If the protocol has ANY existing deployments, keys, or stored data using liboqs Kyber-768, switching to ML-KEM is a **protocol-breaking change** that requires versioning.

#### 6.4 Migration Implementation

**If using `ml-kem` (no backward compat needed):**

```rust
// ============================================
// BEFORE (liboqs):
// ============================================
use oqs::kem::{Kem, Algorithm};

fn pq_keygen() -> (Vec<u8>, Vec<u8>) {
    let kem = Kem::new(Algorithm::Kyber768).unwrap();
    let (pk, sk) = kem.keypair().unwrap();
    (pk.into_vec(), sk.into_vec())
}

fn pq_encaps(pk: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let kem = Kem::new(Algorithm::Kyber768).unwrap();
    let pk = kem.public_key_from_bytes(pk).unwrap();
    let (ct, ss) = kem.encapsulate(&pk).unwrap();
    (ct.into_vec(), ss.into_vec())
}

fn pq_decaps(sk: &[u8], ct: &[u8]) -> Vec<u8> {
    let kem = Kem::new(Algorithm::Kyber768).unwrap();
    let sk = kem.secret_key_from_bytes(sk).unwrap();
    let ct = kem.ciphertext_from_bytes(ct).unwrap();
    kem.decapsulate(&sk, &ct).unwrap().into_vec()
}

// ============================================
// AFTER (ml-kem, pure Rust):
// ============================================
use ml_kem::{MlKem768, KemCore, Encoded};
use ml_kem::kem::{Encapsulate, Decapsulate};
use rand_core::OsRng;
use zeroize::Zeroizing;

/// ML-KEM-768 key sizes
pub const PQ_PUBLIC_KEY_SIZE: usize = 1184;
pub const PQ_SECRET_KEY_SIZE: usize = 2400;
pub const PQ_CIPHERTEXT_SIZE: usize = 1088;
pub const PQ_SHARED_SECRET_SIZE: usize = 32;

pub struct PqKeypair {
    pub public_key: [u8; PQ_PUBLIC_KEY_SIZE],
    secret_key: Zeroizing<[u8; PQ_SECRET_KEY_SIZE]>,  // Zeroize on drop!
}

impl PqKeypair {
    pub fn generate() -> Self {
        let (dk, ek) = MlKem768::generate(&mut OsRng);

        let mut public_key = [0u8; PQ_PUBLIC_KEY_SIZE];
        let mut secret_key = Zeroizing::new([0u8; PQ_SECRET_KEY_SIZE]);

        let ek_bytes = ek.as_bytes();
        let dk_bytes = dk.as_bytes();

        public_key.copy_from_slice(ek_bytes);
        secret_key.copy_from_slice(dk_bytes);

        Self { public_key, secret_key }
    }

    pub fn secret_key(&self) -> &[u8; PQ_SECRET_KEY_SIZE] {
        &self.secret_key
    }
}

pub struct PqEncapsulation {
    pub ciphertext: [u8; PQ_CIPHERTEXT_SIZE],
    pub shared_secret: Zeroizing<[u8; PQ_SHARED_SECRET_SIZE]>,
}

pub fn pq_encapsulate(
    public_key: &[u8; PQ_PUBLIC_KEY_SIZE],
) -> Result<PqEncapsulation, ProtocolError> {
    let ek = ml_kem::kem::EncapsulationKey::<MlKem768>::from_bytes(public_key.into());

    let (ct, ss) = ek.encapsulate(&mut OsRng)
        .map_err(|_| ProtocolError::PqEncapsulationFailed)?;

    let mut ciphertext = [0u8; PQ_CIPHERTEXT_SIZE];
    let mut shared_secret = Zeroizing::new([0u8; PQ_SHARED_SECRET_SIZE]);

    ciphertext.copy_from_slice(ct.as_bytes());
    shared_secret.copy_from_slice(ss.as_bytes());

    Ok(PqEncapsulation { ciphertext, shared_secret })
}

pub fn pq_decapsulate(
    secret_key: &[u8; PQ_SECRET_KEY_SIZE],
    ciphertext: &[u8; PQ_CIPHERTEXT_SIZE],
) -> Result<Zeroizing<[u8; PQ_SHARED_SECRET_SIZE]>, ProtocolError> {
    let dk = ml_kem::kem::DecapsulationKey::<MlKem768>::from_bytes(secret_key.into());
    let ct = ml_kem::Ciphertext::<MlKem768>::from_bytes(ciphertext.into());

    let ss = dk.decapsulate(&ct)
        .map_err(|_| ProtocolError::PqDecapsulationFailed)?;

    let mut shared_secret = Zeroizing::new([0u8; PQ_SHARED_SECRET_SIZE]);
    shared_secret.copy_from_slice(ss.as_bytes());

    Ok(shared_secret)
}

// CRITICAL: Debug must not leak PQ secret keys
impl fmt::Debug for PqKeypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PqKeypair")
            .field("public_key", &format!("MlKem768Pk({}...)", hex::encode(&self.public_key[..4])))
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}
```

**If using `pqc-kyber` (backward compat with liboqs):**

```rust
// ============================================
// AFTER (pqc-kyber, wire-compatible with liboqs):
// ============================================
use pqc_kyber::{keypair, encapsulate, decapsulate};
use pqc_kyber::{KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES,
                KYBER_CIPHERTEXTBYTES, KYBER_SSBYTES};
use zeroize::Zeroizing;

pub fn pq_keygen() -> Result<(
    [u8; KYBER_PUBLICKEYBYTES],          // 1184
    Zeroizing<[u8; KYBER_SECRETKEYBYTES]> // 2400, zeroized on drop
), ProtocolError> {
    let mut rng = rand_core::OsRng;
    let keys = keypair(&mut rng)
        .map_err(|_| ProtocolError::PqKeygenFailed)?;

    let mut sk = Zeroizing::new([0u8; KYBER_SECRETKEYBYTES]);
    sk.copy_from_slice(&keys.secret);

    Ok((keys.public, sk))
}

pub fn pq_encaps(
    pk: &[u8; KYBER_PUBLICKEYBYTES],
) -> Result<(
    [u8; KYBER_CIPHERTEXTBYTES],          // 1088
    Zeroizing<[u8; KYBER_SSBYTES]>        // 32, zeroized on drop
), ProtocolError> {
    let mut rng = rand_core::OsRng;
    let (ct, ss) = encapsulate(pk, &mut rng)
        .map_err(|_| ProtocolError::PqEncapsulationFailed)?;

    let mut shared = Zeroizing::new([0u8; KYBER_SSBYTES]);
    shared.copy_from_slice(&ss);

    Ok((ct, shared))
}

pub fn pq_decaps(
    sk: &[u8; KYBER_SECRETKEYBYTES],
    ct: &[u8; KYBER_CIPHERTEXTBYTES],
) -> Result<Zeroizing<[u8; KYBER_SSBYTES]>, ProtocolError> {
    let ss = decapsulate(ct, sk)
        .map_err(|_| ProtocolError::PqDecapsulationFailed)?;

    let mut shared = Zeroizing::new([0u8; KYBER_SSBYTES]);
    shared.copy_from_slice(&ss);

    Ok(shared)
}
```

#### 6.5 Hybrid Construction Verification

When migrating the PQ component, the hybrid KDF MUST remain identical:

```rust
// VERIFY this is how X25519 + Kyber/ML-KEM are currently combined:

fn hybrid_key_derivation(
    x25519_shared: &[u8; 32],
    pq_shared: &[u8; 32],     // Kyber/ML-KEM shared secret
    // Context binding — MUST include all of these:
    our_identity: &PublicKey,
    peer_identity: &PublicKey,
    our_ephemeral_pk: &[u8; 32],
    peer_ephemeral_pk: &[u8; 32],
    our_pq_pk: &[u8],          // PQ encapsulation key
    peer_pq_ct: &[u8],         // PQ ciphertext
) -> Result<SessionKeys, ProtocolError> {
    // Input keying material = X25519 ‖ PQ
    let mut ikm = Zeroizing::new([0u8; 64]);
    ikm[..32].copy_from_slice(x25519_shared);
    ikm[32..].copy_from_slice(pq_shared);

    // Salt / info MUST include identity binding
    // VERIFY: is this the exact construction currently used?
    let hkdf = Hkdf::<Sha256>::new(
        Some(transcript_hash),  // handshake transcript as salt
        &*ikm,
    );

    let mut session_key = Zeroizing::new([0u8; 32]);
    hkdf.expand(b"session-key-v1", &mut *session_key)
        .map_err(|_| ProtocolError::KdfFailed)?;

    // ikm is Zeroizing — auto-wiped here
    Ok(SessionKeys::from_bytes(&session_key)?)
}

// CRITICAL CHECKS:
// 1. Is x25519_shared ALWAYS first, pq_shared ALWAYS second? (Order matters for KDF!)
// 2. Is the same HKDF info/label string used? (Byte-identical!)
// 3. Is the transcript hash computed the same way?
// 4. If Kyber ciphertext is included in transcript — it changes with ML-KEM migration!
```

**DANGER**: If the handshake transcript includes the Kyber ciphertext bytes, and you switch from Kyber to ML-KEM, the transcript changes even for the "same" key exchange → session keys differ → protocol breaks silently (encryption works but peers derive different keys → auth fails).

#### 6.6 Compatibility Tests

```rust
#[cfg(test)]
mod pq_migration_tests {
    // Temporarily have BOTH deps:
    // [dev-dependencies]
    // oqs = "0.9"

    #[test]
    fn test_key_sizes_match() {
        // Verify the replacement crate uses identical sizes
        assert_eq!(REPLACEMENT_PK_SIZE, 1184, "PQ public key size mismatch!");
        assert_eq!(REPLACEMENT_SK_SIZE, 2400, "PQ secret key size mismatch!");
        assert_eq!(REPLACEMENT_CT_SIZE, 1088, "PQ ciphertext size mismatch!");
        assert_eq!(REPLACEMENT_SS_SIZE, 32,   "PQ shared secret size mismatch!");
    }

    /// ONLY valid if using pqc-kyber (not ml-kem):
    #[test]
    fn test_cross_encaps_decaps() {
        // Generate keypair with liboqs:
        let oqs_kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber768).unwrap();
        let (oqs_pk, oqs_sk) = oqs_kem.keypair().unwrap();

        // Encapsulate with new crate using liboqs public key:
        let (new_ct, new_ss) = pq_encaps(
            oqs_pk.as_ref().try_into().unwrap()
        ).unwrap();

        // Decapsulate with liboqs using new crate's ciphertext:
        let oqs_ct = oqs_kem.ciphertext_from_bytes(&new_ct).unwrap();
        let oqs_ss = oqs_kem.decapsulate(&oqs_sk, &oqs_ct).unwrap();

        // Shared secrets MUST be identical:
        assert_eq!(
            &*new_ss, oqs_ss.as_ref(),
            "SHARED SECRET MISMATCH — PQ migration breaks key agreement!"
        );
    }

    /// Reverse direction:
    #[test]
    fn test_cross_encaps_decaps_reverse() {
        // Generate keypair with new crate:
        let (new_pk, new_sk) = pq_keygen().unwrap();

        // Encapsulate with liboqs:
        let oqs_kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber768).unwrap();
        let oqs_pk = oqs_kem.public_key_from_bytes(&new_pk).unwrap();
        let (oqs_ct, oqs_ss) = oqs_kem.encapsulate(&oqs_pk).unwrap();

        // Decapsulate with new crate:
        let new_ss = pq_decaps(
            &*new_sk,
            oqs_ct.as_ref().try_into().unwrap(),
        ).unwrap();

        assert_eq!(
            &*new_ss, oqs_ss.as_ref(),
            "SHARED SECRET MISMATCH — reverse direction broken!"
        );
    }

    /// If using ml-kem (NOT wire-compatible), this test SHOULD FAIL:
    #[test]
    fn test_ml_kem_is_not_compatible_with_kyber() {
        // This test documents the incompatibility.
        // If you're using ml-kem, this test MUST fail,
        // confirming that protocol versioning is required.

        let oqs_kem = oqs::kem::Kem::new(oqs::kem::Algorithm::Kyber768).unwrap();
        let (oqs_pk, oqs_sk) = oqs_kem.keypair().unwrap();

        // Try to use ML-KEM encaps with Kyber public key:
        // This should either fail or produce different shared secret
        let result = ml_kem_encaps(oqs_pk.as_ref().try_into().unwrap());

        if let Ok((ct, ss)) = result {
            let oqs_ct = oqs_kem.ciphertext_from_bytes(&ct).unwrap();
            let oqs_ss = oqs_kem.decapsulate(&oqs_sk, &oqs_ct).unwrap();
            // This SHOULD NOT match:
            assert_ne!(
                &*ss, oqs_ss.as_ref(),
                "If this matches, ML-KEM and Kyber are unexpectedly compatible — investigate!"
            );
        }
        // Failure or mismatch = expected. ML-KEM ≠ Kyber.
    }

    /// Stress test: many encaps/decaps cycles to catch rare failures
    #[test]
    fn test_pq_roundtrip_stress() {
        for i in 0..1000 {
            let (pk, sk) = pq_keygen().unwrap();
            let (ct, ss_encaps) = pq_encaps(&pk).unwrap();
            let ss_decaps = pq_decaps(&*sk, &ct).unwrap();
            assert_eq!(
                &*ss_encaps, &*ss_decaps,
                "PQ roundtrip failed on iteration {i}"
            );
        }
    }
}
```

#### 6.7 PQ Secret Key Protection

liboqs stores Kyber secret keys in its own allocated memory. After migration, YOU must protect them:

```rust
// liboqs managed its own memory — after migration, verify:

// ✅ PQ secret keys behind Zeroizing or SecureMemoryHandle
// ✅ PQ shared secrets behind Zeroizing (they're intermediate — used once then discarded)
// ✅ PQ secret keys not in Debug output
// ✅ PQ secret keys not serialized via serde accidentally
// ✅ PQ secret keys wiped after decapsulation if no longer needed
// ✅ Temporary buffers in PQ operations (NTT intermediates, etc.) —
//    these are INSIDE the crate, verify the crate handles this
//    (pqc-kyber and ml-kem should zero intermediates, but verify)

// If SecureMemoryHandle is used for X25519 secret keys,
// PQ secret keys MUST have equivalent protection:
pub struct HybridKeypair {
    pub x25519: X25519Keypair,          // Already behind SecureMemoryHandle
    pub pq: PqKeypair,                  // MUST ALSO be behind SecureMemoryHandle
    // NOT this:
    // pub pq_sk: [u8; 2400],           // ← UNPROTECTED, NO!
}
```

#### 6.8 PQ-Specific Security Checks

After migration, verify the pure Rust PQ crate:

```
□ Constant-time NTT (Number Theoretic Transform)?
  - Variable-time NTT leaks secret key bits via cache timing
  - Check: does the crate use constant-time polynomial multiplication?

□ Ciphertext validation before decapsulation?
  - Decapsulating malformed ciphertext can leak sk in non-IND-CCA2 impls
  - Check: does the crate validate ct length and structure?

□ Implicit rejection?
  - On decapsulation failure, Kyber/ML-KEM should return a pseudorandom
    value derived from sk ‖ ct, NOT an error
  - This prevents chosen-ciphertext attacks
  - Check: does the crate implement implicit rejection per spec?

□ RNG quality in encapsulation?
  - Encapsulation randomness must come from CSPRNG
  - Check: does the crate accept a proper RngCore + CryptoRng?

□ No secret-dependent branching?
  - Run cargo-asm on hot functions, inspect for conditional jumps on secret data
  - Or: check if the crate has been tested with dudect/ctgrind
```

#### 6.9 Post-Migration Cargo.toml

```toml
# REMOVE:
# oqs = "..."           ← gone, no more CMake
# oqs-sys = "..."       ← gone, no more C compilation

# ADD (choose one):
ml-kem = { version = "0.2", features = ["std"] }     # If no backward compat needed
# OR
pqc-kyber = { version = "0.8", features = ["kyber768"] }  # If backward compat needed

# VERIFY after migration:
# cargo tree | grep cmake    → nothing
# cargo tree | grep -- "-sys" → no crypto sys crates
# cargo tree | grep "cc "    → no C compiler dependency for crypto
```

#### 6.10 Migration Risk Summary

```
Component          | Risk  | Reason
X25519 (sodium)    | LOW   | x25519-dalek is battle-tested, same curve
Ed25519 (sodium)   | LOW   | ed25519-dalek is battle-tested, same algorithm
AES-GCM-SIV       | MED   | Verify wire format, tag position
HMAC/Hash          | LOW   | Standard algorithms, easy to verify
SecureMemoryHandle | HIGH  | Must preserve 3 security properties
Kyber → ML-KEM     | 🔴 HIGH | Wire-incompatible, protocol versioning needed
Kyber → pqc-kyber  | MED   | Wire-compatible but less audited crate
Hybrid KDF         | 🔴 HIGH | If transcript includes PQ ciphertext, it changes
```

**The Kyber migration is the SINGLE HIGHEST RISK item in the entire migration. Do it last, test it most, and get explicit author approval on the Kyber vs ML-KEM decision before writing any code.**
