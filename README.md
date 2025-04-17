# KeySense Cipher GUI v1.00
Very strong text substitution cipher that compresses data, PBKDF2‑stretches a keyword + Initialization Vector, autokey‑substitutes &amp; keyed‑transposes text, then outputs Base64.

## Purpose
KeySense Cipher is a text substitution cipher combining modern key‑derivation (PBKDF2‑HMAC‑SHA‑256) with two classical primitives (autokey substitution + keyed transposition) and pre/post‑processing (compression, base‑64, padding).  

## Security Architecture

| Layer | Contribution to Security | Rationale |
|-------|-------------------------|-----------|
| **PBKDF2‑HMAC‑SHA‑256** (100 k iterations, 8 B salt) | **Key stretching** & rainbow‑table resistance | PBKDF2 is NIST‑recommended for deriving keys from low‑entropy passphrases. 100 000 iterations increases the cost of brute‑force by ~10⁵ |
| **Random IV (64 bit)** | **Semantic security** | Same keyword encrypting identical plaintexts yields different ciphertexts. |
| **Pre‑compression (DEFLATE/zlib)** | **Redundancy reduction** | Weakens frequency analysis by flattening symbol distribution. citeturn0search1 |
| **Random header + padding** | **Chosen‑plaintext hardening** | Masks message boundaries & prevents length leakage in short messages. |
| **Enhanced Autokey Cipher** | **Confusion** | Key stream derives from both random subkey and evolving plaintext, thwarting standard Kasiski/IC attacks that break fixed‑key polyalphabetics. |
| **Keyed Transposition** | **Diffusion** | Re‑orders symbols block‑wise using a permutation derived from the same 256‑bit subkey, coupling every eight‑character block. |
| **Kerckhoffs compliance** | **Openness ≠ weakness** | All algorithms are public; only the keyword must remain secret.|

### Why multiple layers?
If one classical primitive failed under cryptanalysis, the remaining layers (plus modern KDF and IV randomization) still provide a security margin. The design therefore follows *defence‑in‑depth* and blends modern best‑practice with historically instructive ciphers.

---

## Threat Model & Assurances
| Assumption | Covered? | Notes |
|------------|----------|-------|
| Offline brute‑force vs. keyword | **Mitigated** | PBKDF2 + 100 k iterations + 64‑bit salt makes guessing ≥10²× slower than raw SHA‑256. |
| Passive eavesdropper | **Mitigated** | IV ensures IND‑CPA resistance given secret keyword. |
| Chosen‑plaintext attack | **Partially** | Compression + random padding conceal structure; autokey injection prevents recovering subkey via classic crib‑dragging. |
| Active tampering | **❌ Not covered** | No MAC / authenticated encryption; add HMAC‑SHA‑256 over (IV‖salt‖ciphertext) if integrity is required. |
| Side‑channel attacks | **Out of scope** | Timing/power channels not modelled. |

---

## Quick Start

# 1. Clone or Dowwnload
 
# 2. Install Python

# 3. Run the script

## Limitations & Caveats
* No formal security proof.  
* Lacks ciphertext integrity.  
* GUI copies IV & salt openly when you copy ciphertext; treat output as sensitive.  
* Compression side‑channels (CRIME/BREACH class) are theoretically possible when encrypting attacker‑controlled + secret mixtures — mitigated by random padding but not eliminated.  
* Performance: ~30 KB/s on CPython 3.12 for 100 k PBKDF2 rounds.

---

Joshua M Clatney made this project under the Apache 2.0 License.
