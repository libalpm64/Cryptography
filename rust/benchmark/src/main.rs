use blake3;
use xxhash_rust::xxh3::xxh3_64;
use argon2::Argon2;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::time::{Duration, Instant};

/*
==========================================================
 Hash Function Overview
==========================================================

- BLAKE3:
    • A fast, general-purpose cryptographic hash function.
    • Commonly used for file integrity verification, checksums, and content-addressed storage
      (e.g., backup tools, distributed storage systems).

- XXHash3:
    • Extremely fast, non-cryptographic hash function.
    • Ideal for scenarios where speed is critical but cryptographic security is not required,
      such as file stream validation, database sharding, deduplication, and hash tables.
    • Note: While BitTorrent uses SHA1, XXHash3 is a modern alternative for non-cryptographic use cases.

- Argon2:
    • A secure, memory-hard password hashing algorithm.
    • Designed for safely storing user passwords, password managers, and key derivation for encryption.
    • Resistant to GPU and ASIC attacks.

- PBKDF2:
    • A cryptographically secure key derivation function (KDF).
    • Widely used for password hashing and key derivation, especially in systems requiring FIPS 140-2 compliance.
    • Auditor-resistant and suitable for regulated environments.

==========================================================
*/

fn benchmark_blake3(data: &[u8], duration: Duration) -> (u64, f64) {
    let mut count = 0u64;
    let start = Instant::now();
    while start.elapsed() < duration {
        let _hash = blake3::hash(data);
        count += 1;
    }
    let elapsed = start.elapsed().as_secs_f64();
    (count, count as f64 / elapsed)
}

fn benchmark_xxh3(data: &[u8], duration: Duration) -> (u64, f64) {
    let mut count = 0u64;
    let start = Instant::now();
    while start.elapsed() < duration {
        let _hash = xxh3_64(data);
        count += 1;
    }
    let elapsed = start.elapsed().as_secs_f64();
    (count, count as f64 / elapsed)
}

/*
 * ---------------------------------------------------------------
 *  Argon2 (Password Hashing Algorithm)
 * ---------------------------------------------------------------
 *  - Usage: Designed for secure password hashing and key derivation.
 *  - Security: Resistant to GPU and ASIC attacks; memory-hard and computationally intensive.
 *  - Parameters: Using default Argon2 parameters for benchmarking purposes.
 *  - Salt: Fixed salt is used here for consistent benchmarking results.
 *    (In production, always use a unique, random salt for each password.)
 * ---------------------------------------------------------------
*/
fn benchmark_argon2(data: &[u8], duration: Duration) -> (u64, f64) {
    let mut count = 0u64;
    let start = Instant::now();
    let salt = b"fixedsalt123456";
    let argon2 = Argon2::default();
    while start.elapsed() < duration {
        let mut output = [0u8; 32];
        // This is a blocking, expensive call: hashes the data using Argon2
        argon2.hash_password_into(data, salt, &mut output).unwrap();
        count += 1;
    }
    let elapsed = start.elapsed().as_secs_f64();
    (count, count as f64 / elapsed)
}
/*
 * ---------------------------------------------------------------
 *  PBKDF2 (Password-Based Key Derivation Function 2)
 * ---------------------------------------------------------------
 *  - Number of iterations: Using a reduced value (10,000) for benchmarking.
 *  - Security: More iterations increase security, but also slow down hashing.
 *    (More iterations = more entropy = more secure = slower performance.)
 *  - 10,000 iterations is a reasonable default for benchmarks, but you may
 *    need to increase/decrease this for production or FIPS compliance.
 *  - Compliance: PBKDF2 is the only KDF in this benchmark that is
 *    FIPS 140-2 compliant. (Argon2, BLAKE3, and XXHash3 are NOT FIPS compliant.)
 * ---------------------------------------------------------------
 */

fn benchmark_pbkdf2(data: &[u8], duration: Duration) -> (u64, f64) {
    let mut count = 0u64;
    let start = Instant::now();
    let salt = b"benchmarksalt";

    let iterations = 10_000;
    
    while start.elapsed() < duration {
        let mut output = [0u8; 32];
        pbkdf2_hmac::<Sha256>(data, salt, iterations, &mut output);
        count += 1;
    }
    let elapsed = start.elapsed().as_secs_f64();
    (count, count as f64 / elapsed)
}

fn main() {
    /*
     * ---------------------------------------------------------------
     *  Data: Example BIP39 Mnemonic Phrase
     * ---------------------------------------------------------------
     *  - This is a sample mnemonic phrase, commonly used in crypto wallets.
     *  - BIP39 (Bitcoin Improvement Proposal 39) defines a standard for
     *    generating deterministic mnemonic phrases from random data.
     *  - Mnemonic phrases are human-readable representations of entropy,
     *    used to derive deterministic private keys and, subsequently, public keys.
     *  - For more information or to generate your own mnemonic, visit:
     *      https://iancoleman.io/bip39/
     * ---------------------------------------------------------------
     */
    let data = b"position critic cloud first film anger matrix ice happy";
    let duration = Duration::from_secs(5);
    
    println!("Running benchmarks for {}s each...", duration.as_secs());
    
    let (count_blake3, speed_blake3) = benchmark_blake3(data, duration);
    println!("BLAKE3:");
    println!("  Total hashes: {}", count_blake3);
    println!("  Hashes per second: {:.2}", speed_blake3);
    
    let (count_xxh3, speed_xxh3) = benchmark_xxh3(data, duration);
    println!("XXHash3:");
    println!("  Total hashes: {}", count_xxh3);
    println!("  Hashes per second: {:.2}", speed_xxh3);
    
    println!("Running PBKDF2 benchmark...");
    let (count_pbkdf2, speed_pbkdf2) = benchmark_pbkdf2(data, duration);
    println!("PBKDF2 (SHA-256, 10,000 iterations):");
    println!("  Total hashes: {}", count_pbkdf2);
    println!("  Hashes per second: {:.5}", speed_pbkdf2);
    
    println!("Running Argon2 benchmark...");
    let (count_argon2, speed_argon2) = benchmark_argon2(data, duration);
    println!("Argon2:");
    println!("  Total hashes: {}", count_argon2);
    println!("  Hashes per second: {:.5}", speed_argon2);

}