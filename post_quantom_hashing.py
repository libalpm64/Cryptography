"""
Deterministic Post-Quantum Password Derivation using Kyber512 and cSHAKE256

This script generates a deterministic, cryptographically strong password from an alias,
by combining a Kyber512 public/private keypair with the alias, then deriving a unique
password using the cSHAKE256 hash function.

- Key Generation: Uses the Kyber512 post-quantum KEM (from PQClean / pypqc)
- Hashing: Uses cSHAKE256 (customizable SHAKE256) from PyCryptodome
- Output: A 256-bit password (hex encoded), deterministically derived per alias
- Security: Combines private key, public key, and user input (alias) to derive secrets

Dependencies:
- `pypqc` or `pqc` with `kyber512` (for PQC keypair)
- `pycryptodome` (for cSHAKE256)

(Included in the report)
"""

import os
from Crypto.Hash import cSHAKE256
from pqc.kem import kyber512

PK_FILE = "kyber_pk.bin"
SK_FILE = "kyber_sk.bin"

def save_bytes(path: str, data: bytes):
    """Save binary data to a file."""
    with open(path, "wb") as f:
        f.write(data)

def load_bytes(path: str) -> bytes:
    """Load binary data from a file."""
    return open(path, "rb").read()

def ensure_keypair():
    """
    Ensure a Kyber512 keypair exists.
    If not found, generate and store them.
    Returns:
        pk (bytes): Public key
        sk (bytes): Secret (private) key
    """
    if not (os.path.exists(SK_FILE) and os.path.exists(PK_FILE)):
        print("Generating & saving Kyber keypair")
        pk, sk = kyber512.keypair()
        save_bytes(PK_FILE, pk)
        save_bytes(SK_FILE, sk)
    else:
        pk = load_bytes(PK_FILE)
        sk = load_bytes(SK_FILE)
    return pk, sk

def derive_password(alias: str, pk: bytes, sk: bytes) -> str:
    """
    Derive a deterministic 256-bit password based on alias and keypair.
    
    Steps:
    1. Create a 256-bit seed from (sk + pk + alias) using cSHAKE256 with custom tag 'SeedDerive'.
    2. Stretch the seed and alias into a 256-bit password using cSHAKE256 with tag 'PwdDerive'.

    Args:
        alias (str): User-defined alias (e.g., service name)
        pk (bytes): Public key
        sk (bytes): Secret key

    Returns:
        str: Hex-encoded password
    """

    seed = cSHAKE256.new(data=sk + pk + alias.encode(), custom=b"SeedDerive").read(32)
    pwd = cSHAKE256.new(data=seed + alias.encode(), custom=b"PwdDerive").read(32)
    return pwd.hex()

if __name__ == "__main__":
    pk, sk = ensure_keypair()
    alias = input("Enter alias: ")
    pwd = derive_password(alias, pk, sk)
    
    # Display the password
    print("\nPQ Password (hex):", pwd)
