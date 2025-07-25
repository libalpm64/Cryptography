# ⚠️ Cryptography Disclaimer & Legal Notice
<img src="https://tokei.rs/b1/github/libalpm64/Cryptography?category=code&style=flat" alt="Lines of Code"/>


This project implements **deterministic password derivation using post-quantum cryptographic techniques**.  
It is intended for **educational, research, or personal use only**.

---

## 📜 Patent Infringement Notice

This software **does not intentionally violate any patents**.

It uses **third-party, publicly available libraries**—notably:
- **Kyber512** from [PQClean](https://github.com/PQClean/PQClean), accessed through the `pypqc` or `pqc` wrapper,
- And **cSHAKE256** from the `pycryptodome` package.

These libraries are released under public-domain or permissive open-source licenses and are widely used in academic and open-source cryptographic research.

> **If you believe this project infringes upon your intellectual property, please open an issue or contact the maintainer.**

---

## 🔒 Post-Quantum Password Hashing (Non-Commercial Use)

This repository includes a one-way, deterministic **post-quantum password derivation algorithm** using:
- `Kyber512` for key encapsulation
- `cSHAKE256` for domain-separated hashing

⚠️ **Not intended for commercial use. Use in production systems is discouraged** unless reviewed by a qualified cryptographic professional.

- This is an experimental proof-of-concept.
- No warranties are provided.
- Use at your own risk.

---

## ✅ Summary

- ✅ Educational and experimental only  
- ❌ Not for commercial or production use  
- 🔐 Focused on post-quantum password derivation  
- 📂 Uses public domain / open-source cryptographic libraries  
