# Quantum–Classical Hybrid Encryption Framework (BB84 + AES-256)

## Overview
This repository contains a hybrid encryption system combining a simulated BB84 quantum key distribution (QKD) protocol with AES-256 encryption and HMAC-SHA256 integrity protection.

This implementation was developed as part of a Master's thesis in Cybersecurity Engineering.
## Research Position
This work is based on a previously published baseline implementation by:

H. E. Mozo (2025)
H. E. Mozo (2025), arXiv:2511.02836

The original framework was publicly released for transparency, reproducibility, and research extension.
## Contribution of This Work
This repository represents a **replication-and-extension study**, not a from-scratch cryptographic system.

The following enhancements were developed:

- QBER-based disturbance detection and abort control  
- Enhanced key-quality evaluation (ones ratio, Shannon entropy, min-entropy)  
- Secure key vault mechanism for improved key management  
- Structured experimental evaluation and reporting  

## Important Academic Note
This repository does NOT claim authorship of the original baseline implementation.

All original design credit belongs to the original author.  
This work focuses on extending, evaluating, and improving the baseline system.

## Acknowledgment
Based on:

H. E. Mozo (2025),  
“Quantum-classical hybrid encryption framework based on simulated BB84 and AES-256.”
## Technology Stack
- Python  
- BB84 Simulation  
- AES-256 (CBC mode)  
- PBKDF2  
- HMAC-SHA256  
## Purpose
This repository is intended for:
- academic research  
- experimental validation  
- demonstration of hybrid quantum-classical cryptographic workflows  

---

## Disclaimer
This is a research prototype and not intended for production-level security deployment.
