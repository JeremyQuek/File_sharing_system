# Secured File Sharing System in Go

<div align="center">
  <img src="https://github.com/user-attachments/assets/dde6a9da-cd58-4b3c-9f6a-74f299ddf7b6" width="446" height="526" alt="Screenshot 2025-12-15 at 3 59 26 PM" />
</div>


## Project Overview
We wrote a secure, backend file sharing platform designed for multi-user access and robust data confidentiality. The system employs **end-to-end encryption** and a **stateless design** to protect data against unauthorized access and offline attacks, ensuring that no plain-text secrets are stored in the data store.

---

## Core Security & Cryptographic Mechanisms

**User Authentication**  
- **Password-Derived Keys**: Users are authenticated without storing passwords. Keys are derived from the password and a per-user salt using **Argon2** and **HKDF** (`deriveUserKeys`).  
- Successful decryption of the user's `UserStruct` (encrypted with these keys) confirms authentication.

**File Confidentiality**  
- **Symmetric Encryption**: Files are independent objects in the datastore, each encrypted with a **random file-specific key** (`deriveFileKeys`).  
- Uses **Encrypt-then-MAC** approach (`encryptThenMAC` / `verifyMACThenDecrypt`) to ensure confidentiality and integrity.

**Secure Sharing**  
- **Hybrid Encryption (`HybridInvStruct`)**: Invitations are encrypted using a hybrid scheme (`hybridEncrypt`).  
- File keys (`InvStruct`) are symmetrically encrypted, then **RSA-encrypted** with the recipient's public key.  
- Entire payloads are **digitally signed** with the sharer’s private key for authenticity.

**File Revocation**  
- **Key Rotation**: Revocation is performed by generating new file encryption and MAC keys.  
- All remaining valid file structures are re-encrypted, and new `HybridInvStruct`s are created for all non-revoked users, replacing the old ones.

---

## File Structure and Scalability

**File Data Partitioning**  
- File data is split into **Content** and **Access** sections.

**Content Section**  
- Stores actual file data as a **linked list of fixed-size chunks (4KB)**:  
  `FileContent → FileChunkMetadata → FileChunkContent`.

**Access Section**  
- Maintains a tree structure (`FileAccessNode`) to track sharing relationships.

**Efficient Append**  
- The linked-list structure ensures that appending requires downloading minimal structures (`UserStruct`, `FilePointers`, `FileStruct`, etc.).  
- Achieves **constant space complexity** per append, making bandwidth usage efficient regardless of file size or number of appends.

---

## Implementation Technologies

- **Core Language:** Go  
- **Cryptography:** Argon2, HKDF, AES-256 (`userlib.SymEnc`), HMAC, RSA Public-Key Encryption (`userlib.PKEEnc`), Digital Signatures (`userlib.DSSign`)

---

## GitHub Repository

> **Project Link:** [Your GitHub Repository](https://www.google.com/search?q=your_github_link%23readme)
