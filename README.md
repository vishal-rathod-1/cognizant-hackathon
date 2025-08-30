# CipherKeep UI (Flask + AES-256-GCM + PBKDF2)

A clean Flask app with a modern dark UI to store PII encrypted with AES‑256‑GCM. The AES key is derived from your password + salt using PBKDF2‑HMAC‑SHA256. Only ciphertext (and nonces) are stored in SQLite.

## Quick start
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

# CipherKeep — User Workflow

- Register
  - Enter username & password
  - Account is created

- Login
  - Enter username & password
  - If correct → access granted

- Add PII
  - Fill form (Name, Email, Phone, Address)
  - Click Encrypt & Save

- View PII
  - Go to My PII page
  - See decrypted personal info
  - See ciphertext preview (proof of encryption at rest)

- Change Password (optional)
  - Enter old password + new password
  - All PII is re-encrypted with the new key

- Logout
  - End session
  - Must log in again to access data

## Notes
- Login hash: SHA‑256(auth_salt || password) stored base64.
- Key derivation: PBKDF2‑HMAC‑SHA256(password, kdf_salt, iters=310k) → 32 bytes.
- AES: AES‑256‑GCM with a fresh 12‑byte nonce per encryption.
- Change Password: re‑encrypts all your PII with a new key (nonces rotated).
