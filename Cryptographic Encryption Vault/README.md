# Cryptographic Encryption Vault

A Flask web application for encrypting and restoring multiple files using AES-256-GCM.

## Features
- Multi-file upload
- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA256 key derivation
- Random salt and nonce
- Directory/file structure preservation
- Key parameter backup
- Full restoration

## Run on Windows PowerShell

```powershell
cd "Cryptographic Encryption Vault"
python -m venv venv
venv\Scripts\activate
python -m pip install -r requirements.txt
python vault.py
```

Open http://127.0.0.1:5000

## Security note
The master passphrase is never written to disk. The key backup stores the salt and KDF parameters required to derive the key, not the passphrase or plaintext key.
