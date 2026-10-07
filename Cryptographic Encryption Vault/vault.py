from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets, json, os, shutil, zipfile, tempfile

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

BASE = Path(__file__).resolve().parent
VAULTS = BASE / "vaults"
RESTORED = BASE / "restored"
VAULTS.mkdir(exist_ok=True)
RESTORED.mkdir(exist_ok=True)

MAGIC = b"CEV1"
ITERATIONS = 600_000

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS
    )
    return kdf.derive(password.encode("utf-8"))

def encrypt_file(src, dst, key):
    data = src.read_bytes()
    nonce = secrets.token_bytes(12)
    encrypted = AESGCM(key).encrypt(nonce, data, None)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(MAGIC + nonce + encrypted)

def decrypt_file(src, dst, key):
    raw = src.read_bytes()
    if len(raw) < 29 or raw[:4] != MAGIC:
        raise ValueError(f"Invalid encrypted file: {src.name}")
    nonce = raw[4:16]
    plaintext = AESGCM(key).decrypt(nonce, raw[16:], None)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(plaintext)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    files = request.files.getlist("files")
    password = request.form.get("password", "")
    vault_name = request.form.get("vault_name", "my_vault").strip()

    if not files or not any(f.filename for f in files):
        flash("Please select files or a folder.", "error")
        return redirect(url_for("index"))
    if len(password) < 8:
        flash("Master password must contain at least 8 characters.", "error")
        return redirect(url_for("index"))

    vault_dir = VAULTS / vault_name
    if vault_dir.exists():
        shutil.rmtree(vault_dir)
    vault_dir.mkdir(parents=True)

    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    count = 0

    for uploaded in files:
        if not uploaded.filename:
            continue
        relative = Path(uploaded.filename)
        # Prevent path traversal while retaining subdirectories.
        relative = Path(*[p for p in relative.parts if p not in ("", ".", "..")])
        if not relative.parts:
            continue

        temp = vault_dir / "_input" / relative
        temp.parent.mkdir(parents=True, exist_ok=True)
        uploaded.save(temp)

        encrypted_path = vault_dir / "encrypted" / (str(relative) + ".enc")
        encrypt_file(temp, encrypted_path, key)
        count += 1

    shutil.rmtree(vault_dir / "_input", ignore_errors=True)

    metadata = {
        "version": 1,
        "algorithm": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "iterations": ITERATIONS,
        "salt": salt.hex(),
        "files_encrypted": count
    }
    (vault_dir / "metadata.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    # Backup contains the salt and parameters, not the password/key.
    backup = vault_dir / "key_backup.json"
    backup.write_text(json.dumps({
        "vault": vault_name,
        "algorithm": metadata["algorithm"],
        "kdf": metadata["kdf"],
        "iterations": ITERATIONS,
        "salt": salt.hex(),
        "note": "This backup does NOT contain the master password or plaintext encryption key."
    }, indent=2), encoding="utf-8")

    zip_path = BASE / f"{vault_name}_encrypted_vault.zip"
    if zip_path.exists():
        zip_path.unlink()
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for p in vault_dir.rglob("*"):
            if p.is_file():
                z.write(p, p.relative_to(vault_dir))

    shutil.rmtree(vault_dir)
    flash(f"Success: {count} file(s) encrypted. Download the vault ZIP below.", "success")
    return render_template("index.html", download_name=zip_path.name)

@app.route("/download/<name>")
def download(name):
    safe = Path(name).name
    path = BASE / safe
    if not path.exists() or path.suffix.lower() != ".zip":
        return "File not found", 404
    return send_file(path, as_attachment=True)

@app.route("/decrypt", methods=["POST"])
def decrypt():
    vault_file = request.files.get("vault")
    password = request.form.get("decrypt_password", "")
    if not vault_file or not vault_file.filename:
        flash("Please select an encrypted vault ZIP.", "error")
        return redirect(url_for("index"))
    if not password:
        flash("Enter the master password.", "error")
        return redirect(url_for("index"))

    work = Path(tempfile.mkdtemp(prefix="cev_"))
    zip_path = work / "vault.zip"
    vault_file.save(zip_path)

    try:
        with zipfile.ZipFile(zip_path, "r") as z:
            z.extractall(work / "vault")

        vault_dir = work / "vault"
        metadata = json.loads((vault_dir / "metadata.json").read_text(encoding="utf-8"))
        salt = bytes.fromhex(metadata["salt"])
        key = derive_key(password, salt)

        output = RESTORED / Path(vault_file.filename).stem.replace("_encrypted_vault", "")
        if output.exists():
            shutil.rmtree(output)
        output.mkdir(parents=True)

        count = 0
        for enc in (vault_dir / "encrypted").rglob("*.enc"):
            relative = enc.relative_to(vault_dir / "encrypted")
            original_name = Path(str(relative)[:-4])
            decrypt_file(enc, output / original_name, key)
            count += 1

        shutil.make_archive(str(output), "zip", output)
        flash(f"Restoration successful: {count} file(s) decrypted.", "success")
        return send_file(str(output) + ".zip", as_attachment=True,
                         download_name=output.name + "_restored.zip")
    except Exception:
        flash("Decryption failed. Check the password and vault file.", "error")
        return redirect(url_for("index"))
    finally:
        shutil.rmtree(work, ignore_errors=True)

if __name__ == "__main__":
    app.run(debug=True)
