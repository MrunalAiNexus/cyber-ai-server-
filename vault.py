from cryptography.fernet import Fernet
import os, json

VAULT_FILE = "credentials.json"
KEY_FILE = "vault.key"

# ------------------ KEY GENERATION ------------------
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    else:
        with open(KEY_FILE, "rb") as f:
            key = f.read()
    return Fernet(key)

cipher = load_key()

# ------------------ ENCRYPT PASSWORD ------------------
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

# ------------------ SAVE PASSWORD ------------------
def save_password(service, username, password):
    encrypted = encrypt_password(password)

    data = load_vault()
    data.append({"service": service, "username": username, "password": encrypted})
    with open(VAULT_FILE, "w") as f:
        json.dump(data, f, indent=2)
    return True

# ------------------ READ PASSWORDS ------------------
def load_vault():
    if not os.path.exists(VAULT_FILE):
        return []
    return json.load(open(VAULT_FILE, "r"))

# ------------------ DECRYPT PASSWORD ------------------
def decrypt_password(enc_text):
    return cipher.decrypt(enc_text.encode()).decode()
