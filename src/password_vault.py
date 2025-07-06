# Refactored version of password_vault.py with requested improvements

import os
import json
import hashlib
import random
import string
import requests
import hmac
import base64
from base64 import urlsafe_b64encode
from stegano import lsb
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet, InvalidToken
from PIL import Image
from io import BytesIO

# ========== CONSTANTS ==========
ITERATIONS = 200_000
SALT_FILE = "lost_kitties.bin"
STRINGS = {
    "download_fail": "[!] Failed to download a valid image: {}",
    "index_load_fail": "[!] Failed to load index: {}",
    "index_save_fail": "[!] Failed to save index: {}",
    "master_setup_fail": "[!] Failed to download valid images for master password setup.",
    "meta_setup_fail": "[!] Failed to download valid images for vault metadata.",
    "pass_store_fail": "[!] Failed to hide password in image: {}",
    "pass_image_fail": "[!] Could not get a valid image to store the password.",
    "verify_fail": "[!] Verification failed.",
    "decrypt_fail": "[!] Decryption failed for service: {}"
}

# ========== PATH MANAGEMENT ==========
def get_paths(image_dir):
    os.makedirs(image_dir, exist_ok=True)
    return {
        "image_dir": image_dir,
        "meta_image": os.path.join(image_dir, "best_cat_ever.png"),
        "meta_key_image": os.path.join(image_dir, "my_favorite_kitty.png"),
        "index_file": os.path.join(image_dir, "my_kitties.json"),
        "salt_file": os.path.join(image_dir, SALT_FILE),
    }

# ========== UTILS ==========
def generate_random_meme_name():
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=10)) + ".png"

_downloaded_cache = set()

def download_random_cat_image(paths, retries=3):
    url = "https://cataas.com/cat"
    for _ in range(retries):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            content_hash = hashlib.sha256(response.content).hexdigest()
            if content_hash in _downloaded_cache:
                continue
            _downloaded_cache.add(content_hash)
            img = Image.open(BytesIO(response.content)).convert("RGB")
            filename = os.path.join(paths["image_dir"], generate_random_meme_name())
            img.save(filename, format="PNG")
            return filename
        except Exception as e:
            print(STRINGS["download_fail"].format(e))
    return None

# ========== SALT HANDLING ==========
def get_or_create_salt(paths):
    salt_path = paths["salt_file"]
    if os.path.exists(salt_path):
        with open(salt_path, "rb") as f:
            return f.read()
    salt = os.urandom(16)
    with open(salt_path, "wb") as f:
        f.write(salt)
    return salt

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

def get_fernet_key(paths):
    salt = get_or_create_salt(paths)
    return derive_key("vault_index_encryption_key", salt)

# ========== HMAC VALIDATION ==========
def add_hmac(data: bytes, key: bytes) -> str:
    digest = hmac.new(key, data, hashlib.sha256).digest()
    return base64.b64encode(digest + data).decode()

def verify_hmac(payload: str, key: bytes) -> bytes:
    decoded = base64.b64decode(payload.encode())
    received_hmac = decoded[:32]
    data = decoded[32:]
    expected_hmac = hmac.new(key, data, hashlib.sha256).digest()
    if hmac.compare_digest(received_hmac, expected_hmac):
        return data
    raise InvalidToken

# ========== INDEX ==========
def load_index(paths):
    try:
        if os.path.exists(paths["index_file"]):
            with open(paths["index_file"], 'r') as f:
                encrypted = f.read()
                key = get_fernet_key(paths)
                decrypted = verify_hmac(encrypted, key)
                return json.loads(Fernet(key).decrypt(decrypted).decode())
    except Exception as e:
        print(STRINGS["index_load_fail"].format(e))
    return {}

def save_index(index, paths):
    try:
        key = get_fernet_key(paths)
        encrypted = Fernet(key).encrypt(json.dumps(index).encode())
        payload = add_hmac(encrypted, key)
        with open(paths["index_file"], 'w') as f:
            f.write(payload)
    except Exception as e:
        print(STRINGS["index_save_fail"].format(e))

# ========== MASTER PASSWORD ==========
def create_master_password(password: str, paths):
    salt = os.urandom(16)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS)
    payload = salt.hex() + ":" + hash_bytes.hex()
    half = len(payload) // 2

    img1 = download_random_cat_image(paths)
    img2 = download_random_cat_image(paths)
    if not img1 or not img2:
        print(STRINGS["master_setup_fail"])
        return

    lsb.hide(img1, payload[:half]).save(img1)
    lsb.hide(img2, payload[half:]).save(img2)

    meta_data = json.dumps({"part1": img1, "part2": img2})
    temp_key = Fernet.generate_key()
    fernet = Fernet(temp_key)
    encrypted_meta = fernet.encrypt(meta_data.encode())

    meta_key_img = download_random_cat_image(paths)
    meta_img = download_random_cat_image(paths)
    if not meta_key_img or not meta_img:
        print(STRINGS["meta_setup_fail"])
        return

    lsb.hide(meta_key_img, temp_key.decode()).save(paths["meta_key_image"])
    lsb.hide(meta_img, encrypted_meta.decode()).save(paths["meta_image"])
    print("[+] Master password setup complete.")

def verify_master_password(input_pw: str, paths) -> tuple:
    if not os.path.exists(paths["meta_image"]) or not os.path.exists(paths["meta_key_image"]):
        return False, None

    try:
        temp_key_data = lsb.reveal(paths["meta_key_image"])
        if not temp_key_data:
            return False, None
        temp_key = temp_key_data.encode()
        fernet = Fernet(temp_key)

        encrypted_meta = lsb.reveal(paths["meta_image"])
        if not encrypted_meta:
            return False, None
        decrypted_meta = fernet.decrypt(encrypted_meta.encode()).decode()
        paths_meta = json.loads(decrypted_meta)
    except:
        print(STRINGS["verify_fail"])
        return False, None

    try:
        part1 = lsb.reveal(paths_meta["part1"])
        part2 = lsb.reveal(paths_meta["part2"])
        if not part1 or not part2:
            return False, None
        payload = part1 + part2
        salt_hex, stored_hash_hex = payload.split(":")
        salt = bytes.fromhex(salt_hex)
        stored_hash = bytes.fromhex(stored_hash_hex)
        input_hash = hashlib.pbkdf2_hmac('sha256', input_pw.encode(), salt, ITERATIONS)
        if input_hash == stored_hash:
            return True, derive_key(input_pw, salt)
    except:
        print(STRINGS["verify_fail"])
    return False, None

# ========== ENCRYPTION / DECRYPTION ==========
def encrypt_and_hide(service: str, plaintext_pw: str, fernet: Fernet, paths) -> str:
    service = service.strip().lower()
    index = load_index(paths)

    if service in index:
        return "exists"

    encrypted_pw = fernet.encrypt(plaintext_pw.encode())
    encrypted_pw_hmac = add_hmac(encrypted_pw, fernet._signing_key)
    image_path = download_random_cat_image(paths)
    if not image_path:
        print(STRINGS["pass_image_fail"])
        return
    try:
        lsb.hide(image_path, encrypted_pw_hmac).save(image_path)
        index[service] = image_path
        save_index(index, paths)
        return "saved"
    except Exception as e:
        print(STRINGS["pass_store_fail"].format(e))
        return "error"

def reveal_and_decrypt(service: str, fernet: Fernet, paths):
    service = service.strip().lower()
    index = load_index(paths)
    if service in index and os.path.exists(index[service]):
        try:
            hidden = lsb.reveal(index[service])
            if hidden:
                payload = verify_hmac(hidden, fernet._signing_key)
                decrypted = fernet.decrypt(payload).decode()
                print(f"[🔐] Password for '{service}': {decrypted}")
                return decrypted
        except Exception:
            print(STRINGS["decrypt_fail"].format(service))
    return None

def list_services(paths):
    index = load_index(paths)
    return sorted(index.keys()) if index else []

def delete_service(service: str, paths):
    service = service.strip().lower()
    index = load_index(paths)
    if service in index:
        try:
            os.remove(index[service])
        except:
            pass
        del index[service]
        save_index(index, paths)
        return True
    return False
