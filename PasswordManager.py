import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from getpass import getpass

import pickle


def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_password(password, key):
    f = Fernet(key)
    encrypted_password = f.encrypt(password.encode())
    return encrypted_password


def decrypt_password(encrypted_password, key):
    f = Fernet(key)
    decrypted_password = f.decrypt(encrypted_password).decode()
    return decrypted_password


def save_passwords(passwords, key):
    encrypted_data = Fernet(key).encrypt(pickle.dumps(passwords))
    
    with open('passwords.bin', 'wb') as f:
        f.write(encrypted_data)


def create_master_password():
    password = getpass("Créez un mot de passe maître : ")
    confirm_password = getpass("Confirmez le mot de passe maître : ")

    if password == confirm_password:
        salt = os.urandom(16)
        with open('salt.bin', 'wb') as f:
            f.write(salt)
        return password, salt
    else:
        print("Les mots de passe ne correspondent pas. Veuillez réessayer.")
        return create_master_password()


def load_passwords(key):
    if not os.path.exists("passwords.bin"):
        return {}

    with open("passwords.bin", "rb") as f:
        encrypted_data = f.read()

    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)
    passwords = pickle.loads(decrypted_data)
    return passwords


def verify_master_password(master_password, salt):
    key = generate_key(master_password, salt)
    passwords = load_passwords(key)

    if not passwords:
        return True

    site, encrypted_password = next(iter(passwords.items()))

    try:
        decrypt_password(encrypted_password, key)
        return True
    except:
        return False
