import os
import shutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def decrypt_file():
    print("\n[2] Decrypt Malware File")
    while True:
        # Get and validate file path
        file_path = input("[?] Path to encrypted file (or drag file here): ").strip(' "\'')
        file_path = os.path.abspath(os.path.normpath(file_path))
        
        print(f"\n[*] Checking: {file_path}")
        
        if not os.path.isfile(file_path):
            print(f"[!] ERROR: File not found at:")
            print(f"    Attempted path: {file_path}")
            print(f"    Current directory: {os.getcwd()}")
            
            # Show files in the target directory
            dir_path = os.path.dirname(file_path) or os.getcwd()
            print("\nFiles in that location:")
            for f in os.listdir(dir_path):
                print(f"- {f}")
            
            if input("\n[?] Try again? (y/n): ").lower() != 'y':
                return
            continue
        
        # Decryption process
        password = input("[?] Enter decryption password: ").strip()
        
        try:
            with open(file_path, "rb") as f:
                iv = f.read(16)
                salt = f.read(16)
                ciphertext = f.read()
            
            # Key derivation
            key = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            ).derive(password.encode())
            
            # AES decryption
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            decrypted = decrypted[:-decrypted[-1]]  # Remove padding
            
            # Save decrypted files
            output_folder = os.path.join(os.path.dirname(file_path), "decrypted_files")
            os.makedirs(output_folder, exist_ok=True)
            
            temp_zip = os.path.join(output_folder, "temp_decrypted.zip")
            with open(temp_zip, "wb") as f:
                f.write(decrypted)
            
            shutil.unpack_archive(temp_zip, output_folder, "zip")
            os.remove(temp_zip)
            
            print(f"\n[+] SUCCESS! Files saved to:\n{os.path.abspath(output_folder)}")
            print("[*] Contains:")
            for f in os.listdir(output_folder):
                print(f"- {f}")
            return
            
        except ValueError:
            print("\n[!] Wrong password or corrupted file!")
        except Exception as e:
            print(f"\n[!] Decryption failed: {str(e)}")
        
        if input("[?] Try again? (y/n): ").lower() != 'y':
            return

if __name__ == "__main__":
    decrypt_file()
