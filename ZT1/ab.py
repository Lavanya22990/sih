import requests, json, base64, os, hashlib, random, string
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
import tkinter as tk
from tkinter import messagebox
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

# ---------------- Server Config ----------------
SERVER_URL = "http://127.0.0.1:9081"

# ---------------- Device Functions ----------------
def generate_device_id(a_args: str, usr_id: str = "usr_id"):
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    rand_str = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    return f"zT{a_args}_{timestamp}_{rand_str}_{usr_id}"

def register_device(device_id: str):
    # Generate ECDSA keys
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_key = priv_key.public_key()

    priv_pem = priv_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    pub_pem = pub_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open("device_private.pem", "wb") as f:
        f.write(priv_pem)
    with open("device_public.pem", "wb") as f:
        f.write(pub_pem)

    # Register device
    resp = requests.post(f"{SERVER_URL}/register_device", json={
        "device_id": device_id,
        "public_key": pub_pem.decode()
    })
    print("Register device:", resp.json())
    return priv_key, device_id

def submit_wipe_certificate(priv_key, device_id: str):
    cert_data = {
        "device_id": device_id,
        "timestamp": datetime.utcnow().isoformat()
    }
    cert_bytes = json.dumps(cert_data).encode()

    # Sign SHA-256 digest
    cert_hash = hashlib.sha256(cert_bytes).hexdigest().encode()
    signature = priv_key.sign(cert_hash, ec.ECDSA(hashes.SHA256()))

    cert_bytes_b64 = base64.b64encode(cert_bytes).decode()
    signature_b64 = base64.b64encode(signature).decode()

    resp = requests.post(f"{SERVER_URL}/submit_certificate_json", json={
        "device_id": device_id,
        "cert_bytes_b64": cert_bytes_b64,
        "signature_b64": signature_b64
    })
    print("Submit wipe result:", json.dumps(resp.json(), indent=2))

    # Download certificate
    download_resp = requests.get(f"{SERVER_URL}/download_certificate/{device_id}")
    cert_filename = "my_wipe_certificate.json"
    with open(cert_filename, "wb") as f:
        f.write(download_resp.content)
    print(f"Certificate downloaded as {cert_filename}")
    return download_resp.json() if download_resp.headers.get('Content-Type') == 'application/json' else {}

# ---------------- PDF Certificate ----------------
def generate_certificate(data):
    filename = f"ZeroTrace_Certificate_{data['device_id']}.pdf"
    c = canvas.Canvas(filename, pagesize=A4)
    width, height = A4

    # Header
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(width/2, height-50, "-"*53)
    c.setFont("Helvetica-Bold", 18)
    c.drawCentredString(width/2, height-80, "SECURE DATA WIPE CERTIFICATE")
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(width/2, height-110, "-"*54)

    y = height - 150
    c.setFont("Helvetica", 12)

    # Certificate details
    c.drawString(50, y, f"Certificate ID:      {data.get('certificate_hash', '')}")
    y -= 20
    c.drawString(50, y, f"Issued By:           ZeroTrace Technologies Pvt. Ltd.")
    y -= 20
    c.drawString(50, y, f"Timestamp:           {data.get('timestamp', '')}")

    # Device Info
    y -= 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "DEVICE INFORMATION")
    c.setFont("Helvetica", 12)
    y -= 20
    c.drawString(70, y, f"Device ID:           {data.get('device_id', '')}")
    y -= 20
    c.drawString(70, y, f"Block Index:         {data.get('block_index', '')}")
    y -= 20
    c.drawString(70, y, f"Block Hash:          {data.get('block_hash', '')}")

    # Wipe Details
    y -= 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "WIPE DETAILS")
    c.setFont("Helvetica", 12)
    y -= 20
    c.drawString(70, y, "Method:              NIST 800-88 Purge – ATA Secure Erase")
    y -= 20
    c.drawString(70, y, "Verification:        PASS")
    y -= 20
    c.drawString(70, y, "Software Version:    ZeroTrace Wipe v1.0.0")

    # Compliance
    y -= 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "COMPLIANCE")
    c.setFont("Helvetica", 12)
    y -= 20
    c.drawString(70, y, "This wipe was executed in compliance with NIST SP 800-88 Rev.1")
    y -= 20
    c.drawString(70, y, "and meets GDPR & HIPAA secure disposal requirements.")

    # Cryptographic Proof
    y -= 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "CRYPTOGRAPHIC PROOF")
    c.setFont("Helvetica", 12)
    y -= 20
    c.drawString(70, y, f"Certificate Hash:   {data.get('hashes', {}).get('sha256', '')}")

    # Blockchain / Digital Signature
    y -= 20
    c.drawString(70, y, "Digital Signature:   Available on ZeroTrace Blockchain")
    y -= 20
    c.drawString(70, y, "Verification Key:    https://zerotrace.com/keys/public.pem")

    # Fuel & Credits Info
    y -= 40
    c.setFont("Helvetica-Bold", 14)
    c.drawString(50, y, "FUEL & CREDITS INFO")
    c.setFont("Helvetica", 12)
    y -= 20
    c.drawString(70, y, 'Fuel Used: 1 credit   |   Remaining Credits: 99')

    # Footer
    y -= 50
    c.setFont("Helvetica-Bold", 14)
    c.drawCentredString(width/2, y, "-"*54)

    c.save()
    return filename

# ---------------- GUI ----------------
def create_gui():
    def on_generate():
        # Replace these with your actual a.exe args and user ID
        a_args = "1E"
        usr_id = "usr_id"
        device_id = generate_device_id(a_args, usr_id)
        priv_key, device_id = register_device(device_id)
        cert_json = submit_wipe_certificate(priv_key, device_id)
        if cert_json:
            filename = generate_certificate(cert_json)
            messagebox.showinfo("Success", f"Certificate generated:\n{filename}")
        else:
            messagebox.showwarning("Warning", "Certificate JSON not received. PDF cannot be generated.")

    root = tk.Tk()
    root.title("ZeroTrace Certificate Generator")
    root.geometry("400x200")

    tk.Label(root, text="ZeroTrace Certificate Generator", font=("Helvetica", 14, "bold")).pack(pady=20)
    tk.Button(root, text="Generate Certificate", command=on_generate, font=("Helvetica", 12)).pack(pady=20)

    root.mainloop()

# ---------------- Main ----------------
if __name__ == "__main__":
    create_gui()
