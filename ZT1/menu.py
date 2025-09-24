import subprocess
import json
import os
import base64
import hashlib
import random
import string
from datetime import datetime
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

SERVER_URL = "http://127.0.0.1:8081"

# ---------------- ASCII & Banner ----------------
BANNER = r"""
 _____            _____
|__  /___ _ __ __|_   _| __ __ _  ___ ___
  / // _ \ '__/ _ \| || '__/ _` |/ __/ _ \
 / /|  __/ | | (_) | || | | (_| | (_|  __/
/____\___|_|  \___/|_||_|  \__,_|\___\___|
"""

TAGLINE = "Secure. Irreversible. ZeroTrace – Data gone, forever."
DISCLAIMER = """
[!] Disclaimer:
    - This tool will permanently erase the selected storage device.
    - Once confirmed, data recovery will NOT be possible.
    - Ensure you have selected the correct device before proceeding.
    - Authors and contributors are not responsible for any data loss.
"""

# ---------------- Helper functions ----------------
def generate_device_id(a_args: str, usr_id: str = "usr_id"):
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    rand_str = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    return f"zT{a_args}_{timestamp}_{rand_str}_{usr_id}"

def get_disks():
    ps_script = r"""
    Get-Disk | ForEach-Object {
        $disk = $_
        Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue | ForEach-Object {
            $partition = $_
            Get-Volume -Partition $partition -ErrorAction SilentlyContinue | ForEach-Object {
                [PSCustomObject]@{
                    Number = $disk.Number
                    Letter = $_.DriveLetter
                    SizeGB = [math]::Round($disk.Size/1GB,2)
                    Model = $disk.FriendlyName
                }
            }
        }
    } | ConvertTo-Json
    """
    result = subprocess.run(
        ["powershell", "-Command", ps_script],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print("Error fetching disks:", result.stderr)
        return []

    try:
        disks = json.loads(result.stdout)
        if isinstance(disks, dict):
            disks = [disks]
        return [d for d in disks if d.get("Letter")]
    except Exception as e:
        print("Parse error:", e)
        return []

def run_wipe(disk_num, disk_letter):
    print(f"\n[+] Running wipe: Disk {disk_num}, Drive {disk_letter}:")
    try:
        subprocess.run(["a.exe", str(disk_num), disk_letter], check=True)
        print("\n[+] Wipe completed successfully!")
    except subprocess.CalledProcessError as e:
        print("\n[!] Wipe failed.")
        print("Return code:", e.returncode)
        return False
    except KeyboardInterrupt:
        print("\n[!] Wipe interrupted by user (CTRL+C).")
        return False
    return True

def register_and_submit(device_id, usr_id="usr_id"):
    # Generate keys
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

    # Submit wipe certificate
    cert_data = {"device_id": device_id, "timestamp": datetime.utcnow().isoformat()}
    cert_bytes = json.dumps(cert_data).encode()
    cert_hash = hashlib.sha256(cert_bytes).hexdigest().encode()
    signature = priv_key.sign(cert_hash, ec.ECDSA(hashes.SHA256()))

    resp = requests.post(f"{SERVER_URL}/submit_certificate_json", json={
        "device_id": device_id,
        "cert_bytes_b64": base64.b64encode(cert_bytes).decode(),
        "signature_b64": base64.b64encode(signature).decode()
    })
    print("Submit wipe result:", json.dumps(resp.json(), indent=2))

    # Download certificate
    download_resp = requests.get(f"{SERVER_URL}/download_certificate/{device_id}")
    with open("my_wipe_certificate.json", "wb") as f:
        f.write(download_resp.content)
    print("Certificate downloaded as my_wipe_certificate.json")

# ---------------- Main ----------------
def main():
    os.system("cls" if os.name == "nt" else "clear")
    print(BANNER)
    print(TAGLINE)
    print(DISCLAIMER)

    disks = get_disks()
    if not disks:
        print("No disks found!")
        return

    print("=== Available Disks ===")
    for d in disks:
        print(f"Disk {d['Number']} | {d['Letter']}: | {d['SizeGB']} GB | {d['Model']}")

    # User selects disk
    choice = input("\nEnter the DISK NUMBER to wipe: ").strip()
    letter = input("Enter the DRIVE LETTER to wipe (e.g. E): ").strip().upper()

    selected = None
    for d in disks:
        if str(d["Number"]) == choice and d["Letter"].upper() == letter:
            selected = d
            break
    if not selected:
        print("Invalid selection.")
        return

    disk_num, disk_letter = selected["Number"], selected["Letter"]
    if run_wipe(disk_num, disk_letter):
        # Generate device_id with disk args (disk number + letter)
        a_args = f"{disk_num}{disk_letter}"
        device_id = generate_device_id(a_args, "usr_id")
        register_and_submit(device_id)

if __name__ == "__main__":
    main()
