# 🔐 Code Signing Portal

A secure Flask + MongoDB web portal for managing digital certificates, signing executables, and verifying integrity.  
It ensures software authenticity and protects users against tampered or malicious code.  

# 📖 Overview
Code signing is the process of digitally signing software to guarantee:
- **Integrity** → The software hasn’t been modified after signing.  
- **Authenticity** → The software really comes from the claimed publisher.  

This project implements:
- Certificate generation (self-signed for demo)  
- File signing with **OpenSSL & SignTool**  
- **Timestamping** (DigiCert server) so signatures remain valid after certificate expiry  
- File verification & integrity checking  
- Secure user management with roles (Admin/User)  

# 🚀 Features
- 🔑 **Certificate Management**
  - Generate RSA/ECC self-signed certs
  - Export as `.pfx` for signing
- 📂 **File Management**
  - Upload executables, scripts, documents
  - Sign multiple files at once
  - Verify signed files
- 🛡 **Security**
  - MFA login (OTP via email)
  - Secure password hashing
  - Session timeout & account lockout
- 🕵 **Logging & Auditing**
  - Tracks logins, uploads, signing actions
  - Admin dashboard for full visibility
- ⏳ **Timestamping**
  - Uses DigiCert trusted timestamp server (`http://timestamp.digicert.com`)
  - Keeps signatures valid even after cert expiry

Prerequisites:
- Python 3.9+
- MongoDB (local or Atlas)
- OpenSSL in PATH
- SignTool available (Windows SDK) and in PATH

Install:
    pip install -r requirements.txt

Run:
    python app.py

---Open http://127.0.0.1:5000
