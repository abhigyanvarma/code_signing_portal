# backend/signer.py
import os, subprocess, re
from datetime import datetime

APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CERTS_DIR = os.path.join(APP_DIR, 'backend', 'certs')
UPLOADS_DIR = os.path.join(APP_DIR, 'uploads')
os.makedirs(CERTS_DIR, exist_ok=True)
os.makedirs(UPLOADS_DIR, exist_ok=True)

def run(cmd):
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = (proc.stdout or '') + (proc.stderr or '')
    return proc.returncode == 0, out.strip()

def _safe_name(name):
    # replace unsafe filename chars
    return re.sub(r'[^A-Za-z0-9_.-]', '_', str(name))

def generate_self_signed(meta, pfx_pass, algo="RSA"):
    """
    meta: dict with CN, O, OU, L, ST, C, days (optional)
    algo: "RSA" (default), "ECDSA", "EDDSA"
    """
    algo = (algo or "RSA").upper()
    cn_safe = _safe_name(meta.get('CN', 'MySigner'))
    priv = os.path.join(CERTS_DIR, f"{cn_safe}_{algo}.key")
    crt  = os.path.join(CERTS_DIR, f"{cn_safe}_{algo}.crt")
    pfx  = os.path.join(CERTS_DIR, f"{cn_safe}_{algo}.pfx")
    cnf  = os.path.join(CERTS_DIR, f"{cn_safe}_{algo}_openssl.cnf")

    cfg = f"""[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no
default_md = sha256

[ req_distinguished_name ]
C = {meta.get('C','IN')}
ST = {meta.get('ST','State')}
L = {meta.get('L','City')}
O = {meta.get('O','MyCompany')}
OU = {meta.get('OU','')}
CN = {meta.get('CN','MyCompany')}

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature
extendedKeyUsage = codeSigning
"""
    with open(cnf, 'w') as fh:
        fh.write(cfg)

    days = str(meta.get('days', 730))

    # ---------- Algorithm-specific generation ----------
    if algo == "RSA":
        # RSA 2048 (default)
        if not (os.path.exists(priv) and os.path.exists(crt)):
            ok, out = run([
                "openssl","req","-x509","-newkey","rsa:2048",
                "-keyout", priv, "-out", crt,
                "-days", days,
                "-config", cnf, "-extensions", "v3_req", "-nodes"
            ])
            if not ok:
                return False, out

    elif algo == "ECDSA":
        # ECDSA P-256
        if not os.path.exists(priv):
            ok, out = run(["openssl","ecparam","-name","prime256v1","-genkey","-noout","-out",priv])
            if not ok:
                return False, out
        if not os.path.exists(crt):
            ok, out = run([
                "openssl","req","-new","-x509",
                "-key", priv,
                "-days", days,
                "-config", cnf, "-extensions", "v3_req",
                "-out", crt
            ])
            if not ok:
                return False, out

   

    # ---------- Export to PFX ----------
    ok, out = run([
        "openssl","pkcs12","-export",
        "-out", pfx,
        "-inkey", priv,
        "-in", crt,
        "-passout", f"pass:{pfx_pass}"
    ])
    if not ok:
        return False, out

    # ---------- Read validity ----------
    ok, out = run(["openssl","x509","-in", crt, "-noout", "-dates"])
    valid_from = valid_to = None
    if ok:
        for line in out.splitlines():
            if line.startswith("notBefore="): valid_from = line.split("=",1)[1].strip()
            if line.startswith("notAfter="):  valid_to   = line.split("=",1)[1].strip()

    return True, {
        "key_path": priv,
        "crt_path": crt,
        "pfx_path": pfx,
        "valid_from": valid_from,
        "valid_to": valid_to,
        "created_at": datetime.utcnow().isoformat(),
        "algo": algo,
    }

def sign_file(pfx, pfx_pass, target, signtool_path='signtool'):
    # normalize absolute paths
    pfx = os.path.abspath(pfx)
    target = os.path.abspath(target)

    print("PFX path:", pfx)
    print("Target path:", target)

    # Default hashing: SHA256 (works for RSA and ECDSA)
    # Note: Ed25519 uses its own underlying hash internally.
    cmd = [
        signtool_path, 'sign', '/f', pfx, '/p', pfx_pass,
        '/fd', 'SHA256',
        '/tr', 'http://timestamp.digicert.com', '/td', 'SHA256',
        target
    ]

    print("Running command:", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.returncode == 0, result.stdout + result.stderr

def verify_file(target, signtool_path='signtool'):
    return run([signtool_path, 'verify', '/pa', target])
