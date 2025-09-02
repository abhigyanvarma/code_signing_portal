import os
import hashlib
from datetime import datetime, timezone
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, send_from_directory
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from backend import signer

# --- MongoDB ---
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi

# -------------------------
# Flask Config
# -------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-change-me')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB
ALLOWED_EXTS = {'.exe', '.zip', '.tar', '.gz', '.jar', '.py', '.txt', '.pdf'}

# -------------------------
# Helpers
# -------------------------
def now_iso() -> str:
    """Timezone-aware UTC ISO timestamp."""
    return datetime.now(timezone.utc).isoformat()

def compute_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def allowed_file_ext(filename: str) -> bool:
    _, ext = os.path.splitext(filename)
    return ext.lower() in ALLOWED_EXTS

def current_user():
    uname = session.get('username')
    if not uname:
        return None
    return users.find_one({'username': uname})

def login_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **k):
        u = current_user()
        if not u:
            flash('Please log in first.')
            return redirect(url_for('login'))
        return fn(*a, **k)
    return wrapper

def admin_required(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*a, **k):
        u = current_user()
        if not u or u.get('role') != 'admin':
            flash('Admin access required.')
            return redirect(url_for('index'))
        return fn(*a, **k)
    return wrapper

# -------------------------
# MongoDB Connection
# -------------------------
MONGO_URI = os.environ.get(
    'MONGO_URI',
    # Your working Atlas URI (no DB name here; we select DB below):
    'mongodb+srv://code_sign_user:code_sign_user@code-signing-portal.ixamkky.mongodb.net/?retryWrites=true&w=majority&appName=Code-Signing-Portal'
)

try:
    client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
    client.admin.command('ping')
    print("✅ Connected to MongoDB successfully!")
except Exception as e:
    print("❌ MongoDB connection failed:", e)
    raise SystemExit(1)

# Use/ensure this DB name
DB_NAME = os.environ.get('MONGO_DB', 'code_signing_portal')
db = client.get_database(DB_NAME)

users = db.users
files_col = db.files
certs_col = db.certs
logs_col = db.logs

# -------------------------
# Directories
# -------------------------
APP_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(APP_DIR, 'uploads')
CERTS_DIR = os.path.join(APP_DIR, 'backend', 'certs')
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(CERTS_DIR, exist_ok=True)

# -------------------------
# Default Admin
# -------------------------
if not users.find_one({'username': 'admin'}):
    users.insert_one({
        'username': 'admin',
        'password_hash': generate_password_hash('admin'),
        'role': 'admin',
        'created_at': now_iso()
    })
    print('Default admin created: admin/admin')

# -------------------------
# Routes
# -------------------------
@app.route('/')
def index():
    u = current_user()
    has_cert = certs_col.count_documents({}) > 0
    return render_template('index.html', has_cert=has_cert, user=u)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form.get('username')
        pwd = request.form.get('password')
        u = users.find_one({'username': uname})
        if u and check_password_hash(u['password_hash'], pwd):
            session['username'] = uname
            flash('Logged in')
            logs_col.insert_one({'username': uname, 'action': 'login', 'success': True, 'timestamp': now_iso()})
            return redirect(url_for('index'))
        flash('Invalid credentials')
        logs_col.insert_one({'username': uname, 'action': 'login', 'success': False, 'timestamp': now_iso()})
    return render_template('login.html', user=current_user())

@app.route('/logout')
def logout():
    uname = session.get('username')
    if uname:
        logs_col.insert_one({'username': uname, 'action': 'logout', 'timestamp': now_iso()})
    session.clear()
    flash('Logged out')
    return redirect(url_for('index'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        uname = request.form.get('username')
        pwd = request.form.get('password')
        pwd2 = request.form.get('password2')

        if not uname or not pwd or not pwd2:
            flash('All fields are required')
            return redirect(url_for('signup'))
        if pwd != pwd2:
            flash('Passwords do not match')
            return redirect(url_for('signup'))
        if users.find_one({'username': uname}):
            flash('Username already exists')
            return redirect(url_for('signup'))

        users.insert_one({
            'username': uname,
            'password_hash': generate_password_hash(pwd),
            'role': 'user',
            'created_at': now_iso()
        })
        logs_col.insert_one({'username': uname, 'action': 'signup', 'timestamp': now_iso()})
        flash('Signup successful! Please login.')
        return redirect(url_for('login'))

    return render_template('signup.html', user=current_user())

# -------- Certificates --------
@app.route('/certs')
@login_required
def certs():
    u = current_user()
    certs_list = list(certs_col.find({})) if u.get('role') == 'admin' else list(certs_col.find({'created_by': u['username']}))
    return render_template('certs.html', certs=certs_list, user=u)

@app.route('/certs/generate', methods=['POST'])
@login_required
def certs_generate():
    u = current_user()
    body = {
        'C': request.form.get('C', 'IN'),
        'ST': request.form.get('ST', 'State'),
        'L': request.form.get('L', 'City'),
        'O': request.form.get('O', 'MyCompany'),
        'OU': request.form.get('OU', ''),
        'CN': request.form.get('CN', 'MyCompany'),
        'days': int(request.form.get('days', 730))
    }
    pfx_password = request.form.get('pfx_password', '')
    if not pfx_password:
        flash('PFX password required')
        return redirect(url_for('certs'))

    ok, res = signer.generate_self_signed(body, pfx_password)
    if not ok:
        flash('Cert generation failed: ' + str(res))
        return redirect(url_for('certs'))

    doc = {
        'cn': body['CN'],
        'meta': body,
        'pfx_path': res['pfx_path'],
        'crt_path': res['crt_path'],
        'valid_from': res['valid_from'],
        'valid_to': res['valid_to'],
        'created_by': u['username'],
        'created_at': res.get('created_at', now_iso())
    }
    certs_col.insert_one(doc)
    logs_col.insert_one({
        'username': u['username'],
        'action': 'generate_cert',
        'cert_cn': body['CN'],
        'timestamp': now_iso()
    })
    flash('Certificate generated')
    return redirect(url_for('certs'))

@app.route('/certs/download/<id>/<kind>')
@login_required
def certs_download(id, kind):
    try:
        objid = ObjectId(str(id))
    except Exception:
        flash('Invalid certificate id')
        return redirect(url_for('certs'))

    cert = certs_col.find_one({'_id': objid})
    if not cert:
        flash('Certificate not found')
        return redirect(url_for('certs'))

    path = cert.get('crt_path') if kind == 'crt' else cert.get('pfx_path')
    if not path or not os.path.exists(path):
        flash('Certificate file missing on server')
        return redirect(url_for('certs'))

    return send_from_directory(os.path.dirname(path), os.path.basename(path), as_attachment=True)

# -------- Files (GET list + POST sign) --------
@app.route('/files', methods=['GET', 'POST'])
@login_required
def files_page():
    u = current_user()

    # POST -> sign selected files
    if request.method == 'POST':
        cert_id = request.form.get('cert_id')
        pfx_password = request.form.get('pfx_password', '')
        selected = request.form.getlist('selected_files')

        if not cert_id or not selected:
            flash('Certificate and files selection required for signing')
            return redirect(url_for('files_page'))

        try:
            cert = certs_col.find_one({'_id': ObjectId(str(cert_id))})
        except Exception:
            cert = None
        if not cert:
            flash('Selected certificate not found')
            return redirect(url_for('files_page'))

        pfx_path = cert.get('pfx_path')
        results = []
        for filename in selected:
            target = os.path.join(UPLOAD_DIR, filename)
            if not os.path.exists(target):
                results.append((filename, False, 'file missing'))
                continue

            ok, out = signer.sign_file(pfx_path, pfx_password, target)
            if ok:
                checksum_signed = compute_sha256(target)
                files_col.update_one(
                    {'filename': filename},
                    {'$set': {
                        'status': 'signed',
                        'checksum_signed': checksum_signed,
                        'signed_at': now_iso()
                    }}
                )
                logs_col.insert_one({
                    'username': u['username'], 'action': 'sign',
                    'filename': filename, 'success': True, 'timestamp': now_iso()
                })
                results.append((filename, True, out))
            else:
                logs_col.insert_one({
                    'username': u['username'], 'action': 'sign',
                    'filename': filename, 'success': False, 'details': out,
                    'timestamp': now_iso()
                })
                results.append((filename, False, out))

        ok_files = [r[0] for r in results if r[1]]
        bad = [f"{r[0]}: {r[2]}" for r in results if not r[1]]
        flash(('Signed: ' + ', '.join(ok_files)) if ok_files else 'No files signed')
        if bad:
            flash('Errors: ' + '; '.join(bad))
        return redirect(url_for('files_page'))

    # GET -> list files & certs
    if u.get('role') == 'admin':
        uploaded = list(files_col.find({}).sort('uploaded_at', -1))
        certs_list = list(certs_col.find({}))
    else:
        uploaded = list(files_col.find({'uploader': u['username']}).sort('uploaded_at', -1))
        certs_list = list(certs_col.find({'created_by': u['username']}))

    return render_template('files.html', files=uploaded, certs=certs_list, user=u)

@app.route('/files/upload', methods=['POST'])
@login_required
def files_upload():
    u = current_user()
    filesx = request.files.getlist('files')
    saved = []

    for f in filesx:
        if not f or f.filename == '':
            continue

        filename = secure_filename(f.filename)
        if not allowed_file_ext(filename):
            flash(f'Skipping disallowed file type: {filename}')
            continue

        dest = os.path.join(UPLOAD_DIR, filename)
        if os.path.exists(dest):
            base, ext = os.path.splitext(filename)
            # keep a simple unique suffix
            filename = f"{base}_{int(datetime.now(timezone.utc).timestamp())}{ext}"
            dest = os.path.join(UPLOAD_DIR, filename)

        f.save(dest)
        checksum_orig = compute_sha256(dest)

        files_col.insert_one({
            'filename': filename,
            'uploader': u['username'],
            'status': 'uploaded',
            'uploaded_at': now_iso(),
            'checksum_original': checksum_orig
        })
        logs_col.insert_one({
            'username': u['username'],
            'action': 'upload',
            'filename': filename,
            'timestamp': now_iso()
        })
        saved.append(filename)

    flash('Uploaded: ' + ', '.join(saved) if saved else 'No files uploaded')
    return redirect(url_for('files_page'))

@app.route('/uploads/<path:filename>')
@login_required
def download_upload(filename):
    u = current_user()
    if u.get('role') != 'admin':
        file_doc = files_col.find_one({'filename': filename})
        if not file_doc or file_doc.get('uploader') != u['username']:
            flash('You can only download files you uploaded')
            return redirect(url_for('files_page'))
    return send_from_directory(UPLOAD_DIR, filename, as_attachment=True)

@app.route('/files/verify', methods=['POST'])
@login_required
def files_verify():
    u = current_user()
    filename = request.form.get('selected_files')
    if not filename:
        flash('No file selected for verification')
        return redirect(url_for('files_page'))

    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(path):
        flash('File not found on server')
        return redirect(url_for('files_page'))

    ok, out = signer.verify_file(path)
    logs_col.insert_one({
        'username': u.get('username'),
        'action': 'verify',
        'filename': filename,
        'success': ok,
        'details': out,
        'timestamp': now_iso()
    })
    flash('Verification ' + ('successful' if ok else 'failed: ' + out))
    return redirect(url_for('files_page'))

@app.route('/files/compare', methods=['POST'])
@login_required
def files_compare():
    u = current_user()
    local = request.files.get('local_file')
    signed_filename = request.form.get('signed_filename')

    if not local or not signed_filename:
        flash('Please provide both files to compare')
        return redirect(url_for('verify_integrity_page'))

    # save the uploaded local file to a temp location
    tmp_dir = os.path.join(APP_DIR, 'tmp')
    os.makedirs(tmp_dir, exist_ok=True)
    local_path = os.path.join(tmp_dir, secure_filename(local.filename))
    local.save(local_path)

    local_sum = compute_sha256(local_path)
    signed_path = os.path.join(UPLOAD_DIR, signed_filename)
    if not os.path.exists(signed_path):
        flash('Signed file not found on server')
        return redirect(url_for('verify_integrity_page'))

    signed_sum = compute_sha256(signed_path)
    result = 'MATCH' if local_sum == signed_sum else f'MISMATCH (local:{local_sum} vs signed:{signed_sum})'

    signed_files = list(
        files_col.find({'status': 'signed'}) if u.get('role') == 'admin'
        else files_col.find({'uploader': u['username'], 'status': 'signed'})
    )
    return render_template('verify_integrity.html', signed_files=signed_files, user=u, comparison_result=result)

# -------- Logs (admin) --------
@app.route('/logs')
@admin_required
def logs_page():
    u = current_user()
    logs = list(logs_col.find({}).sort('timestamp', -1))
    return render_template('logs.html', logs=logs, user=u)

# -------- Verify Integrity Page --------
@app.route('/verify', methods=['GET'])
@login_required
def verify_integrity_page():
    u = current_user()
    signed_files = list(
        files_col.find({'status': 'signed'}) if u.get('role') == 'admin'
        else files_col.find({'uploader': u['username'], 'status': 'signed'})
    )
    return render_template('verify_integrity.html', signed_files=signed_files, user=u)

# -------------------------
# Main
# -------------------------
if __name__ == '__main__':
    # Make sure your Atlas "Network Access" allows your IP,
    # and that the DB user dilli/dilli exists with proper roles.
    app.run(debug=True, host='127.0.0.1', port=5000)
