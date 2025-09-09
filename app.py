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
from flask_mail import Mail, Message
import random
import re
import secrets
from datetime import timedelta

# --- MongoDB ---
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from dotenv import load_dotenv
load_dotenv()

# -------------------------
# Flask Config
# -------------------------
app = Flask(__name__)
app.secret_key = 'mysecret123'
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1 GB

ALLOWED_EXTS = {
    '.exe', '.dll', '.msi', '.zip', '.tar', '.gz', '.jar', '.py', '.txt', '.pdf'
}

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Account lockout settings ---
MAX_FAILED_ATTEMPTS = 5        # lock after 5 bad logins
LOCKOUT_MINUTES = 10           # lock for 10 minutes

# Auto logout after 15 minutes of inactivity
app.permanent_session_lifetime = timedelta(minutes=5)

# --- Mail Config ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv("MAIL_USERNAME")
app.config['MAIL_PASSWORD'] = os.getenv("MAIL_PASSWORD") # your 16-char Gmail App Password

app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

mail = Mail(app)

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
    uname = session.get('username') or session.get('user')
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

def is_strong_password(pwd: str) -> bool:
    """Check if password meets security requirements."""
    if len(pwd) < 8:
        return False
    if not re.search(r"[A-Z]", pwd):  # at least one uppercase
        return False
    if not re.search(r"[a-z]", pwd):  # at least one lowercase
        return False
    if not re.search(r"[0-9]", pwd):  # at least one digit
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", pwd):  # at least one special char
        return False
    return True
# -------------------------
# MongoDB Connection
# -------------------------
MONGO_URI = os.getenv("MONGO_URI","your_fallback_local_mongo_uri")
    
try:
    client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
    client.admin.command('ping')
    print("✅ Connected to MongoDB successfully!")
except Exception as e:
    print("❌ MongoDB connection failed:", e)
    raise SystemExit(1)

DB_NAME = os.environ.get('MONGO_DB', 'code_signing_portal')
db = client.get_database(DB_NAME)

users = db.users
files_col = db.files
certs_col = db.certs
logs_col = db.logs

# --- Ensure unique email ---
existing_indexes = users.index_information()

if "unique_email" not in existing_indexes:
    users.create_index(
        [("email", 1)],
        unique=True,
        sparse=True,
        name="unique_email"
    )
    print("✅ Unique index on email created")
else:
    print("ℹ️ Unique index on email already exists, skipping.")

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
        'email': 'admin@example.com',
        'password_hash': generate_password_hash('admin'),
        'role': 'admin',
        'failed_attempts': 0,     # 👈 add
        'lock_until': None,       # 👈 add
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
    return render_template(
        'index.html',
        has_cert=has_cert,
        user=u,
        session_timeout=int(app.permanent_session_lifetime.total_seconds())
    )

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        uname = request.form.get('username')
        pwd = request.form.get('password')
        u = users.find_one({'username': uname})

        if u:
            # --- Step 1: Check if locked ---
            lock_until_str = u.get("lock_until")
            lock_until = None
            if lock_until_str:
                try:
                    lock_until = datetime.fromisoformat(lock_until_str)
                except Exception:
                    lock_until = None

            now_utc = datetime.now(timezone.utc)
            if lock_until and lock_until > now_utc:
                mins_left = max(1, int((lock_until - now_utc).total_seconds() // 60))
                flash(f"Your account is locked. Try again in about {mins_left} minute(s).")
                logs_col.insert_one({
                    'username': uname,
                    'action': 'login_locked',
                    'success': False,
                    'timestamp': now_iso()
                })
                return redirect(url_for('login'))

            # --- Step 2: Check password ---
            if check_password_hash(u['password_hash'], pwd):
                # Reset failed attempts on success
                users.update_one(
                    {'_id': u['_id']},
                    {'$set': {'failed_attempts': 0}, '$unset': {'lock_until': ""}}
                )

                # ✅ Enable session timeout
                session.permanent = True  # This makes the session use Flask’s timeout
                # (set lifetime globally: app.permanent_session_lifetime = timedelta(minutes=15))

                # ✅ Admin: bypass MFA
                if u.get('role') == 'admin':
                    session['username'] = uname
                    session['role'] = 'admin'
                    flash("Welcome Admin! Logged in successfully.")
                    logs_col.insert_one({'username': uname, 'action': 'login', 'success': True, 'timestamp': now_iso()})
                    return redirect(url_for('index'))

                # ✅ Normal user: generate OTP
                otp = str(random.randint(100000, 999999))
                session['pending_user'] = uname
                session['otp'] = otp
                session['otp_time'] = now_utc.timestamp()

                try:
                    msg = Message("Your Login OTP", recipients=[u['email']])
                    msg.body = f"Hello {uname},\n\nYour OTP is: {otp}\nIt is valid for 5 minutes."
                    mail.send(msg)
                    flash("OTP has been sent to your email.")
                except Exception as e:
                    flash("Error sending OTP email: " + str(e))
                    return redirect(url_for('login'))

                return redirect(url_for('mfa'))

            else:
                # --- Step 3: Wrong password → increment attempts ---
                attempts = int(u.get('failed_attempts') or 0) + 1
                update = {'$set': {'failed_attempts': attempts}}

                if attempts >= MAX_FAILED_ATTEMPTS:
                    until = (now_utc + timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
                    update['$set']['lock_until'] = until

                    # 📧 Send account lock notification email
                    try:
                        msg = Message("Account Locked - Code Signing Portal", recipients=[u['email']])
                        msg.body = f"""
                        Hello {uname},

                        Your account has been locked due to {MAX_FAILED_ATTEMPTS} unsuccessful login attempts.
                        It will remain locked for {LOCKOUT_MINUTES} minutes.

                        If this was not you, we strongly recommend resetting your password immediately.

                        Regards,
                        Code Signing Portal Security Team
                        """
                        mail.send(msg)
                    except Exception as e:
                        print("⚠️ Error sending lock email:", e)

                    flash(f"Too many failed attempts. Account locked for {LOCKOUT_MINUTES} minutes. An email has been sent.")
                    logs_col.insert_one({
                        'username': uname,
                        'action': 'account_locked',
                        'success': False,
                        'timestamp': now_iso()
                    })

                else:
                    left = MAX_FAILED_ATTEMPTS - attempts
                    flash(f"Invalid credentials. Attempts left: {left}")

                users.update_one({'_id': u['_id']}, update)
                return redirect(url_for('login'))

        # --- Step 4: Invalid user ---
        flash('Invalid credentials')
        logs_col.insert_one({'username': uname, 'action': 'login', 'success': False, 'timestamp': now_iso()})
        return redirect(url_for('login'))

    return render_template('login.html', user=current_user())



@app.route('/mfa', methods=['GET', 'POST'])
def mfa():
    if 'pending_user' not in session:
        flash("No pending login. Please login again.")
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_entered = request.form.get('otp')
        otp_expected = session.get('otp')
        otp_time = session.get('otp_time')

        # Check expiry (5 min = 300 sec)
        if otp_time and (datetime.now(timezone.utc).timestamp() - otp_time) > 300:
            session.pop('otp', None)
            session.pop('otp_time', None)
            session.pop('pending_user', None)
            flash("OTP expired. Please login again.")
            return redirect(url_for('login'))

        if otp_entered == otp_expected:
            uname = session.pop('pending_user')
            session.pop('otp', None)
            session.pop('otp_time', None)
            session['username'] = uname
            flash("Login successful!")
            logs_col.insert_one({'username': uname, 'action': 'login', 'success': True, 'timestamp': now_iso()})
            return redirect(url_for('index'))
        else:
            flash("Invalid OTP. Try again.")
            return redirect(url_for('mfa'))

    return render_template('mfa.html', user=current_user())



@app.route('/logout')
def logout():
    uname = session.get('username')
    if uname:
        logs_col.insert_one({'username': uname, 'action': 'logout', 'timestamp': now_iso()})
    session.clear()
    flash('Logged out')
    return redirect(url_for('index'))

# Forgot Password
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = (request.form.get('email') or "").strip().lower()
        u = users.find_one({'email': email})
        if not u:
            flash("No account found with that email.")
            return redirect(url_for('forgot_password'))

        # Generate reset token
        token = secrets.token_urlsafe(32)
        expiry = datetime.now(timezone.utc) + timedelta(hours=1)

        users.update_one(
            {'_id': u['_id']},
            {'$set': {'reset_token': token, 'reset_expiry': expiry.isoformat()}}
        )

        # Send email with reset link
        reset_url = url_for('reset_password', token=token, _external=True)
        try:
            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"Hello {u['username']},\n\nClick below link to reset your password:\n{reset_url}\n\nThis link is valid for 1 hour."
            mail.send(msg)
            flash("Password reset link has been sent to your email.")
        except Exception as e:
            flash("Error sending email: " + str(e))

        return redirect(url_for('login'))

    return render_template('forgot_password.html', user=current_user())



# Reset Password
# Reset Password
# Reset Password
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    u = users.find_one({'reset_token': token})
    if not u:
        flash("Invalid or expired reset link.")
        return redirect(url_for('login'))

    # Check expiry
    expiry_str = u.get('reset_expiry')
    if not expiry_str or datetime.fromisoformat(expiry_str) < datetime.now(timezone.utc):
        flash("Reset link has expired. Please request again.")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        pwd = request.form.get('password')
        pwd2 = request.form.get('password2')

        # Check if both passwords match
        if not pwd or pwd != pwd2:
            flash("Passwords do not match.")
            return redirect(request.url)

        # ✅ Enforce strong password using helper
        if not is_strong_password(pwd):
            flash("Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.")
            return redirect(request.url)

        # ✅ Prevent reusing old password
        if check_password_hash(u['password_hash'], pwd):
            flash("New password cannot be the same as your old password.")
            return redirect(request.url)

        # Update password
        users.update_one(
            {'_id': u['_id']},
            {
                '$set': {'password_hash': generate_password_hash(pwd)},
                '$unset': {'reset_token': "", 'reset_expiry': ""}
            }
        )

        flash("Password has been reset. Please login.")
        return redirect(url_for('login'))

    return render_template('reset_password.html', token=token, user=current_user())



# Change Password (user must be logged in)
# Change Password
@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    u = current_user()
    if not u:
        flash("Please log in first.")
        return redirect(url_for("login"))

    if request.method == "POST":
        old_pwd = request.form.get("old_password", "")
        new_pwd = request.form.get("new_password", "")
        confirm_pwd = request.form.get("confirm_password", "")

        # Check old password
        if not check_password_hash(u["password_hash"], old_pwd):
            flash("❌ Current password is incorrect.")
            return redirect(request.url)

        # Prevent reusing the old password
        if check_password_hash(u["password_hash"], new_pwd):
            flash("❌ New password cannot be the same as the old password.")
            return redirect(request.url)

        # Confirm match
        if new_pwd != confirm_pwd:
            flash("❌ New password and confirmation do not match.")
            return redirect(request.url)

        # Strong password check
        import re
        strong_regex = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$')
        if not strong_regex.match(new_pwd):
            flash("❌ Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.")
            return redirect(request.url)

        # Update password
        users.update_one(
            {"_id": u["_id"]},
            {"$set": {"password_hash": generate_password_hash(new_pwd)}}
        )

        flash("✅ Password changed successfully. Please log in again.")
        return redirect(url_for("logout"))

    return render_template("change_password.html", user=u)

@app.route('/delete_account', methods=['POST'])
def delete_account():
    u = current_user()
    if not u:
        flash("You need to log in first.")
        return redirect(url_for('login'))

    # prevent admin from deleting themselves accidentally
    if u.get("role") == "admin":
        flash("Admin account cannot be deleted.")
        return redirect(url_for('index'))

    # delete user files
    files_col.delete_many({'uploaded_by': u['username']})
    logs_col.insert_one({'username': u['username'], 'action': 'account_deleted', 'timestamp': now_iso()})

    # delete user from DB
    users.delete_one({'_id': u['_id']})

    # log out
    session.clear()
    flash("Your account has been deleted permanently.")
    return redirect(url_for('index'))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        # validation
        if not username or not email or not password or not confirm_password:
            flash("All fields are required")
            return redirect(url_for("signup"))

        if password != confirm_password:
            flash("Passwords do not match")
            return redirect(url_for("signup"))

        # ✅ Check strong password
        if not is_strong_password(password):
            flash("Password must be at least 8 characters long, include uppercase, lowercase, number, and special character.")
            return redirect(url_for("signup"))

        # check if username or email already exists
        if users.find_one({"username": username}):
            flash("Username already taken")
            return redirect(url_for("signup"))

        if users.find_one({"email": email}):
            flash("Email already registered, please log in")
            return redirect(url_for("login"))

        # ✅ save user
        users.insert_one({
            "username": username,
            "email": email,
            "password_hash": generate_password_hash(password),
            "role": "user",
            "failed_attempts": 0,   # for account lockout
            "lock_until": None,     # for account lockout
            "created_at": now_iso()
        })

        flash("Signup successful. Please log in.")
        return redirect(url_for("login"))

    return render_template("signup.html", user=current_user())


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
        'CN': request.form.get('CN', 'localhost'),
        'O': request.form.get('O', 'MyCompany'),
        'OU': request.form.get('OU', ''),
        'C': request.form.get('C', 'IN'),
        'ST': request.form.get('ST', 'State'),
        'L': request.form.get('L', 'City'),
        'days': int(request.form.get('days', 730))
}

    algo = request.form.get('algo', 'RSA')
    pfx_password = request.form.get('pfx_password', '')

    if not pfx_password:
        flash('PFX password required')
        return redirect(url_for('certs'))

    ok, res = signer.generate_self_signed(body, pfx_password, algo=algo)
    if not ok:
        flash('Cert generation failed: ' + str(res))
        return redirect(url_for('certs'))

    doc = {
        'cn': body['CN'],
        'meta': body,
        'algo': algo,
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
        'algo': algo,
        'timestamp': now_iso()
    })
    flash(f'Certificate generated with {algo}')
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
            target = os.path.abspath(os.path.join(UPLOAD_DIR, filename))

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
                        'signed_at': now_iso(),
                        'cert_cn': cert.get('cn'),
                        'algo': cert.get('algo', 'RSA')
                    }}
                )
                logs_col.insert_one({
                    'username': u['username'],
                    'action': 'sign',
                    'filename': filename,
                    'success': True,
                    'cert_cn': cert.get('cn'),
                    'algo': cert.get('algo', 'RSA'),
                    'timestamp': now_iso()
                })
                results.append((filename, True, out))
            else:
                logs_col.insert_one({
                    'username': u['username'],
                    'action': 'sign',
                    'filename': filename,
                    'success': False,
                    'details': out,
                    'cert_cn': cert.get('cn'),
                    'algo': cert.get('algo', 'RSA'),
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

@app.before_request
def make_session_permanent():
    session.modified = True  # refresh session timer on activity


@app.before_request
def session_timeout_check():
    # Skip for static files
    if request.endpoint in ("static",):
        return

    # If user is logged in
    if "username" in session:
        now = datetime.now(timezone.utc).timestamp()
        last_activity = session.get("last_activity")

        # If session is new → set activity time
        if not last_activity:
            session["last_activity"] = now
        else:
            # Check inactivity
            elapsed = now - last_activity
            if elapsed > app.permanent_session_lifetime.total_seconds():
                session.clear()
                flash("Session expired, please login again.")
                return redirect(url_for("login"))

            # Update last activity
            session["last_activity"] = now

@app.context_processor
def inject_session_timeout():
    return {
        "session_timeout": int(app.permanent_session_lifetime.total_seconds())
    }


# -------------------------
# Main
# -------------------------
if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
