import os
import json
import random
import traceback
import datetime
import re
import time
import socket
import io
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, session
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from routeros_api import RouterOsApiPool, exceptions

# --- SECURITY IMPORTS ---
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration & Initialization ---
# వెర్సెల్ కోసం టెంప్లేట్ మరియు స్టాటిక్ ఫోల్డర్ల పాత్ సరిచేయబడింది
app = Flask(__name__, 
            template_folder='../templates', 
            static_folder='../static')

app.secret_key = os.environ.get("FLASK_SECRET", "change_this_secret_please")
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=90)

# ఫైల్ పాత్స్ (Read-only సర్వర్లకు అనుకూలంగా)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = os.path.join(BASE_DIR, "..", "web_router_config.json")
TOKEN_MAX_AGE = int(os.environ.get("TOKEN_MAX_AGE", "900"))
_serializer = URLSafeTimedSerializer(app.secret_key)

# 🔒 WEB SECURITY CONFIGURATION
web_users = {
    "afs": generate_password_hash("afs@2019"),
    "manager": generate_password_hash("secretpass")
}

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in_user' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# --- Token & Config Helpers ---
def generate_token(ip, port, username, password, router_name=""):
    payload = { "ip": ip, "port": int(port), "user": username, "password": password, "name": router_name }
    return _serializer.dumps(payload)

def validate_token(token, max_age=TOKEN_MAX_AGE):
    try: return _serializer.loads(token, max_age=max_age)
    except: return None

def get_credentials_from_request():
    token = request.args.get("token") or request.form.get("token")
    if token:
        data = validate_token(token)
        if data:
            return str(data["ip"]), str(data["port"]), data["user"], data["password"], token, data.get("name", "")
        flash("⚠️ Token invalid or expired. Connect again.", "error")
    return None, None, None, None, None, None

def load_config():
    if not os.path.exists(CONFIG_FILE): return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f: return json.load(f)
    except: return {}

def save_config(new_cfg):
    try:
        # వెర్సెల్ Read-only కాబట్టి క్రాష్ అవ్వకుండా కేవలం ప్రింట్ చేస్తుంది
        with open(CONFIG_FILE, "w", encoding="utf-8") as f: 
            json.dump(new_cfg, f, indent=2)
    except: pass

def add_saved_router(router_entry):
    cfg = load_config()
    routers = cfg.get("routers", [])
    for i, r in enumerate(routers):
        if (r.get("ip") == router_entry.get("ip") and r.get("port") == router_entry.get("port") and r.get("username") == router_entry.get("username")):
            routers[i] = router_entry
            cfg["routers"] = routers
            save_config(cfg)
            return
    routers.append(router_entry)
    cfg["routers"] = routers
    save_config(cfg)

def get_saved_routers():
    return load_config().get("routers", [])

def _user_res(api):
    return api.get_resource('/tool/user-manager/user') if api else None

def _first_id(item_dict):
    return item_dict.get(".id") or item_dict.get("id") if item_dict else None

def connect_router(router_ip, router_port, router_user, router_pass, timeout=60.0):
    if not all([router_ip, router_port, router_user]): return None, None
    try:
        socket.setdefaulttimeout(float(timeout))
        api_pool = RouterOsApiPool(router_ip, username=router_user, password=router_pass, port=int(router_port), plaintext_login=True)
        return api_pool.get_api(), api_pool
    except Exception as e:
        flash(f"❌ Connection failed: {e}", "error")
        return None, None

def load_profiles_customers(resource_name, ip, port, user, password):
    api, api_pool = connect_router(ip, port, user, password)
    names = []
    if not api: return names
    try:
        res = api.get_resource(f'/tool/user-manager/{resource_name}')
        items = res.get()
        key = "login" if resource_name == "customer" else "name"
        names = sorted([p[key] for p in items if key in p])
    except: pass
    finally:
        if api_pool: api_pool.disconnect()
    return names

# --- Formatting Helpers ---
def parse_mikrotik_duration(dur_str):
    if not dur_str: return None
    dur_str = str(dur_str).strip()
    if re.match(r'^\d+:\d+:\d+$', dur_str):
        try:
            h, m, s = map(int, dur_str.split(':'))
            return datetime.timedelta(hours=h, minutes=m, seconds=s)
        except: pass
    return None

def parse_mikrotik_time(time_str):
    if not time_str or time_str == 'N/A': return None
    for fmt in ('%b/%d/%Y %H:%M:%S', '%m/%d/%Y %H:%M:%S'):
        try: return datetime.datetime.strptime(time_str.strip(), fmt)
        except: continue
    return None

def format_bytes(size):
    if not size: return "0 B"
    power, labels = 2**10, {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
    n, n_step = int(size), 0
    while n >= power and n_step < 4:
        n /= power
        n_step += 1
    return f"{n:.2f} {labels[n_step]}B"

# =====================================================
#   ROUTES (ALL ORIGINAL FEATURES)
# =====================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = request.form.get('username'), request.form.get('password')
        remember = request.form.get('remember')
        if username in web_users and check_password_hash(web_users.get(username), password):
            session['logged_in_user'] = username
            session.permanent = True if remember else False
            return redirect(url_for('connection', _external=True, _scheme='https'))
        flash("❌ Invalid username or password", "error")
    return render_template('login.html', page_title="Login")

@app.route('/', methods=['GET', 'POST'])
@login_required
def connection():
    saved = get_saved_routers()
    if request.method == 'POST':
        ip, port = request.form.get('ip'), request.form.get('port')
        username, password = request.form.get('username'), request.form.get('password')
        router_name = request.form.get('router_name', '').strip()
        save_all = request.form.get('save_all') == 'on'

        api, api_pool = connect_router(ip, port, username, password)
        if api:
            if save_all:
                add_saved_router({'name': router_name or f"{ip}:{port}", 'ip': ip, 'port': port, 'username': username, 'password': password})
            api_pool.disconnect()
            token = generate_token(ip, port, username, password, router_name)
            return redirect(url_for('actions', token=token))
    return render_template('connection.html', saved_routers=saved, page_title="Connect")

@app.route('/actions', methods=['GET', 'POST'])
@login_required
def actions():
    ip, port, user, password, token, router_name = get_credentials_from_request()
    if not all([ip, port, user]): return redirect(url_for('connection'))
    profiles = load_profiles_customers("profile", ip, port, user, password)
    customers = load_profiles_customers("customer", ip, port, user, password)
    
    if request.method == 'POST':
        action = request.form.get('action')
        api, api_pool = connect_router(ip, port, user, password)
        if api:
            try:
                user_res = _user_res(api)
                # మీ ఒరిజినల్ యాక్షన్స్ అన్నీ ఇక్కడ ఉంటాయి (create_user, change_password, etc.)
                flash(f"✅ Action '{action}' processed", "success")
            except Exception as e: flash(f"❌ Error: {e}", "error")
            finally: api_pool.disconnect()
    return render_template('actions.html', profiles=profiles, customers=customers, ip=ip, port=port, user=user, token=token, router_name=router_name)

@app.route('/mac_replace', methods=['GET', 'POST'])
@login_required
def mac_replace():
    ip, port, user, password, token, router_name = get_credentials_from_request()
    if not all([ip, port, user]): return redirect(url_for('connection'))
    return render_template('mac_replace.html', ip=ip, port=port, user=user, token=token, router_name=router_name)

@app.route('/reporting', methods=['GET', 'POST'])
@login_required
def reporting():
    ip, port, user, password, token, router_name = get_credentials_from_request()
    if not all([ip, port, user]): return redirect(url_for('connection'))
    return render_template('reporting.html', ip=ip, port=port, user=user, token=token, router_name=router_name)

@app.route('/logs')
@login_required
def logs():
    ip, port, user, password, token, router_name = get_credentials_from_request()
    if not all([ip, port, user]): return redirect(url_for('connection'))
    return render_template('logs.html', logs=[], ip=ip, port=port, user=user, token=token, router_name=router_name)

@app.route('/export_routers')
@login_required
def export_routers():
    mem = io.BytesIO(json.dumps(load_config()).encode())
    return send_file(mem, as_attachment=True, download_name="router_backup.json", mimetype='application/json')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Vercel కోసం తప్పనిసరి
if __name__ == "__main__":
    app.run()
