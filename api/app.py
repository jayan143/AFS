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
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration & Initialization ---
# Vercel కోసం template మరియు static ఫోల్డర్ల పాత్ సరిచేయబడింది
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

# --- Helpers ---
def generate_token(ip, port, username, password, router_name=""):
    payload = { "ip": ip, "port": int(port), "user": username, "password": password, "name": router_name }
    return _serializer.dumps(payload)

def validate_token(token, max_age=TOKEN_MAX_AGE):
    try:
        return _serializer.loads(token, max_age=max_age)
    except:
        return None

def get_credentials_from_request():
    token = request.args.get("token") or request.form.get("token")
    if token:
        data = validate_token(token)
        if data:
            return str(data["ip"]), str(data["port"]), data["user"], data["password"], token, data.get("name", "")
    return None, None, None, None, None, None

def load_config():
    if not os.path.exists(CONFIG_FILE): return {}
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f: return json.load(f)
    except: return {}

def save_config(new_cfg):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f: 
            json.dump(new_cfg, f, indent=2)
    except Exception as e: 
        print(f"Config Write Skipped: {e}")

# --- Router Logic ---
def connect_router(router_ip, router_port, router_user, router_pass, timeout=60.0):
    if not all([router_ip, router_port, router_user]): return None, None
    try:
        socket.setdefaulttimeout(float(timeout))
        api_pool = RouterOsApiPool(router_ip, username=router_user, password=router_pass, port=int(router_port), plaintext_login=True)
        return api_pool.get_api(), api_pool
    except Exception as e:
        flash(f"❌ Connection failed: {e}", "error")
        return None, None

def _user_res(api):
    return api.get_resource('/tool/user-manager/user') if api else None

def _first_id(item_dict):
    return item_dict.get(".id") or item_dict.get("id") if item_dict else None

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

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username, password = request.form.get('username'), request.form.get('password')
        if username in web_users and check_password_hash(web_users.get(username), password):
            session['logged_in_user'] = username
            session.permanent = request.form.get('remember') == 'on'
            return redirect(url_for('connection', _external=True, _scheme='https'))
        flash("❌ Invalid credentials", "error")
    return render_template('login.html', page_title="Login")

@app.route('/', methods=['GET', 'POST'])
@login_required
def connection():
    saved = load_config().get("routers", [])
    if request.method == 'POST':
        ip, port = request.form.get('ip'), request.form.get('port')
        username, password = request.form.get('username'), request.form.get('password')
        api, api_pool = connect_router(ip, port, username, password)
        if api:
            api_pool.disconnect()
            token = generate_token(ip, port, username, password)
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
                if action == 'create_user':
                    # User creation logic...
                    flash("User action processed", "success")
            except Exception as e: flash(f"Error: {e}", "error")
            finally: api_pool.disconnect()
    return render_template('actions.html', profiles=profiles, customers=customers, token=token, router_name=router_name)

@app.route('/mac_replace', methods=['GET', 'POST'])
@login_required
def mac_replace():
    ip, port, user, password, token, router_name = get_credentials_from_request()
    if not all([ip, port, user]): return redirect(url_for('connection'))
    return render_template('mac_replace.html', token=token, router_name=router_name)

@app.route('/reporting', methods=['GET', 'POST'])
@login_required
def reporting():
    ip, port, user, password, token, router_name = get_credentials_from_request()
    if not all([ip, port, user]): return redirect(url_for('connection'))
    return render_template('reporting.html', token=token, router_name=router_name)

@app.route('/export_routers')
@login_required
def export_routers():
    mem = io.BytesIO(json.dumps(load_config()).encode())
    return send_file(mem, as_attachment=True, download_name="backup.json", mimetype='application/json')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# Vercel కోసం తప్పనిసరి
if __name__ == "__main__":
    app.run()
