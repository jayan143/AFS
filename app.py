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
from flask import Flask, render_template, request, redirect, url_for, flash, render_template_string, send_file, session
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from routeros_api import RouterOsApiPool, exceptions

# --- SECURITY IMPORTS ---
from werkzeug.security import generate_password_hash, check_password_hash

# --- Configuration & Initialization ---
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "change_this_secret_please")

# CHANGE: Extended session lifetime to 90 days
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=90)

CONFIG_FILE = "web_router_config.json"
TOKEN_MAX_AGE = int(os.environ.get("TOKEN_MAX_AGE", "900"))
_serializer = URLSafeTimedSerializer(app.secret_key)

# =====================================================
#   🔒 WEB SECURITY CONFIGURATION
# =====================================================

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

# =====================================================

# --- Token & Config Helpers ---
def generate_token(ip, port, username, password, router_name=""):
    payload = { "ip": ip, "port": int(port), "user": username, "password": password, "name": router_name }
    return _serializer.dumps(payload)

def validate_token(token, max_age=TOKEN_MAX_AGE):
    try:
        data = _serializer.loads(token, max_age=max_age)
        return data
    except (SignatureExpired, BadSignature):
        return None

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
        with open(CONFIG_FILE, "w", encoding="utf-8") as f: json.dump(new_cfg, f, indent=2)
    except Exception as e: app.logger.error(f"Failed to save config: {e}")

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
    cfg = load_config()
    return cfg.get("routers", [])

def delete_saved_router(index):
    cfg = load_config()
    routers = cfg.get("routers", [])
    if 0 <= index < len(routers):
        routers.pop(index)
        cfg["routers"] = routers
        save_config(cfg)

def update_saved_router(index, entry):
    cfg = load_config()
    routers = cfg.get("routers", [])
    if 0 <= index < len(routers):
        routers[index].update(entry)
        cfg["routers"] = routers
        save_config(cfg)

def _user_res(api):
    return api.get_resource('/tool/user-manager/user') if api else None

def _first_id(item_dict):
    return item_dict.get(".id") or item_dict.get("id") if item_dict else None

def connect_router(router_ip, router_port, router_user, router_pass, timeout=60.0):
    if not all([router_ip, router_port, router_user]): return None, None
    try:
        socket.setdefaulttimeout(float(timeout))
        app.logger.info(f"Connecting to {router_ip}:{router_port} with timeout {timeout}s...")
        api_pool = RouterOsApiPool(router_ip, username=router_user, password=router_pass, port=int(router_port), plaintext_login=True)
        api = api_pool.get_api()
        return api, api_pool
    except Exception as e:
        app.logger.error(f"Connection error: {e}")
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
    except Exception as e:
        app.logger.error(f"Failed to load {resource_name}s: {e}")
    finally:
        if api_pool: api_pool.disconnect()
    return names

def detect_router_identity_and_model(api):
    identity, model = None, None
    try:
        items = api.get_resource('/system/identity').get()
        if items: identity = items[0].get('name')
    except: pass
    try:
        rb = api.get_resource('/system/routerboard').get()
        if rb: model = rb[0].get('model')
    except: pass
    return identity, model

# --- Formatting Helpers ---
def parse_mikrotik_duration(dur_str):
    if not dur_str: return None
    dur_str = str(dur_str).strip()
    if re.match(r'^\d+:\d+:\d+$', dur_str):
        try:
            h, m, s = map(int, dur_str.split(':'))
            return datetime.timedelta(hours=h, minutes=m, seconds=s)
        except: pass
    weeks = 0
    days = 0
    hours = 0
    minutes = 0
    seconds = 0
    try:
        if 'w' in dur_str: weeks = int(re.search(r'(\d+)w', dur_str).group(1))
        if 'd' in dur_str: days = int(re.search(r'(\d+)d', dur_str).group(1))
        if 'h' in dur_str: hours = int(re.search(r'(\d+)h', dur_str).group(1))
        if 'm' in dur_str: minutes = int(re.search(r'(\d+)m', dur_str).group(1))
        if 's' in dur_str: seconds = int(re.search(r'(\d+)s', dur_str).group(1))
        if weeks or days or hours or minutes or seconds:
            return datetime.timedelta(weeks=weeks, days=days, hours=hours, minutes=minutes, seconds=seconds)
    except: pass
    return None

def parse_mikrotik_time(time_str):
    if not time_str or time_str == 'N/A': return None
    time_str = str(time_str).strip()
    try: return datetime.datetime.strptime(time_str.title(), '%b/%d/%Y %H:%M:%S')
    except ValueError: pass
    try: return datetime.datetime.strptime(time_str, '%m/%d/%Y %H:%M:%S')
    except ValueError: pass
    return None

def format_bytes(size):
    if not size: return "0 B"
    try:
        power = 2**10
        n = int(size)
        if n <= 0: return "0 B"
        labels = {0: '', 1: 'K', 2: 'M', 3: 'G', 4: 'T'}
        n_step = 0
        while n >= power and n_step < 4:
            n /= power
            n_step += 1
        return f"{n:.2f} {labels[n_step]}B"
    except: return str(size)

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = request.form.get('remember')

        if username in web_users and check_password_hash(web_users.get(username), password):
            session['logged_in_user'] = username
            session.permanent = True if remember else False
            flash(f"Welcome back, {username}!", "success")
            
            # CHANGE: Force HTTPS on redirect logic
            # Use _external=True and _scheme='https' to ensure we land on the SSL version
            default_target = url_for('connection', _external=True, _scheme='https')
            
            # If there is a 'next' param (e.g., from bookmark), try to honor it but force HTTPS
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                 # Reconstruct full URL with HTTPS
                 # Removing trailing slash from base to avoid double slash
                 base_url = url_for('connection', _external=True, _scheme='https').rstrip('/')
                 # Remove connection path from base if it exists to get root, or just append if relative
                 # Safest approach: just let connection route handle it, or simple redirect
                 # For simplicity, if they land on a specific page, we redirect to HTTPS dashboard
                 # unless we do complex parsing. 
                 # Let's stick to the user's primary need: "go to https://actnet..."
                 pass
            
            # Redirecting to the secure URL
            return redirect(default_target)
        else:
            flash("❌ Invalid username or password", "error")
    
    return render_template('login.html', page_title="Login")

@app.route('/', methods=['GET', 'POST'])
@login_required
def connection():
    saved = get_saved_routers()
    config = load_config()
    default = config.get('default', {})

    if request.method == 'POST':
        ip = request.form.get('ip')
        port = request.form.get('port')
        username = request.form.get('username')
        password = request.form.get('password')
        router_name = request.form.get('router_name', '').strip()
        tag = request.form.get('tag', '').strip()
        auto_identity = request.form.get('auto_identity') == 'on'
        remember = request.form.get('remember') == 'on'
        save_all = request.form.get('save_all') == 'on'

        api, api_pool = connect_router(ip, port, username, password)
        if not api: return render_template('connection.html', config=default, saved_routers=saved, page_title="Connect")

        identity, model = None, None
        if auto_identity:
            identity, model = detect_router_identity_and_model(api)
            if identity and not router_name: router_name = identity

        flash("✅ Connection successful!", "success")
        
        if remember:
            config['default'] = {'ip': ip, 'port': port, 'username': username, 'password': password, 'name': router_name, 'tag': tag, 'model': model}
            save_config(config)
        
        if save_all:
            entry = {'name': router_name or f"{ip}:{port}", 'ip': ip, 'port': port, 'username': username, 'password': password, 'tag': tag, 'model': model}
            add_saved_router(entry)

        api_pool.disconnect()
        token = generate_token(ip, port, username, password, router_name)
        return redirect(url_for('actions', token=token))

    return render_template('connection.html', config=default, saved_routers=saved, page_title="Connect")

@app.route('/connect_saved/<int:index>', methods=['GET'])
@login_required
def connect_saved(index):
    saved = get_saved_routers()
    if index < 0 or index >= len(saved): return redirect(url_for('connection'))
    r = saved[index]
    token = generate_token(r['ip'], r['port'], r['username'], r['password'], r.get('name', ''))
    flash(f"✅ Connected to {r.get('name', 'saved router')}", "success")
    return redirect(url_for('actions', token=token))

@app.route('/saved/edit/<int:index>', methods=['GET', 'POST'])
@login_required
def saved_edit(index):
    saved = get_saved_routers()
    if index < 0 or index >= len(saved): return redirect(url_for('connection'))
    entry = saved[index]
    if request.method == 'POST':
        name = request.form.get('router_name', '').strip()
        tag = request.form.get('tag', '').strip()
        update_saved_router(index, {'name': name or entry.get('name', ''), 'tag': tag})
        flash("Saved router updated.", "success")
        return redirect(url_for('connection'))
    return render_template('saved_edit.html', entry=entry, index=index, page_title="Edit Router")

@app.route('/saved/delete/<int:index>', methods=['POST'])
@login_required
def saved_delete(index):
    delete_saved_router(index)
    flash("Saved router deleted.", "info")
    return redirect(url_for('connection'))

@app.route('/export_routers', methods=['GET'])
@login_required
def export_routers():
    try:
        config = load_config()
        json_str = json.dumps(config, indent=2)
        mem = io.BytesIO()
        mem.write(json_str.encode('utf-8'))
        mem.seek(0)
        return send_file(
            mem, 
            as_attachment=True, 
            download_name=f"router_backup_{datetime.datetime.now().strftime('%Y%m%d')}.json",
            mimetype='application/json'
        )
    except Exception as e:
        flash(f"❌ Export failed: {e}", "error")
        return redirect(url_for('connection'))

@app.route('/import_routers', methods=['POST'])
@login_required
def import_routers():
    if 'file' not in request.files:
        flash("❌ No file uploaded.", "error")
        return redirect(url_for('connection'))
    file = request.files['file']
    if file.filename == '':
        flash("❌ No file selected.", "error")
        return redirect(url_for('connection'))
    if file:
        try:
            content = file.read().decode('utf-8-sig')
            data = json.loads(content)
            final_config = {}
            current_config = load_config()
            if isinstance(data, list):
                final_config = current_config
                final_config['routers'] = data
            elif isinstance(data, dict):
                if 'routers' in data:
                    final_config = data
                else:
                    flash("❌ Invalid JSON format: Missing 'routers' list.", "error")
                    return redirect(url_for('connection'))
            else:
                flash("❌ Invalid JSON format: Must be a List [] or Object {}.", "error")
                return redirect(url_for('connection'))
            save_config(final_config)
            count = len(final_config.get('routers', []))
            flash(f"✅ Success! Imported {count} routers.", "success")
        except json.JSONDecodeError as e:
            flash(f"❌ JSON Syntax Error: {e.msg} at line {e.lineno}.", "error")
        except Exception as e:
            flash(f"❌ Import failed: {str(e)}", "error")
    return redirect(url_for('connection'))

@app.route('/actions', methods=['GET', 'POST'])
@login_required
def actions():
    ip, port, user, password, token, router_name = get_credentials_from_request()
    if not all([ip, port, user]): return redirect(url_for('connection'))

    profiles = load_profiles_customers("profile", ip, port, user, password)
    customers = load_profiles_customers("customer", ip, port, user, password)

    if request.method == 'POST':
        action = request.form.get('action')
        search_value = request.form.get('search_value', '').strip()
        
        api, api_pool = connect_router(ip, port, user, password)
        if not api: return redirect(url_for('actions', token=token))
        
        try:
            user_res = _user_res(api)
            
            if action == 'create_user':
                username = request.form.get('new_username', '').strip()
                new_pass = request.form.get('new_user_pass', '').strip()
                profile = request.form.get('profile_combobox', '').strip()
                customer = request.form.get('customer_combobox', '').strip()
                comment = request.form.get('price_entry', '').strip()
                bind_state = "yes" if request.form.get('bind_create') == 'on' else "no"
                if not all([username, new_pass, profile, customer]): flash("⚠️ Fill all fields!", "error")
                elif user_res.get(name=username): flash(f"User '{username}' already exists.", "error")
                else:
                    user_res.add(name=username, password=new_pass, customer=customer, comment=comment, **{"caller-id-bind-on-first-use": bind_state})
                    user_res.call('create-and-activate-profile', {'user': username, 'customer': customer, 'profile': profile})
                    flash(f"✅ User '{username}' created.", "success")

            elif action == 'change_password':
                username = request.form.get('action_user_entry', '').strip()
                new_pass = request.form.get('new_pass_entry', '').strip()
                u = user_res.get(name=username)
                if u:
                    user_data = u[0]
                    old_pass = user_data.get('password', 'N/A')
                    final_pass = new_pass if new_pass else str(random.randint(100, 999))
                    user_res.set(id=_first_id(user_data), password=final_pass)
                    flash(f"✅ Password changed for '{username}'. Old: '{old_pass}' ➝ New: '{final_pass}'", "success")
                else:
                    flash(f"User '{username}' not found.", "error")

            elif action == 'unbind_user':
                username = request.form.get('action_user_entry', '').strip()
                u = user_res.get(name=username)
                if u:
                    uid = _first_id(u[0])
                    user_res.set(id=uid, **{"caller-id": ""})
                    removed_count = 0
                    try:
                        active_res = api.get_resource('/ip/hotspot/active')
                        active_connections = active_res.get(user=username)
                        for ac in active_connections:
                            try:
                                active_res.remove(id=_first_id(ac))
                                removed_count += 1
                            except: pass
                    except Exception as e:
                        app.logger.warning(f"Could not check active sessions: {e}")

                    flash(f"✅ Success: User '{username}' Unbound. MAC Cleared and {removed_count} active connections dropped.", "success")
                else:
                    flash(f"User '{username}' not found.", "error")

            elif action == 'bulk_enable_bind':
                bulk_text = request.form.get('bulk_user_list', '').strip()
                if not bulk_text: flash("⚠️ Provide usernames.", "error")
                else:
                    names = [n.strip() for n in bulk_text.replace(',', '\n').splitlines() if n.strip()]
                    successes, not_found = [], []
                    try:
                        all_users_list = user_res.get()
                        user_map = {u.get('name'): u for u in all_users_list if u.get('name')}
                        for nm in names:
                            target_user = user_map.get(nm)
                            if not target_user:
                                not_found.append(nm)
                                continue
                            user_res.set(id=_first_id(target_user), **{"caller-id-bind-on-first-use": "yes"})
                            successes.append(nm)
                        flash(f"✅ Bulk bind enabled for: {', '.join(successes)}", "success")
                        if not_found: flash(f"⚠️ Not found: {', '.join(not_found)}", "warning")
                    except Exception as e: flash(f"❌ Bulk update failed: {e}", "error")

            elif action in ['enable_bind', 'disable_user', 'enable_user', 'remove_user']:
                username = request.form.get('action_user_entry', '').strip()
                u = user_res.get(name=username)
                if u:
                    uid = _first_id(u[0])
                    if action == 'enable_bind':
                        user_res.set(id=uid, **{"caller-id-bind-on-first-use": "yes"})
                        flash(f"✅ Bind enabled for {username}.", "success")
                    elif action == 'remove_user':
                        user_res.remove(id=uid)
                        flash(f"🗑️ User '{username}' removed.", "success")
                    else:
                        disable = "yes" if action == 'disable_user' else "no"
                        user_res.set(id=uid, disabled=disable)
                        flash(f"✅ User '{username}' {'disabled' if disable=='yes' else 'enabled'}.", "success")
                else: flash(f"User '{username}' not found.", "error")

        except Exception as e:
            app.logger.error(f"Action failed: {traceback.format_exc()}")
            flash(f"❌ Action failed: {e}", "error")
        finally:
            if api_pool: api_pool.disconnect()
        return redirect(url_for('actions', token=token, search_value=search_value))
    
    return render_template('actions.html', profiles=profiles, customers=customers, ip=ip, port=port, user=user, token=token, router_name=router_name, search_value=request.args.get('search_value', ''), page_title=router_name)

@app.route('/mac_replace', methods=['GET', 'POST'])
@login_required
def mac_replace():
    ip, port, user, password, token, router_name = get_credentials_from_request()
    if not all([ip, port, user]): return redirect(url_for('connection'))

    if request.method == 'POST':
        target_user = request.form.get('target_user', '').strip()
        mac = request.form.get('new_mac', '').strip()
        drop = request.form.get('drop_sessions') == 'on'
        bind = "yes" if request.form.get('enable_bind') == 'on' else "no"
        
        if not target_user or not mac:
            flash("⚠️ Provide username and MAC.", "error")
        else:
            clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac)
            if len(clean_mac) != 12: flash("❌ Invalid MAC format.", "error")
            else:
                new_mac = ':'.join(clean_mac[i:i+2] for i in range(0, 12, 2)).upper()
                api, api_pool = connect_router(ip, port, user, password)
                if api:
                    try:
                        ur = _user_res(api)
                        if ur.get(name=new_mac): flash(f"❌ User '{new_mac}' already exists.", "error")
                        else:
                            u = ur.get(name=target_user)
                            if u:
                                u_data = u[0]
                                old_username = target_user
                                old_password = u_data.get('password', '')
                                ur.set(id=_first_id(u_data), name=new_mac, password="", **{"caller-id": new_mac, "caller-id-bind-on-first-use": bind, "first-name": old_username, "last-name": old_password})
                                if drop:
                                    ha = api.get_resource('/ip/hotspot/active')
                                    for s in (ha.get(user=target_user) or ha.get(user=new_mac)): ha.remove(id=_first_id(s))
                                flash(f"✅ Converted '{target_user}' to '{new_mac}'.", "success")
                            else: flash(f"User '{target_user}' not found.", "error")
                    except Exception as e: flash(f"❌ Failed: {e}", "error")
                    finally: api_pool.disconnect()
    
    return render_template('mac_replace.html', ip=ip, port=port, user=user, token=token, router_name=router_name, page_title=router_name)

@app.route('/reporting', methods=['GET', 'POST'])
@login_required
def reporting():
    ip, port, user, password, token, router_name = get_credentials_from_request()
    if not all([ip, port, user]):
        flash("Please connect to a router first.", "warning")
        return redirect(url_for('connection'))
    
    user_details = None
    search_value = request.form.get('search_value', '').strip() if request.method == 'POST' else ''
    search_key = request.form.get('search_key', 'name') if request.method == 'POST' else 'name'

    if 'search_history' not in session:
        session['search_history'] = []

    if request.method == 'POST' and search_value:
        if search_value not in session['search_history']:
            session['search_history'].insert(0, search_value)
            session['search_history'] = session['search_history'][:20]
            session.modified = True

        api, api_pool = connect_router(ip, port, user, password, timeout=300)
        if api:
            try:
                user_res = _user_res(api)
                query_key = 'caller-id' if search_key == 'mac' else 'name' if search_key == 'login' else search_key
                results = user_res.get(**{query_key: search_value})
                if results: 
                    user_data = results[0]
                    try:
                        raw_download = user_data.get('download-used') or 0
                        raw_upload = user_data.get('upload-used') or 0

                        keys_to_remove = ["wireless-psk", "wireless-enc-key", "wireless-enc-algo", "uptime-used", "download-used", "upload-used", "active-sessions", "active", "incomplete", "disabled"]
                        for key in keys_to_remove: user_data.pop(key, None)

                        user_data['Download Used'] = format_bytes(raw_download)
                        user_data['Upload Used'] = format_bytes(raw_upload)

                        start_dt_object = None
                        first_login_display = "Not Started Yet"
                        raw_start = user_data.get('start-time')
                        start_dt_object = parse_mikrotik_time(raw_start)
                        if start_dt_object:
                            first_login_display = start_dt_object.strftime('%b/%d/%Y %H:%M:%S')
                        else:
                            try:
                                sess_res = api.get_resource('/tool/user-manager/session')
                                sessions = sess_res.get(user=user_data.get('name'))
                                if sessions:
                                    oldest_session = min(sessions, key=lambda s: parse_mikrotik_time(s.get("from-time")) or datetime.datetime.max)
                                    start_dt_object = parse_mikrotik_time(oldest_session.get("from-time"))
                                    if start_dt_object:
                                        first_login_display = f"{start_dt_object.strftime('%b/%d/%Y %H:%M:%S')} (From History)"
                            except Exception: pass

                            if not start_dt_object:
                                raw_last = user_data.get('last-seen')
                                raw_uptime = results[0].get('uptime-used')
                                last_seen_dt = parse_mikrotik_time(raw_last)
                                uptime_delta = parse_mikrotik_duration(raw_uptime)
                                if last_seen_dt and uptime_delta:
                                    start_dt_object = last_seen_dt - uptime_delta
                                    first_login_display = f"{start_dt_object.strftime('%b/%d/%Y %H:%M:%S')} (Calculated)"
                                elif last_seen_dt:
                                    first_login_display = f"Last Seen: {last_seen_dt.strftime('%b/%d/%Y %H:%M:%S')}"
                        user_data['First Login'] = first_login_display

                        expiry_display = "Unlimited / Not Set"
                        raw_till = user_data.get('till-time') or user_data.get('valid-until') or user_data.get('end-time')
                        if not raw_till and user_data.get('comment'):
                            match = re.search(r'\d{2}/\d{2}/\d{4}', user_data.get('comment'))
                            if match: raw_till = match.group(0) + " (Found in Comment)"
                        formatted_till = parse_mikrotik_time(raw_till)
                        if formatted_till:
                            expiry_display = formatted_till.strftime('%b/%d/%Y %H:%M:%S')
                        elif start_dt_object:
                            profile_name = user_data.get('actual-profile')
                            if profile_name:
                                try:
                                    profile_res = api.get_resource('/tool/user-manager/profile')
                                    profile_list = profile_res.get(name=profile_name)
                                    if profile_list:
                                        validity_str = profile_list[0].get('validity')
                                        validity_delta = parse_mikrotik_duration(validity_str)
                                        if validity_delta:
                                            expiry_dt = start_dt_object + validity_delta
                                            expiry_display = f"{expiry_dt.strftime('%b/%d/%Y %H:%M:%S')} (Calculated)"
                                except: pass
                        user_data['User Expiry Date'] = expiry_display
                        
                    except Exception as e: 
                        user_data['Error'] = f"Processing error: {str(e)}"
                    
                    user_details = user_data
                else: flash("No results found.", "info")
            except Exception as e: flash(f"❌ Search failed: {e}", "error")
            finally: api_pool.disconnect()

    return render_template('reporting.html', 
                           search_value=search_value, 
                           search_key=search_key, 
                           user_details=user_details, 
                           search_history=session.get('search_history', []), 
                           ip=ip, port=port, user=user, token=token, 
                           router_name=router_name, page_title=router_name)

@app.route('/logs', methods=['GET', 'POST'])
@login_required
def logs():
    ip, port, user, password, token, router_name = get_credentials_from_request()
    if not all([ip, port, user]): return redirect(url_for('connection'))
    logs_list = []
    api, api_pool = connect_router(ip, port, user, password)
    if api:
        try:
            logs_list = sorted(api.get_resource('/log').get(), key=lambda x: x.get('time', ''), reverse=True)[:200]
        except Exception as e:
            flash(f"❌ Log fetch error: {e}", "error")
        finally: 
            api_pool.disconnect()
    return render_template('logs.html', logs=logs_list, ip=ip, port=port, user=user, token=token, router_name=router_name, page_title=router_name)

@app.route('/manage', methods=['GET'])
@login_required
def manage():
    ip, port, user, password, token, router_name = get_credentials_from_request()
    if not all([ip, port, user]): return redirect(url_for('connection'))
    return render_template('manage.html', saved_routers=get_saved_routers(), ip=ip, port=port, user=user, token=token, router_name=router_name, page_title=router_name)

@app.route('/logout', methods=['GET'])
@login_required
def logout():
    session.pop('search_history', None)
    session.pop('logged_in_user', None) # Clear user session
    session.permanent = False
    
    if request.args.get('clear_default') == '1':
        cfg = load_config()
        if 'default' in cfg:
            cfg.pop('default', None)
            save_config(cfg)
    flash("Logged out.", "info")
    return redirect(url_for('login'))

@app.route('/refresh_token', methods=['GET'])
@login_required
def refresh_token():
    token = request.args.get('token')
    data = validate_token(token) if token else None
    if not data: return redirect(url_for('connection'))
    new_token = generate_token(data['ip'], data['port'], data['user'], data['password'], data.get('name', ''))
    return redirect(url_for('actions', token=new_token))

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8010)
    
    
    # చివరన app.run() బదులు ఇది ఉంచండి
    app = Flask(__name__)
# ... మీ మిగతా కోడ్ ...
app.secret_key = os.environ.get("FLASK_SECRET", "change_this_secret_please")

# Vercel కి ఇది అవసరం
app = app
# ... మీ మిగతా కోడ్ ...

# Vercel కోసం ఇది అవసరం
if __name__ == "__main__":
    app.run()
