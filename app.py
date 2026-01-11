import os
import uuid
import functools
import json
from datetime import datetime, timedelta
from collections import Counter
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash, Response
from dotenv import load_dotenv
from supabase import create_client, Client
from dateutil import parser

# --- KONFIGURACJA ---
load_dotenv(override=True)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change_me_in_prod")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
ADMIN_ID = os.getenv("ADMIN_ID")

db: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# Zmienne globalne w pamięci RAM
MAINTENANCE_MODE = False
MOTD_MESSAGE = "Access Granted"  # Domyślna wiadomość dla bota

# --- ANTI-BRUTE FORCE CONFIG ---
LOGIN_ATTEMPTS = {}  # {ip: {'count': 0, 'block_until': datetime}}
MAX_FAILURES = 5
BLOCK_TIME_MINUTES = 15

# --- POMOCNIKI ---

def get_real_ip():
    """Pobiera prawdziwe IP, nawet zza proxy"""
    if request.headers.getlist("X-Forwarded-For"):
        ip = request.headers.getlist("X-Forwarded-For")[0]
        if ',' in ip:
            ip = ip.split(',')[0].strip()
        return ip
    return request.remote_addr

def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def log_security_event(key, ip, hwid, msg, severity="info"):
    """Zapisuje zdarzenie w bazie"""
    try:
        db.table("access_logs").insert({
            "license_key": key,
            "ip_address": ip,
            "hwid_attempt": hwid,
            "message": msg,
            "severity": severity
        }).execute()
    except Exception as e:
        print(f"Błąd logowania: {e}")

# --- ROUTY AUTORYZACJI ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = get_real_ip()
    now = datetime.utcnow()

    # 1. Sprawdzenie czy IP jest zablokowane
    if ip in LOGIN_ATTEMPTS:
        attempt_data = LOGIN_ATTEMPTS[ip]
        if attempt_data['block_until'] and now < attempt_data['block_until']:
            time_left = attempt_data['block_until'] - now
            minutes_left = int(time_left.total_seconds() // 60) + 1
            flash(f'Zbyt wiele prób. IP zablokowane na {minutes_left} min.', 'error')
            return render_template('login.html')
        
        if attempt_data['block_until'] and now >= attempt_data['block_until']:
            del LOGIN_ATTEMPTS[ip]

    if request.method == 'POST':
        password = request.form.get('password')
        
        if password == ADMIN_PASSWORD:
            session['logged_in'] = True
            if ip in LOGIN_ATTEMPTS:
                del LOGIN_ATTEMPTS[ip]
            return redirect(url_for('index'))
        else:
            if ip not in LOGIN_ATTEMPTS:
                LOGIN_ATTEMPTS[ip] = {'count': 0, 'block_until': None}
            
            LOGIN_ATTEMPTS[ip]['count'] += 1
            
            if LOGIN_ATTEMPTS[ip]['count'] >= MAX_FAILURES:
                LOGIN_ATTEMPTS[ip]['block_until'] = now + timedelta(minutes=BLOCK_TIME_MINUTES)
                flash(f'Zablokowano dostęp na {BLOCK_TIME_MINUTES} minut.', 'error')
            else:
                remaining = MAX_FAILURES - LOGIN_ATTEMPTS[ip]['count']
                flash(f'Błędne hasło. Pozostało prób: {remaining}', 'error')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- DASHBOARD ---

@app.route("/")
@login_required
def index():
    # Pobieranie licencji
    licenses = db.table("licenses").select("*").order("created_at", desc=True).execute().data
    
    now = datetime.utcnow()
    for lic in licenses:
        lic['is_expired'] = False
        if lic.get('expires_at'):
            expire_dt = parser.isoparse(lic['expires_at']).replace(tzinfo=None)
            if expire_dt < now:
                lic['is_expired'] = True

    # Pobieranie logów
    logs_response = db.table("access_logs").select("*").order("created_at", desc=True).limit(200).execute().data
    
    online_users = set()
    five_mins_ago = now - timedelta(minutes=5)
    
    chart_labels = []
    chart_data = []
    hours_hits = Counter()
    
    for log in logs_response:
        try:
            log_time = parser.isoparse(log['created_at']).replace(tzinfo=None)
            
            if log_time > five_mins_ago:
                if log['hwid_attempt']:
                    online_users.add(log['hwid_attempt'])

            hour_key = log_time.strftime("%H:00")
            hours_hits[hour_key] += 1
        except:
            continue

    for i in range(11, -1, -1):
        t = now - timedelta(hours=i)
        key = t.strftime("%H:00")
        chart_labels.append(key)
        chart_data.append(hours_hits.get(key, 0))

    return render_template(
        'dashboard.html', 
        licenses=licenses, 
        logs=logs_response[:50], 
        admin_id=ADMIN_ID,
        maintenance=MAINTENANCE_MODE,
        motd=MOTD_MESSAGE,
        online_count=len(online_users),
        chart_labels=json.dumps(chart_labels),
        chart_data=json.dumps(chart_data)
    )

@app.route("/update_settings", methods=["POST"])
@login_required
def update_settings():
    global MOTD_MESSAGE
    new_motd = request.form.get("motd")
    if new_motd:
        MOTD_MESSAGE = new_motd
        flash("Zaktualizowano wiadomość powitalną (MOTD).", "success")
    return redirect(url_for("index"))

@app.route("/toggle_maintenance")
@login_required
def toggle_maintenance():
    global MAINTENANCE_MODE
    MAINTENANCE_MODE = not MAINTENANCE_MODE
    status = "WŁĄCZONY" if MAINTENANCE_MODE else "WYŁĄCZONY"
    flash(f"Kill Switch: {status}.", "warning" if MAINTENANCE_MODE else "success")
    return redirect(url_for("index"))

@app.route("/export_active")
@login_required
def export_active():
    licenses = db.table("licenses").select("license_key, license_type, note").eq("status", "active").execute().data
    output = "--- THUNDERT ACTIVE LICENSES ---\n"
    for lic in licenses:
        output += f"{lic['license_key']} | {lic['license_type']} | {lic['note']}\n"
    return Response(output, mimetype="text/plain", headers={"Content-Disposition": "attachment;filename=active_keys.txt"})

@app.route("/create", methods=["POST"])
@login_required
def create_license():
    note = request.form.get("note", "")
    l_type = request.form.get("license_type", "BASIC")
    duration = request.form.get("duration", "30")

    expires_at = None
    if duration != "lifetime":
        days = int(duration)
        expires_at = (datetime.utcnow() + timedelta(days=days)).isoformat()

    new_key = str(uuid.uuid4()).upper()

    db.table("licenses").insert({
        "license_key": new_key,
        "note": note,
        "status": "active",
        "license_type": l_type,
        "expires_at": expires_at,
        "hwid": None,       # Reset HWID
        "fingerprint": None # Reset Fingerprint
    }).execute()

    flash(f'Utworzono: {l_type}', 'success')
    return redirect(url_for("index"))

@app.route("/edit_license", methods=["POST"])
@login_required
def edit_license():
    lic_id = request.form.get("id")
    new_note = request.form.get("note")
    extend_days = request.form.get("extend_days")
    
    update_data = {"note": new_note}
    if extend_days and int(extend_days) > 0:
        current_lic = db.table("licenses").select("expires_at").eq("id", lic_id).single().execute()
        current_expires = current_lic.data.get("expires_at")
        if current_expires:
            base_date = parser.isoparse(current_expires)
            if base_date.replace(tzinfo=None) < datetime.utcnow():
                base_date = datetime.utcnow()
            new_date = base_date + timedelta(days=int(extend_days))
            update_data["expires_at"] = new_date.isoformat()
            update_data["status"] = "active"

    db.table("licenses").update(update_data).eq("id", lic_id).execute()
    flash('Zaktualizowano.', 'success')
    return redirect(url_for("index"))

@app.route("/action/<action_type>/<int:id>", methods=["POST"])
@login_required
def license_action(action_type, id):
    if action_type == "delete":
        db.table("licenses").delete().eq("id", id).execute()
    elif action_type == "ban":
        db.table("licenses").update({"status": "banned"}).eq("id", id).execute()
    elif action_type == "unban":
        db.table("licenses").update({"status": "active"}).eq("id", id).execute()
    elif action_type == "reset_hwid":
        # Resetujemy ZARÓWNO stary HWID jak i nowy Fingerprint
        db.table("licenses").update({"hwid": None, "fingerprint": None}).eq("id", id).execute()
        flash("Zresetowano HWID i Fingerprint.", "success")
        
    return redirect(url_for("index"))

# --- API ENDPOINTS ---

@app.route("/api/verify", methods=["POST"])
def verify_license():
    ip = get_real_ip()

    if MAINTENANCE_MODE:
        return jsonify({"valid": False, "message": "⚠️ SERWER W TRAKCIE PRAC. WRÓĆ PÓŹNIEJ."}), 403

    data = request.json
    key = data.get("key")
    hwid = data.get("hwid")
    fingerprint = data.get("fingerprint") # Nowy Strong HWID

    if not key or not hwid:
        return jsonify({"valid": False, "message": "Brak danych"}), 400

    res = db.table("licenses").select("*").eq("license_key", key).execute()
    if not res.data:
        log_security_event(key, ip, hwid, "Nieistniejący klucz", "warning")
        return jsonify({"valid": False, "message": "Invalid Key"}), 403

    lic = res.data[0]

    # Sprawdzenie bana
    if lic["status"] == "banned":
        log_security_event(key, ip, hwid, "Próba użycia zbanowanego klucza", "critical")
        return jsonify({"valid": False, "message": "License Banned"}), 403

    # Sprawdzenie wygaśnięcia
    if lic.get("expires_at"):
        expire_dt = parser.isoparse(lic["expires_at"]).replace(tzinfo=None)
        if expire_dt < datetime.utcnow():
            if lic["status"] != "expired":
                db.table("licenses").update({"status": "expired"}).eq("id", lic["id"]).execute()
            return jsonify({"valid": False, "message": "License Expired"}), 403

    # --- WERYFIKACJA SPRZĘTOWA ---
    
    current_hwid = lic.get("hwid")
    current_fingerprint = lic.get("fingerprint")
    
    update_data = {}
    security_breach = False

    # 1. Weryfikacja Legacy HWID (wmic)
    if current_hwid is None:
        # Pierwsze użycie - przypisujemy HWID
        update_data["hwid"] = hwid
    elif current_hwid != hwid:
        log_security_event(key, ip, hwid, f"HWID Mismatch (Legacy)! Oczekiwano: {current_hwid}", "critical")
        return jsonify({"valid": False, "message": "HWID Mismatch"}), 403

    # 2. Weryfikacja Strong Fingerprint (Anti-Spoof/Anti-Clone)
    if fingerprint: # Jeśli klient wysyła fingerprint (v1.3+)
        if current_fingerprint is None:
            # Użytkownik zaktualizował bota - przypisujemy fingerprint
            update_data["fingerprint"] = fingerprint
            log_security_event(key, ip, hwid, "Migracja do Strong HWID (v1.3)", "info")
        elif current_fingerprint != fingerprint:
            # HWID (wmic) się zgadza, ale Fingerprint NIE -> Spoofing/Klonowanie
            log_security_event(key, ip, hwid, "STRONG FINGERPRINT MISMATCH (Clone Detected!)", "critical")
            return jsonify({"valid": False, "message": "Security Error: Environment Changed (Spoof/Clone)"}), 403

    # Zapis zmian w bazie (przypisanie HWID/Fingerprint)
    if update_data:
        db.table("licenses").update(update_data).eq("id", lic["id"]).execute()
        if "hwid" in update_data and current_hwid is None:
            log_security_event(key, ip, hwid, "Aktywacja (Nowy HWID)", "info")

    return jsonify({
        "valid": True,
        "type": lic["license_type"],
        "expires": lic.get("expires_at"),
        "message": MOTD_MESSAGE 
    }), 200

# --- NOWY ENDPOINT: SECURITY REPORT ---
@app.route("/api/report", methods=["POST"])
def security_report():
    """
    Odbiera ciche alarmy od klientów (Logic Bomb, wykrycie VM, cracka).
    """
    data = request.json
    hwid = data.get("hwid", "UNKNOWN")
    pc_user = data.get("pc_user", "UNKNOWN")
    reason = data.get("reason", "UNKNOWN_REASON")
    
    # Próbujemy znaleźć klucz po HWID, żeby wiedzieć kto to
    # (To opcjonalne, ale pomaga namierzyć klienta)
    license_key = "UNKNOWN_KEY"
    try:
        res = db.table("licenses").select("license_key").eq("hwid", hwid).limit(1).execute()
        if res.data:
            license_key = res.data[0]['license_key']
    except:
        pass

    msg = f"SECURITY ALERT: {reason} | User: {pc_user}"
    ip = get_real_ip()
    
    # Logujemy jako CRITICAL
    log_security_event(license_key, ip, hwid, msg, "critical")
    
    # Opcjonalnie: Automatyczny ban licencji przy wykryciu cracka
    # if "TAMPERING" in reason or "CRACK" in reason:
    #     if license_key != "UNKNOWN_KEY":
    #         db.table("licenses").update({"status": "banned"}).eq("license_key", license_key).execute()

    return jsonify({"status": "received"}), 200

if __name__ == "__main__":
    app.run(debug=True, port=5000)
