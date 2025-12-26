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

# Zmienna globalna dla trybu konserwacji (Kill Switch)
# Resetuje się po restarcie serwera do False
MAINTENANCE_MODE = False

# --- POMOCNIKI ---

def get_real_ip():
    """Pobiera prawdziwe IP użytkownika, nawet jeśli jest za proxy"""
    if request.headers.getlist("X-Forwarded-For"):
        # X-Forwarded-For może zawierać listę (np. "IP_KLIENTA, IP_PROXY"). Bierzemy pierwsze.
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
    """Zapisuje zdarzenie w tabeli access_logs"""
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
    if request.method == 'POST':
        if request.form.get('password') == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('index'))
        flash('Błędne hasło.', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# --- DASHBOARD I ZARZĄDZANIE ---

@app.route("/")
@login_required
def index():
    # 1. Pobierz licencje
    licenses = db.table("licenses").select("*").order("created_at", desc=True).execute().data
    
    now = datetime.utcnow()
    for lic in licenses:
        lic['is_expired'] = False
        if lic.get('expires_at'):
            expire_dt = parser.isoparse(lic['expires_at']).replace(tzinfo=None)
            if expire_dt < now:
                lic['is_expired'] = True

    # 2. Pobierz logi (zwiększony limit dla wykresów)
    logs_response = db.table("access_logs").select("*").order("created_at", desc=True).limit(200).execute().data
    
    # 3. Przygotowanie danych do wykresu (Ostatnie 24h)
    chart_labels = []
    chart_data = []
    
    # Grupujemy logi po godzinie
    hours_hits = Counter()
    for log in logs_response:
        try:
            # Parsowanie daty logu
            log_time = parser.isoparse(log['created_at'])
            # Formatowanie do "HH:00"
            hour_key = log_time.strftime("%H:00")
            hours_hits[hour_key] += 1
        except:
            continue

    # Generujemy etykiety dla ostatnich 12h (żeby wykres był czytelny)
    # Można zmienić na 24h
    for i in range(11, -1, -1):
        t = now - timedelta(hours=i)
        key = t.strftime("%H:00")
        chart_labels.append(key)
        chart_data.append(hours_hits.get(key, 0))

    # Tylko 50 ostatnich logów do tabeli, żeby nie śmiecić
    table_logs = logs_response[:50]

    return render_template(
        'dashboard.html', 
        licenses=licenses, 
        logs=table_logs, 
        admin_id=ADMIN_ID,
        maintenance=MAINTENANCE_MODE,
        chart_labels=json.dumps(chart_labels),
        chart_data=json.dumps(chart_data)
    )

@app.route("/toggle_maintenance")
@login_required
def toggle_maintenance():
    global MAINTENANCE_MODE
    MAINTENANCE_MODE = not MAINTENANCE_MODE
    status = "WŁĄCZONY" if MAINTENANCE_MODE else "WYŁĄCZONY"
    flash(f"Tryb konserwacji (Kill Switch) został {status}.", "warning" if MAINTENANCE_MODE else "success")
    return redirect(url_for("index"))

@app.route("/export_active")
@login_required
def export_active():
    """Eksportuje aktywne klucze do pliku TXT"""
    licenses = db.table("licenses").select("license_key, license_type, note").eq("status", "active").execute().data
    
    output = "--- THUNDERT ACTIVE LICENSES ---\n"
    output += f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M')}\n\n"
    
    for lic in licenses:
        output += f"{lic['license_key']} | {lic['license_type']} | {lic['note']}\n"
    
    return Response(
        output,
        mimetype="text/plain",
        headers={"Content-Disposition": "attachment;filename=active_keys.txt"}
    )

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
        "expires_at": expires_at
    }).execute()

    flash(f'Utworzono: {l_type} ({duration} dni)', 'success')
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
    flash('Zaktualizowano licencję.', 'success')
    return redirect(url_for("index"))

@app.route("/action/<action_type>/<int:id>", methods=["POST"])
@login_required
def license_action(action_type, id):
    if action_type == "delete":
        db.table("licenses").delete().eq("id", id).execute()
        flash('Usunięto licencję.', 'warning')
    elif action_type == "ban":
        db.table("licenses").update({"status": "banned"}).eq("id", id).execute()
        flash('Zbanowano licencję.', 'danger')
    elif action_type == "unban":
        db.table("licenses").update({"status": "active"}).eq("id", id).execute()
        flash('Odblokowano licencję.', 'success')
    elif action_type == "reset_hwid":
        db.table("licenses").update({"hwid": None}).eq("id", id).execute()
        flash('Zresetowano HWID.', 'info')

    return redirect(url_for("index"))

# --- API (Verification Logic) ---

@app.route("/api/verify", methods=["POST"])
def verify_license():
    # 1. KILL SWITCH CHECK
    if MAINTENANCE_MODE:
        return jsonify({
            "valid": False, 
            "message": "⚠️ SYSTEM MAINTENANCE. Please wait."
        }), 403

    data = request.json
    key = data.get("key")
    hwid = data.get("hwid")
    ip = request.remote_addr

    if not key or not hwid:
        return jsonify({"valid": False, "message": "Brak danych"}), 400

    res = db.table("licenses").select("*").eq("license_key", key).execute()
    if not res.data:
        log_security_event(key, ip, hwid, "Próba użycia nieistniejącego klucza", "warning")
        return jsonify({"valid": False, "message": "Invalid Key"}), 403

    lic = res.data[0]

    if lic["status"] == "banned":
        log_security_event(key, ip, hwid, "Próba użycia ZBANOWANEGO klucza", "warning")
        return jsonify({"valid": False, "message": "License Banned"}), 403

    if lic.get("expires_at"):
        expire_dt = parser.isoparse(lic["expires_at"]).replace(tzinfo=None)
        if expire_dt < datetime.utcnow():
            if lic["status"] != "expired":
                db.table("licenses").update({"status": "expired"}).eq("id", lic["id"]).execute()
            return jsonify({"valid": False, "message": "License Expired"}), 403

    current_hwid = lic["hwid"]
    if current_hwid is None:
        db.table("licenses").update({"hwid": hwid}).eq("id", lic["id"]).execute()
        log_security_event(key, ip, hwid, "Aktywacja licencji (Nowy HWID)", "info")
    elif current_hwid != hwid:
        log_security_event(key, ip, hwid, f"HWID Mismatch! Oczekiwano: {current_hwid}", "critical")
        return jsonify({"valid": False, "message": "HWID Mismatch"}), 403

    return jsonify({
        "valid": True,
        "type": lic["license_type"],
        "expires": lic.get("expires_at"),
        "message": "Access Granted"
    }), 200

if __name__ == "__main__":
    app.run(debug=True, port=5000)

