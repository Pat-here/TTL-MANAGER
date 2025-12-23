import os
import uuid
import functools
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, jsonify, session, flash
from dotenv import load_dotenv
from supabase import create_client, Client
from dateutil import parser  # Do parsowania dat z Supabase

# --- KONFIGURACJA ---
load_dotenv(override=True)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "change_me_in_prod")

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
ADMIN_ID = os.getenv("ADMIN_ID")

db: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


# --- POMOCNIKI ---
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
    # Pobierz licencje i logi
    licenses = db.table("licenses").select("*").order("created_at", desc=True).execute().data

    # Przetwarzanie daty dla widoku (żeby ładnie wyświetlić status)
    now = datetime.utcnow()
    for lic in licenses:
        lic['is_expired'] = False
        if lic.get('expires_at'):
            # Parsowanie stringa ISO z bazy na obiekt datetime
            expire_dt = parser.isoparse(lic['expires_at']).replace(tzinfo=None)
            if expire_dt < now:
                lic['is_expired'] = True

    logs = db.table("access_logs").select("*").order("created_at", desc=True).limit(50).execute().data

    return render_template('dashboard.html', licenses=licenses, logs=logs, admin_id=ADMIN_ID)


@app.route("/create", methods=["POST"])
@login_required
def create_license():
    note = request.form.get("note", "")
    l_type = request.form.get("license_type", "BASIC")
    duration = request.form.get("duration", "30")  # Dni jako string

    # Obliczanie daty wygaśnięcia
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
    extend_days = request.form.get("extend_days")  # Może być 0, 30, itp.

    update_data = {"note": new_note}

    # Jeśli admin chce przedłużyć
    if extend_days and int(extend_days) > 0:
        # Pobieramy obecną datę wygaśnięcia
        current_lic = db.table("licenses").select("expires_at").eq("id", lic_id).single().execute()
        current_expires = current_lic.data.get("expires_at")

        if current_expires:
            # Dodajemy do istniejącej daty
            base_date = parser.isoparse(current_expires)
            # Jeśli licencja już wygasła, przedłużamy od TERAZ
            if base_date.replace(tzinfo=None) < datetime.utcnow():
                base_date = datetime.utcnow()

            new_date = base_date + timedelta(days=int(extend_days))
            update_data["expires_at"] = new_date.isoformat()
            update_data["status"] = "active"  # Odblokuj jeśli wygasła
        else:
            # Była lifetime, a teraz ustawiamy datę? (rzadki case)
            pass

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
    data = request.json
    key = data.get("key")
    hwid = data.get("hwid")
    ip = request.remote_addr

    if not key or not hwid:
        return jsonify({"valid": False, "message": "Brak danych"}), 400

    # 1. Pobierz licencję
    res = db.table("licenses").select("*").eq("license_key", key).execute()
    if not res.data:
        log_security_event(key, ip, hwid, "Próba użycia nieistniejącego klucza", "warning")
        return jsonify({"valid": False, "message": "Invalid Key"}), 403

    lic = res.data[0]

    # 2. Sprawdź Status (BAN)
    if lic["status"] == "banned":
        log_security_event(key, ip, hwid, "Próba użycia ZBANOWANEGO klucza", "warning")
        return jsonify({"valid": False, "message": "License Banned"}), 403

    # 3. Sprawdź Datę Ważności
    if lic.get("expires_at"):
        expire_dt = parser.isoparse(lic["expires_at"]).replace(tzinfo=None)
        if expire_dt < datetime.utcnow():
            # Auto-expired update (opcjonalne, ale przydatne)
            if lic["status"] != "expired":
                db.table("licenses").update({"status": "expired"}).eq("id", lic["id"]).execute()

            return jsonify({"valid": False, "message": "License Expired"}), 403

    # 4. Sprawdź HWID (KRYTYCZNE - 2 maszyny)
    current_hwid = lic["hwid"]

    if current_hwid is None:
        # Pierwsze odpalenie - wiążemy HWID
        db.table("licenses").update({"hwid": hwid}).eq("id", lic["id"]).execute()
        log_security_event(key, ip, hwid, "Aktywacja licencji (Nowy HWID)", "info")

    elif current_hwid != hwid:
        # ALERT: Ktoś próbuje odpalić na innym kompie!
        log_security_event(key, ip, hwid, f"HWID Mismatch! Oczekiwano: {current_hwid}", "critical")
        return jsonify({"valid": False, "message": "HWID Mismatch - Multiple devices detected"}), 403

    return jsonify({
        "valid": True,
        "type": lic["license_type"],
        "expires": lic.get("expires_at"),
        "message": "Access Granted"
    }), 200


if __name__ == "__main__":
    app.run(debug=True, port=5000)