from flask import Flask, render_template, request, redirect
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_socketio import SocketIO
import sqlite3
import os
import requests   # ← for IP geolocation (pip install requests)

from db import init_db
from detector import monitor_logs, set_socketio, set_app

from threading import Thread

app = Flask(__name__)
app.secret_key = "secret123"

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading"
)

set_socketio(socketio)
set_app(app)

init_db()

os.makedirs("logs", exist_ok=True)

if not os.path.exists("logs/server.log"):
    open("logs/server.log", "w").close()

Thread(
    target=monitor_logs,
    args=("logs/server.log",),
    daemon=True
).start()

# ==================================================
# GEO LOOKUP  (free, no API key needed)
# ==================================================

_geo_cache = {}   # cache so we don't hammer the API

def geo_lookup(ip):
    """Return (lat, lon, country) for an IP, or (None, None, None) on failure."""

    # Skip private / loopback ranges — they have no public location
    if ip.startswith(("192.168.", "10.", "172.", "127.", "::1")):
        return None, None, None

    if ip in _geo_cache:
        return _geo_cache[ip]

    try:
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=lat,lon,country,status",
                         timeout=3)
        data = r.json()
        if data.get("status") == "success":
            result = (data["lat"], data["lon"], data.get("country", ""))
        else:
            result = (None, None, None)
    except Exception:
        result = (None, None, None)

    _geo_cache[ip] = result
    return result


# ==================================================
# LOGIN SYSTEM
# ==================================================

login_manager = LoginManager(app)
login_manager.login_view = "login"


class User(UserMixin):
    def __init__(self, id):
        self.id = id


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


# ==================================================
# FIREWALL
# ==================================================

def block_ip(ip):
    db = sqlite3.connect("database.db")
    cur = db.cursor()
    try:
        cur.execute("INSERT INTO blocked_ips (ip) VALUES (?)", (ip,))
        db.commit()
    except:
        pass
    db.close()


def get_blocked_ips():
    db = sqlite3.connect("database.db")
    cur = db.cursor()
    try:
        cur.execute("SELECT ip FROM blocked_ips")
        data = cur.fetchall()
    except:
        data = []
    db.close()
    return [x[0] for x in data]


def is_blocked(ip):
    db = sqlite3.connect("database.db")
    cur = db.cursor()
    try:
        cur.execute("SELECT 1 FROM blocked_ips WHERE ip=?", (ip,))
        res = cur.fetchone()
    except:
        res = None
    db.close()
    return res


@app.before_request
def firewall():
    allowed_routes = [
        "/simulate/brute",
        "/simulate/ddos",
        "/simulate/sql",
        "/simulate/xss",
        "/login",
        "/notify",
        "/stream",
        "/logs"
    ]

    if request.path in allowed_routes:
        return

    if request.remote_addr in ["127.0.0.1", "::1"]:
        return

    if is_blocked(request.remote_addr):
        return "<h1>🚫 BLOCKED BY SIEM FIREWALL</h1>"


# ==================================================
# ALERTS
# ==================================================

def get_alerts():
    db = sqlite3.connect("database.db")
    db.row_factory = sqlite3.Row
    cur = db.cursor()
    try:
        cur.execute("SELECT * FROM alerts ORDER BY id DESC")
        data = cur.fetchall()
    except:
        data = []
    db.close()
    return data


# ==================================================
# LOGIN
# ==================================================

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        db = sqlite3.connect("database.db")
        cur = db.cursor()
        cur.execute(
            "SELECT id FROM users WHERE username=? AND password=?",
            (request.form["username"], request.form["password"])
        )
        user = cur.fetchone()
        db.close()

        if user:
            login_user(User(user[0]))
            return redirect("/")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")


# ==================================================
# ATTACK PAGE
# ==================================================

@app.route("/attack")
@login_required
def attack_page():
    return render_template("attack.html")


# ==================================================
# ATTACK SIMULATIONS (emit includes lat/lon now)
# ==================================================

@app.route("/simulate/brute")
@login_required
def brute():
    ip = "192.168.1.10"
    with open("logs/server.log", "a") as f:
        for _ in range(6):
            f.write(f"Failed Login from {ip}\n")
        f.write(f"Success Login from {ip}\n")

    lat, lon, country = geo_lookup(ip)
    socketio.emit("alert", {
        "ip": ip, "type": "Brute Force", "severity": "High",
        "mitre": "T1110", "lat": lat, "lon": lon, "country": country
    })
    return {"status": "brute simulated"}


@app.route("/simulate/ddos")
@login_required
def ddos():
    ip = "10.0.0.5"
    with open("logs/server.log", "a") as f:
        for _ in range(25):
            f.write(f"Request from {ip}\n")

    lat, lon, country = geo_lookup(ip)
    socketio.emit("alert", {
        "ip": ip, "type": "DDoS", "severity": "Critical",
        "mitre": "T1498", "lat": lat, "lon": lon, "country": country
    })
    return {"status": "ddos simulated"}


@app.route("/simulate/sql")
@login_required
def sql():
    ip = "45.12.23.1"
    with open("logs/server.log", "a") as f:
        f.write(f"Login attempt ' OR 1=1 -- from {ip}\n")

    lat, lon, country = geo_lookup(ip)
    socketio.emit("alert", {
        "ip": ip, "type": "SQL Injection", "severity": "Medium",
        "mitre": "T1190", "lat": lat, "lon": lon, "country": country
    })
    return {"status": "sql simulated"}


@app.route("/simulate/xss")
@login_required
def xss():
    ip = "66.77.88.99"
    with open("logs/server.log", "a") as f:
        f.write(f"Search query <script>alert('xss')</script> from {ip}\n")

    lat, lon, country = geo_lookup(ip)
    socketio.emit("alert", {
        "ip": ip, "type": "XSS", "severity": "Medium",
        "mitre": "T1059", "lat": lat, "lon": lon, "country": country
    })
    return {"status": "xss simulated"}


# ==================================================
# LOGS PAGE
# ==================================================

@app.route("/logs")
@login_required
def logs_page():
    try:
        with open("logs/server.log", "r") as f:
            content = f.read()
    except:
        content = "No logs found."
    return render_template("logs.html", log_data=content)


# ==================================================
# MAIN DASHBOARD  —  builds map_data with geo coords
# ==================================================

@app.route("/")
@login_required
def index():
    alerts = get_alerts()
    ip_activity = {}
    map_data = []
    seen_ips = set()

    for a in alerts:
        ip  = a["ip"]
        sev = a["severity"]

        if sev.lower() in ["high", "critical"]:
            block_ip(ip)

        ip_activity[ip] = ip_activity.get(ip, 0) + 1

        # Only geo-lookup each unique IP once
        if ip not in seen_ips:
            seen_ips.add(ip)
            lat, lon, country = geo_lookup(ip)
            if lat is not None and lon is not None:
                map_data.append({
                    "ip": ip,
                    "lat": lat,
                    "lon": lon,
                    "country": country,
                    "attack_type": a["attack_type"]
                })

    return render_template(
        "index.html",
        alerts=alerts,
        ip_labels=list(ip_activity.keys()),
        ip_values=list(ip_activity.values()),
        blocked_ips=get_blocked_ips(),
        map_data=map_data        # ← now has real coordinates
    )


# ==================================================
# RUN
# ==================================================

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000)