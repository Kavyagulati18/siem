import sqlite3
import time
import os
import statistics

DB = "database.db"

ip_count = {}
req_count = {}
history = []

# 🔌 socketio + flask app instances
socketio = None
flask_app = None


# ======================================================
# INJECTIONS
# ======================================================

def set_socketio(sio):
    global socketio
    socketio = sio


def set_app(a):
    global flask_app
    flask_app = a  # ✅ FIX: needed to emit from background thread


# ======================================================
# MITRE + RISK
# ======================================================

MITRE_MAP = {
    "Brute Force":      "T1110 - Credential Access",
    "SQL Injection":    "T1190 - Initial Access",
    "XSS Attack":       "T1059 - Execution",
    "DDoS":             "T1498 - Impact",
    "Account Takeover": "T1078 - Valid Accounts",
    "Anomaly":          "T1046 - Discovery"
}

RISK_SCORE = {
    "Low":      20,
    "Medium":   50,
    "High":     80,
    "Critical": 100
}


# ======================================================
# SAVE ALERT
# ======================================================

def save_alert(ip, typ, sev):

    mitre = MITRE_MAP.get(typ, "Unknown")
    risk  = RISK_SCORE.get(sev, 0)

    db  = sqlite3.connect(DB)
    cur = db.cursor()

    try:
        cur.execute("""
            INSERT INTO alerts
            (ip, attack_type, severity, mitre, risk, timestamp)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        """, (ip, typ, sev, mitre, risk))
        db.commit()

    except Exception as e:
        print("DB ERROR:", e)

    db.close()

    # ✅ FIX: emit inside app context so it works from background thread
    if socketio and flask_app:
        with flask_app.app_context():
            socketio.emit("alert", {
                "ip":       ip,
                "type":     typ,
                "severity": sev,
                "mitre":    mitre,
                "risk":     risk
            })
            print("ALERT EMITTED")


# ======================================================
# AI ANOMALY
# ======================================================

def detect_anomaly(ip):

    history.append(req_count.get(ip, 0))

    if len(history) > 10:
        avg     = statistics.mean(history)
        current = req_count.get(ip, 0)

        if current > avg * 2:
            save_alert(ip, "Anomaly", "High")


# ======================================================
# SQLI
# ======================================================

def detect_sql(line, ip):

    keywords = [
        "' OR 1=1",
        "UNION SELECT",
        "DROP TABLE",
        "--"
    ]

    for k in keywords:
        if k.lower() in line.lower():
            save_alert(ip, "SQL Injection", "Critical")


# ======================================================
# XSS
# ======================================================

def detect_xss(line, ip):

    patterns = [
        "<script>",
        "javascript:",
        "onerror=",
        "alert("
    ]

    for p in patterns:
        if p.lower() in line.lower():
            save_alert(ip, "XSS Attack", "High")


# ======================================================
# PROCESS LOG LINE
# ======================================================

def process(line):

    print("LOG DETECTED:", line.strip())

    parts = line.strip().split()
    ip    = parts[-1] if parts else "unknown"

    # 🟡 BRUTE FORCE
    if "Failed" in line:
        ip_count[ip] = ip_count.get(ip, 0) + 1
        if ip_count[ip] >= 5:
            save_alert(ip, "Brute Force", "High")

    # 🔴 DDOS
    if "Request" in line:
        req_count[ip] = req_count.get(ip, 0) + 1
        if req_count[ip] >= 20:
            save_alert(ip, "DDoS", "Critical")

    # 🔐 ACCOUNT TAKEOVER
    if "Success" in line and ip_count.get(ip, 0) >= 5:
        save_alert(ip, "Account Takeover", "Critical")

    # 💉 SQLI
    detect_sql(line, ip)

    # ⚡ XSS
    detect_xss(line, ip)

    # 🧠 ANOMALY
    detect_anomaly(ip)


# ======================================================
# MONITOR LOGS (background thread)
# ======================================================

def monitor_logs(path):

    print("MONITORING:", path)

    os.makedirs("logs", exist_ok=True)

    if not os.path.exists(path):
        open(path, "w").close()

    with open(path, "r") as f:

        # move to end — only pick up NEW lines
        f.seek(0, os.SEEK_END)

        while True:
            line = f.readline()

            if not line:
                time.sleep(0.5)
                continue

            process(line)