import sqlite3

DB = "database.db"

def init_db():

    db = sqlite3.connect(DB)

    cur = db.cursor()

    # USERS
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )
    """)

    # ALERTS
    cur.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            attack_type TEXT,
            severity TEXT,
            mitre TEXT,
            risk INTEGER,
            timestamp TEXT
        )
    """)

    # BLOCKED IPS
    cur.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE
        )
    """)

    # DEFAULT LOGIN
    cur.execute("""
        INSERT OR IGNORE INTO users
        (id, username, password)
        VALUES
        (1, 'admin', 'admin')
    """)

    db.commit()

    db.close()