import json, sqlite3, threading, time, os
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

EVE_LOG  = "/var/log/suricata/eve.json"
DB_PATH  = os.path.join(os.path.dirname(__file__), "siem.db")

# ── DB SETUP ──────────────────────────────────────────────
def init_db():
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            event_type TEXT,
            src_ip TEXT,
            dest_ip TEXT,
            src_port INTEGER,
            dest_port INTEGER,
            proto TEXT,
            alert_signature TEXT,
            alert_severity INTEGER,
            alert_category TEXT,
            http_url TEXT,
            dns_query TEXT,
            raw TEXT
        )
    """)
    con.commit()
    con.close()

def insert_event(evt: dict):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    alert = evt.get("alert", {})
    http  = evt.get("http", {})
    dns   = evt.get("dns", {})
    cur.execute("""
        INSERT INTO events (timestamp, event_type, src_ip, dest_ip,
            src_port, dest_port, proto, alert_signature, alert_severity,
            alert_category, http_url, dns_query, raw)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        evt.get("timestamp"),
        evt.get("event_type"),
        evt.get("src_ip"),
        evt.get("dest_ip"),
        evt.get("src_port"),
        evt.get("dest_port"),
        evt.get("proto"),
        alert.get("signature"),
        alert.get("severity"),
        alert.get("category"),
        http.get("url"),
        dns.get("rrname"),
        json.dumps(evt)
    ))
    con.commit()
    con.close()

# ── LOG TAILER ────────────────────────────────────────────
def tail_eve():
    """Wait for eve.json to exist, then tail it continuously."""
    print(f"[tailer] waiting for {EVE_LOG} ...")
    while not os.path.exists(EVE_LOG):
        time.sleep(2)

    print(f"[tailer] watching {EVE_LOG}")
    with open(EVE_LOG, "r") as f:
        f.seek(0, 2)  # seek to end, only read new lines
        while True:
            line = f.readline()
            if line:
                try:
                    evt = json.loads(line.strip())
                    insert_event(evt)
                except json.JSONDecodeError:
                    pass
            else:
                time.sleep(0.2)

# ── API ROUTES ────────────────────────────────────────────
def query(sql, params=()):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute(sql, params).fetchall()
    con.close()
    return [dict(r) for r in rows]

@app.route("/api/events")
def events():
    limit  = request.args.get("limit", 200)
    etype  = request.args.get("type", None)
    sql    = "SELECT * FROM events"
    params = []
    if etype:
        sql += " WHERE event_type = ?"
        params.append(etype)
    sql += f" ORDER BY id DESC LIMIT {int(limit)}"
    return jsonify(query(sql, params))

@app.route("/api/alerts")
def alerts():
    rows = query("""
        SELECT * FROM events WHERE event_type='alert'
        ORDER BY id DESC LIMIT 100
    """)
    return jsonify(rows)

@app.route("/api/stats")
def stats():
    total     = query("SELECT COUNT(*) as c FROM events")[0]["c"]
    alert_cnt = query("SELECT COUNT(*) as c FROM events WHERE event_type='alert'")[0]["c"]
    dns_cnt   = query("SELECT COUNT(*) as c FROM events WHERE event_type='dns'")[0]["c"]
    http_cnt  = query("SELECT COUNT(*) as c FROM events WHERE event_type='http'")[0]["c"]
    top_src   = query("""SELECT src_ip, COUNT(*) as hits FROM events
                         WHERE src_ip IS NOT NULL
                         GROUP BY src_ip ORDER BY hits DESC LIMIT 5""")
    top_sigs  = query("""SELECT alert_signature, COUNT(*) as hits FROM events
                         WHERE event_type='alert' AND alert_signature IS NOT NULL
                         GROUP BY alert_signature ORDER BY hits DESC LIMIT 5""")
    severity  = query("""SELECT alert_severity, COUNT(*) as hits FROM events
                         WHERE event_type='alert' AND alert_severity IS NOT NULL
                         GROUP BY alert_severity ORDER BY alert_severity""")
    timeline  = query("""
        SELECT substr(timestamp,1,16) as minute, COUNT(*) as hits
        FROM events GROUP BY minute ORDER BY minute DESC LIMIT 30
    """)
    return jsonify({
        "total": total, "alerts": alert_cnt,
        "dns": dns_cnt, "http": http_cnt,
        "top_sources": top_src,
        "top_signatures": top_sigs,
        "severity_dist": severity,
        "timeline": list(reversed(timeline))
    })

# ── SERVE DASHBOARD ───────────────────────────────────────
@app.route("/")
def dashboard():
    return send_from_directory(os.path.dirname(os.path.abspath(__file__)), "dashboard.html")

# ── MAIN ──────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    t = threading.Thread(target=tail_eve, daemon=True)
    t.start()
    print("[SIEM] backend running at http://localhost:3000")
    app.run(host="0.0.0.0", port=3000, debug=False)