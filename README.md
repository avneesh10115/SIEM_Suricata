# SuriSIEM — Suricata-based SIEM
A lightweight Security Information and Event Management (SIEM) system built on Suricata IDS. Captures live network traffic, detects threats using community rules, stores events in SQLite, and displays them on a real-time web dashboard.

---

## Requirements

- Windows 10/11 with WSL2 (Ubuntu)
- Python 3.10+
- Internet connection (for rule updates)

---

## Project Files

```
siem-project/
├── backend.py       ← Flask API server + Suricata log tailer
├── dashboard.html   ← Web dashboard (open in browser)
└── siem.db          ← SQLite database (auto-created on first run)
```

---

## Setup Instructions

### Step 1 — Open WSL
Launch Ubuntu from your Start menu or run `wsl` in PowerShell.

---

### Step 2 — Install Suricata

```bash
sudo apt update
sudo apt install -y suricata nmap bind9-dnsutils
```

Verify installation:
```bash
suricata --version
```

---

### Step 3 — Download Community Rules

```bash
sudo suricata-update
```

---

### Step 4 — Find Your Network Interface

```bash
ip a
```

Look for an interface with a `172.x.x.x` IP — this is your WSL ethernet interface. It is usually named `eth0`.

---

### Step 5 — Configure Suricata

Open the config file:
```bash
sudo nano /etc/suricata/suricata.yaml
```

Make these two changes:

**1. Set your HOME_NET** — use your WSL subnet (replace with your actual subnet):
```yaml
HOME_NET: "[172.28.144.0/20]"
```

**2. Set your interface:**
```yaml
af-packet:
  - interface: eth0
```

Save and exit: `Ctrl+X` → `Y` → `Enter`

---

### Step 6 — Fix Log Permissions

```bash
sudo chmod 644 /var/log/suricata/eve.json
```

---

### Step 7 — Start Suricata

```bash
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D
```

Verify it is running:
```bash
sudo tail -f /var/log/suricata/eve.json
```

You should see JSON lines appearing. Press `Ctrl+C` to stop tailing.

---

### Step 8 — Install Python Dependencies

```bash
pip3 install flask flask-cors --break-system-packages
```

---

### Step 9 — Set Up Project Folder

```bash
mkdir ~/siem-project
cd ~/siem-project
```

Copy `backend.py` and `dashboard.html` into this folder.

---

### Step 10 — Start the Backend

```bash
cd ~/siem-project
python3 backend.py
```

You should see:
```
[tailer] watching /var/log/suricata/eve.json
[SIEM] backend running at http://localhost:3000
```

---

### Step 11 — Open the Dashboard

In your **Windows browser**, navigate to:
```
http://localhost:3000
```

The dashboard will load and begin showing live data. It auto-refreshes every 10 seconds. The status indicator in the top-right corner will show green "live" when the backend is connected.

---

## Generating Test Alerts

Run these commands in WSL to trigger Suricata detection rules:

```bash
# Triggers GPL ATTACK_RESPONSE rule
curl http://testmyids.com

# Triggers custom user-agent alert
curl -A "BlackSun" http://testmyids.com --max-time 5

# Triggers ET SCAN rules (port scan)
sudo nmap -sS 172.28.2.144

# Triggers DNS logging
dig google.com
```

After running these, click **↻ refresh** on the dashboard to see the new alerts.

---

## Verifying the Pipeline

At any point you can manually check each layer:

```bash
# Check Suricata is writing events
sudo tail -f /var/log/suricata/eve.json

# Check only alerts
sudo cat /var/log/suricata/eve.json | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        e = json.loads(line)
        if e.get('event_type') == 'alert':
            print(e['timestamp'][11:19], e['alert']['signature'])
    except: pass
"

# Check backend API is responding
curl http://localhost:3000/api/stats

# Check alerts via API
curl http://localhost:3000/api/alerts
```

---

## Restarting After a Reboot

WSL does not persist running processes. After rebooting, run these in order:

```bash
# 1. Start Suricata
sudo suricata -c /etc/suricata/suricata.yaml -i eth0 -D

# 2. Fix permissions
sudo chmod 644 /var/log/suricata/eve.json

# 3. Start backend
cd ~/siem-project
python3 backend.py
```

Then open `http://localhost:3000` in your browser.

---

## Troubleshooting

**Dashboard shows "backend offline"**
→ Make sure `python3 backend.py` is running in WSL.

**Stats show zeros / no events**
→ Suricata may not be running. Check with `sudo tail -f /var/log/suricata/eve.json`.

**eve.json not found error in backend**
→ Suricata has not written any events yet. Generate some traffic and wait a few seconds.

**nmap says "requires root privileges"**
→ Use `sudo nmap` instead of `nmap`.

**localhost:3000 does not open in Windows browser**
→ Find your WSL IP with `hostname -I` and use that instead, e.g. `http://172.28.2.144:3000`.

**Suricata already running error on startup**
→ Run `sudo pkill suricata && sudo rm /var/run/suricata.pid` then start again.

---

## Architecture

```
Network Traffic
      ↓
 Suricata IDS          (packet capture + rule matching)
      ↓ eve.json
 backend.py            (Flask API + SQLite log parser)
      ↓ HTTP /api
 dashboard.html        (real-time web UI)
```

---

## API Endpoints

| Endpoint | Description |
|---|---|
| `GET /` | Serves the dashboard |
| `GET /api/stats` | Summary counts and top IPs/signatures |
| `GET /api/alerts` | Last 100 alerts |
| `GET /api/events` | All events (filterable by `?type=alert/dns/http/tls/flow`) |
