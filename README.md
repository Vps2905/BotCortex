# 🚀 Real-Time IP Intelligence & Threat Detection System

A Flask-based cybersecurity project that captures and analyzes visitor metadata in real time.

---

## 🔍 Features

- Real client IP extraction (handles proxy/tunnel environments)
- Device fingerprinting (User-Agent)
- Geo-location (City, Country, ISP, Latitude/Longitude)
- Live map visualization (Leaflet.js)
- VPN / Proxy detection
- Logging + dashboard interface

---

## 🧠 Tech Stack

- Python (Flask)
- Requests API
- Leaflet.js (map visualization)
- Cloudflare Tunnel (public access)

---

## ⚙️ Setup

```bash
git clone https://github.com/Vps2905/BotCortex.git
cd BotCortex
python3 -m venv venv
source venv/bin/activate
pip install flask requests
python app.py
