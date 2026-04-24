from flask import Flask, request, render_template_string
import requests
from datetime import datetime

app = Flask(__name__)

LOG_FILE = "logs.txt"

# ------------------ HTML DASHBOARD ------------------

HTML = """
<h2>🚀 Visitor Intelligence Dashboard</h2>

<div id="map" style="height: 400px;"></div>

<table border="1" cellpadding="5">
<tr>
<th>Time</th>
<th>IP</th>
<th>City</th>
<th>Country</th>
<th>ISP</th>
<th>VPN?</th>
<th>Device</th>
</tr>

{% for row in data %}
<tr>
<td>{{row[0]}}</td>
<td>{{row[1]}}</td>
<td>{{row[2]}}</td>
<td>{{row[3]}}</td>
<td>{{row[4]}}</td>

{% if row[7] == "True" %}
<td style="color:red;">Yes</td>
{% else %}
<td style="color:green;">No</td>
{% endif %}

<td>{{row[8]}}</td>
</tr>
{% endfor %}
</table>

<link rel="stylesheet" href="https://unpkg.com/leaflet/dist/leaflet.css" />
<script src="https://unpkg.com/leaflet/dist/leaflet.js"></script>

<script>
var map = L.map('map').setView([20, 78], 5);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png').addTo(map);

{% for row in data %}
L.marker([{{row[5]}}, {{row[6]}}])
.addTo(map)
.bindPopup("IP: {{row[1]}}<br>{{row[2]}}, {{row[3]}}");
{% endfor %}
</script>
"""

# ------------------ GET LOCATION ------------------

def get_location(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}").json()
        return (
            res.get("city"),
            res.get("country"),
            res.get("isp"),
            res.get("lat"),
            res.get("lon"),
            res.get("proxy")
        )
    except:
        return "N/A", "N/A", "N/A", 0, 0, False

# ------------------ TRACK VISITOR ------------------

@app.route('/')
def track():
    # Get real IP behind proxy/tunnel
    ip = request.headers.get('CF-Connecting-IP') or \
         request.headers.get('X-Forwarded-For') or \
         request.remote_addr

    device = request.headers.get('User-Agent')

    city, country, isp, lat, lon, proxy = get_location(ip)

    time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log = f"{time},{ip},{city},{country},{isp},{lat},{lon},{proxy},{device}\n"

    with open(LOG_FILE, "a") as f:
        f.write(log)

    print(log)

    return "Logged 👀"

# ------------------ DASHBOARD ------------------

@app.route('/dashboard')
def dashboard():
    data = []
    try:
        with open(LOG_FILE, "r") as f:
            for line in f.readlines():
                data.append(line.strip().split(","))
    except:
        pass

    return render_template_string(HTML, data=data)

# ------------------ RUN APP ------------------

app.run(host='0.0.0.0', port=5000)
