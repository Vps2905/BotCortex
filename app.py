from flask import Flask, render_template, request, redirect, url_for, session, Response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import csv
import io

from modules.fingerprint import parse_user_agent, generate_fingerprint, get_client_ip
from modules.risk_engine import calculate_risk
from modules.alerts import generate_alerts
from modules.ip_intel import get_ip_intelligence
from modules.web_attack_detector import detect_web_attack


app = Flask(__name__)
app.config["SECRET_KEY"] = "change-this-secret-key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///threatpulse.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


# -------------------------
# Database Models
# -------------------------

class LoginEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(120))
    ip_address = db.Column(db.String(100))
    user_agent = db.Column(db.Text)

    browser = db.Column(db.String(100))
    os = db.Column(db.String(100))
    device = db.Column(db.String(100))
    fingerprint = db.Column(db.String(128))

    city = db.Column(db.String(120), default="Unknown")
    country = db.Column(db.String(120), default="Unknown")
    isp = db.Column(db.String(200), default="Unknown")
    latitude = db.Column(db.Float, default=0.0)
    longitude = db.Column(db.Float, default=0.0)
    is_proxy = db.Column(db.Boolean, default=False)
    is_vpn = db.Column(db.Boolean, default=False)

    status = db.Column(db.String(20))  # success / failed
    risk_score = db.Column(db.Integer)
    risk_level = db.Column(db.String(20))

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    alert_type = db.Column(db.String(120))
    message = db.Column(db.Text)
    severity = db.Column(db.String(20))
    ip_address = db.Column(db.String(100))
    username = db.Column(db.String(120))

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class WebRequestEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    ip_address = db.Column(db.String(100))
    method = db.Column(db.String(20))
    path = db.Column(db.String(500))
    query_string = db.Column(db.Text)
    user_agent = db.Column(db.Text)

    attack_type = db.Column(db.String(200))
    severity = db.Column(db.String(20))
    risk_score = db.Column(db.Integer)
    reason = db.Column(db.Text)

    is_suspicious = db.Column(db.Boolean, default=False)

    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# -------------------------
# Demo User
# -------------------------

DEMO_USER = {
    "username": "admin",
    "password": "Admin@123"
}


# -------------------------
# Web Attack Monitor Middleware
# -------------------------

@app.before_request
def monitor_web_requests():
    """
    Logs web requests and detects suspicious patterns.
    This works like a simple mini-WAF/SOC web request monitor.
    """

    ignored_paths = [
        "/static",
        "/favicon.ico",
        "/dashboard",
        "/events",
        "/alerts",
        "/web-attacks",
        "/export/events.csv",
        "/export/web-attacks.csv"
    ]

    for ignored in ignored_paths:
        if request.path.startswith(ignored):
            return

    try:
        ip_address = get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "Unknown")
        query_string = request.query_string.decode("utf-8", errors="ignore")

        detection = detect_web_attack(
            path=request.path,
            query_string=query_string,
            user_agent=user_agent,
            method=request.method
        )

        web_event = WebRequestEvent(
            ip_address=ip_address,
            method=request.method,
            path=request.path,
            query_string=query_string,
            user_agent=user_agent,
            attack_type=detection["attack_type"],
            severity=detection["severity"],
            risk_score=detection["risk_score"],
            reason=detection["reason"],
            is_suspicious=detection["is_suspicious"]
        )

        db.session.add(web_event)

        if detection["is_suspicious"]:
            alert = Alert(
                alert_type="Web Attack Detected",
                message=f"{detection['attack_type']} detected on {request.path} from IP {ip_address}",
                severity=detection["severity"],
                ip_address=ip_address,
                username="-"
            )
            db.session.add(alert)

        db.session.commit()

    except Exception:
        db.session.rollback()


# -------------------------
# Routes
# -------------------------

@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        ip_address = get_client_ip(request)
        user_agent = request.headers.get("User-Agent", "Unknown")

        parsed = parse_user_agent(user_agent)
        fingerprint = generate_fingerprint(ip_address, user_agent)
        ip_intel = get_ip_intelligence(ip_address)

        status = "success" if (
            username == DEMO_USER["username"] and password == DEMO_USER["password"]
        ) else "failed"

        risk_score, risk_level = calculate_risk(
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            status=status,
            ip_intel=ip_intel
        )

        event = LoginEvent(
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,

            browser=parsed["browser"],
            os=parsed["os"],
            device=parsed["device"],
            fingerprint=fingerprint,

            city=ip_intel["city"],
            country=ip_intel["country"],
            isp=ip_intel["isp"],
            latitude=ip_intel["latitude"],
            longitude=ip_intel["longitude"],
            is_proxy=ip_intel["is_proxy"],
            is_vpn=ip_intel["is_vpn"],

            status=status,
            risk_score=risk_score,
            risk_level=risk_level
        )

        db.session.add(event)
        db.session.commit()

        new_alerts = generate_alerts(
            db=db,
            AlertModel=Alert,
            EventModel=LoginEvent,
            current_event=event
        )

        for alert in new_alerts:
            db.session.add(alert)

        db.session.commit()

        if status == "success":
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("dashboard"))

        error = "Invalid username or password"

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
def dashboard():
    total_events = LoginEvent.query.count()
    success_count = LoginEvent.query.filter_by(status="success").count()
    failed_count = LoginEvent.query.filter_by(status="failed").count()
    alert_count = Alert.query.count()
    high_risk_count = LoginEvent.query.filter(LoginEvent.risk_score >= 70).count()

    total_web_requests = WebRequestEvent.query.count()
    suspicious_web_requests = WebRequestEvent.query.filter_by(is_suspicious=True).count()
    sqli_count = WebRequestEvent.query.filter(
        WebRequestEvent.attack_type.like("%SQL Injection%")
    ).count()
    xss_count = WebRequestEvent.query.filter(
        WebRequestEvent.attack_type.like("%XSS%")
    ).count()
    traversal_count = WebRequestEvent.query.filter(
        WebRequestEvent.attack_type.like("%Directory Traversal%")
    ).count()

    recent_events = LoginEvent.query.order_by(LoginEvent.timestamp.desc()).limit(10).all()
    recent_alerts = Alert.query.order_by(Alert.timestamp.desc()).limit(10).all()

    map_events = LoginEvent.query.filter(
        LoginEvent.latitude != 0.0,
        LoginEvent.longitude != 0.0
    ).order_by(LoginEvent.timestamp.desc()).limit(25).all()

    return render_template(
        "dashboard.html",
        total_events=total_events,
        success_count=success_count,
        failed_count=failed_count,
        alert_count=alert_count,
        high_risk_count=high_risk_count,

        total_web_requests=total_web_requests,
        suspicious_web_requests=suspicious_web_requests,
        sqli_count=sqli_count,
        xss_count=xss_count,
        traversal_count=traversal_count,

        recent_events=recent_events,
        recent_alerts=recent_alerts,
        map_events=map_events
    )


@app.route("/events")
def events():
    all_events = LoginEvent.query.order_by(LoginEvent.timestamp.desc()).all()
    return render_template("events.html", events=all_events)


@app.route("/alerts")
def alerts():
    all_alerts = Alert.query.order_by(Alert.timestamp.desc()).all()
    return render_template("alerts.html", alerts=all_alerts)


@app.route("/web-attacks")
def web_attacks():
    all_requests = WebRequestEvent.query.order_by(
        WebRequestEvent.timestamp.desc()
    ).limit(200).all()

    return render_template(
        "web_attacks.html",
        requests=all_requests
    )


# -------------------------
# CSV Exports
# -------------------------

@app.route("/export/events.csv")
def export_events():
    events = LoginEvent.query.order_by(LoginEvent.timestamp.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Username",
        "IP Address",
        "City",
        "Country",
        "ISP",
        "Latitude",
        "Longitude",
        "Proxy",
        "VPN",
        "Browser",
        "OS",
        "Device",
        "Fingerprint",
        "Status",
        "Risk Score",
        "Risk Level",
        "Timestamp"
    ])

    for event in events:
        writer.writerow([
            event.id,
            event.username,
            event.ip_address,
            event.city,
            event.country,
            event.isp,
            event.latitude,
            event.longitude,
            event.is_proxy,
            event.is_vpn,
            event.browser,
            event.os,
            event.device,
            event.fingerprint,
            event.status,
            event.risk_score,
            event.risk_level,
            event.timestamp
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=login_events.csv"}
    )


@app.route("/export/web-attacks.csv")
def export_web_attacks():
    web_events = WebRequestEvent.query.order_by(WebRequestEvent.timestamp.desc()).all()

    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Time",
        "IP Address",
        "Method",
        "Path",
        "Query String",
        "User-Agent",
        "Suspicious",
        "Attack Type",
        "Severity",
        "Risk Score",
        "Reason"
    ])

    for event in web_events:
        writer.writerow([
            event.id,
            event.timestamp,
            event.ip_address,
            event.method,
            event.path,
            event.query_string,
            event.user_agent,
            event.is_suspicious,
            event.attack_type,
            event.severity,
            event.risk_score,
            event.reason
        ])

    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=web_attack_events.csv"}
    )


# -------------------------
# Utility Route
# -------------------------

@app.route("/reset")
def reset():
    db.drop_all()
    db.create_all()
    return redirect(url_for("login"))


# -------------------------
# App Start
# -------------------------

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(host="0.0.0.0", port=5000, debug=True)
