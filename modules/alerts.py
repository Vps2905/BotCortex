from datetime import datetime, timedelta


def generate_alerts(db, AlertModel, EventModel, current_event):
    """
    Generates alerts from login events.
    """

    alerts = []

    if current_event.status == "failed":
        alerts.append(
            AlertModel(
                alert_type="Failed Login",
                message=f"Failed login attempt for username '{current_event.username}' from IP {current_event.ip_address}",
                severity="Medium",
                ip_address=current_event.ip_address,
                username=current_event.username
            )
        )

    if current_event.risk_score >= 70:
        alerts.append(
            AlertModel(
                alert_type="High Risk Login Event",
                message=f"High risk event detected from IP {current_event.ip_address} with score {current_event.risk_score}",
                severity="High",
                ip_address=current_event.ip_address,
                username=current_event.username
            )
        )

    ten_minutes_ago = datetime.utcnow() - timedelta(minutes=10)

    failed_count = EventModel.query.filter(
        EventModel.ip_address == current_event.ip_address,
        EventModel.status == "failed",
        EventModel.timestamp >= ten_minutes_ago
    ).count()

    if failed_count >= 3:
        alerts.append(
            AlertModel(
                alert_type="Multiple Failed Logins",
                message=f"{failed_count} failed login attempts from IP {current_event.ip_address} within 10 minutes",
                severity="High",
                ip_address=current_event.ip_address,
                username=current_event.username
            )
        )

    return alerts
