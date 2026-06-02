import re


SQLI_PATTERNS = [
    r"(\bor\b|\band\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
    r"union\s+select",
    r"select\s+.*\s+from",
    r"insert\s+into",
    r"drop\s+table",
    r"sleep\s*\(",
    r"benchmark\s*\(",
    r"--",
    r"#",
    r"/\*",
    r"\*/",
]

XSS_PATTERNS = [
    r"<script",
    r"</script>",
    r"javascript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"alert\s*\(",
    r"document\.cookie",
    r"<img",
    r"<svg",
]

TRAVERSAL_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e",
    r"%252e%252e",
    r"/etc/passwd",
    r"boot\.ini",
    r"win\.ini",
]

SENSITIVE_PATHS = [
    "/admin",
    "/phpmyadmin",
    "/wp-admin",
    "/.env",
    "/config",
    "/backup",
    "/db",
    "/database",
    "/server-status",
    "/ftp",
]

SCANNER_UA_KEYWORDS = [
    "sqlmap",
    "nikto",
    "nmap",
    "masscan",
    "acunetix",
    "nessus",
    "burp",
    "zap",
    "python-requests",
    "curl",
    "wget",
]


def _match_patterns(value, patterns):
    if not value:
        return False

    value_lower = value.lower()

    for pattern in patterns:
        if re.search(pattern, value_lower, re.IGNORECASE):
            return True

    return False


def detect_web_attack(path, query_string, user_agent, method):
    """
    Detects suspicious web request patterns.
    Returns attack_type, severity, risk_score, reason.
    """

    full_payload = f"{path} {query_string}".lower()
    user_agent_lower = (user_agent or "").lower()

    detections = []
    score = 0

    if _match_patterns(full_payload, SQLI_PATTERNS):
        detections.append("SQL Injection Attempt")
        score += 40

    if _match_patterns(full_payload, XSS_PATTERNS):
        detections.append("XSS Attempt")
        score += 40

    if _match_patterns(full_payload, TRAVERSAL_PATTERNS):
        detections.append("Directory Traversal Attempt")
        score += 45

    for sensitive_path in SENSITIVE_PATHS:
        if path.lower().startswith(sensitive_path):
            detections.append("Sensitive Path Access")
            score += 25
            break

    for keyword in SCANNER_UA_KEYWORDS:
        if keyword in user_agent_lower:
            detections.append("Scanner User-Agent")
            score += 30
            break

    if method.upper() in ["PUT", "DELETE", "PATCH"]:
        detections.append("Unusual HTTP Method")
        score += 20

    if not detections:
        return {
            "is_suspicious": False,
            "attack_type": "Normal",
            "severity": "Low",
            "risk_score": 0,
            "reason": "No suspicious pattern detected"
        }

    if score >= 70:
        severity = "High"
    elif score >= 35:
        severity = "Medium"
    else:
        severity = "Low"

    return {
        "is_suspicious": True,
        "attack_type": ", ".join(sorted(set(detections))),
        "severity": severity,
        "risk_score": min(score, 100),
        "reason": f"Detected: {', '.join(sorted(set(detections)))}"
    }
