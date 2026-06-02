def calculate_risk(username, ip_address, user_agent, status, ip_intel=None):
    """
    Phase 2 risk scoring engine.
    Adds geo/IP intelligence based scoring.
    """

    score = 0

    if status == "failed":
        score += 35

    if ip_address in ["127.0.0.1", "::1"]:
        score += 5
    else:
        score += 10

    suspicious_keywords = [
        "sqlmap",
        "nikto",
        "nmap",
        "masscan",
        "curl",
        "python-requests",
        "wget",
        "bot",
        "scanner"
    ]

    user_agent_lower = user_agent.lower()

    for keyword in suspicious_keywords:
        if keyword in user_agent_lower:
            score += 25
            break

    if not username:
        score += 10

    if ip_intel:
        if ip_intel.get("is_proxy"):
            score += 25

        if ip_intel.get("is_vpn"):
            score += 25

        if ip_intel.get("country") not in ["Private Network", "Unknown"]:
            score += 5

    if score >= 70:
        level = "High"
    elif score >= 40:
        level = "Medium"
    else:
        level = "Low"

    return score, level
