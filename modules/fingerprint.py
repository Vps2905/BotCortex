import hashlib
from user_agents import parse


def get_client_ip(request):
    """
    Extracts real client IP where possible.
    Works with proxy/tunnel headers also.
    """

    forwarded_for = request.headers.get("X-Forwarded-For")
    real_ip = request.headers.get("X-Real-IP")
    cf_ip = request.headers.get("CF-Connecting-IP")

    if cf_ip:
        return cf_ip

    if real_ip:
        return real_ip

    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    return request.remote_addr or "Unknown"


def parse_user_agent(user_agent_string):
    """
    Parses browser, OS, and device info from User-Agent.
    """

    ua = parse(user_agent_string)

    browser = f"{ua.browser.family} {ua.browser.version_string}".strip()
    os = f"{ua.os.family} {ua.os.version_string}".strip()

    if ua.is_mobile:
        device = "Mobile"
    elif ua.is_tablet:
        device = "Tablet"
    elif ua.is_pc:
        device = "Desktop"
    elif ua.is_bot:
        device = "Bot"
    else:
        device = "Unknown"

    return {
        "browser": browser,
        "os": os,
        "device": device
    }


def generate_fingerprint(ip_address, user_agent):
    """
    Creates simple repeatable device fingerprint.
    """

    raw = f"{ip_address}|{user_agent}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]
