import requests


PRIVATE_IPS = ["127.0.0.1", "::1", "localhost"]


def is_private_or_local_ip(ip_address):
    if not ip_address:
        return True

    if ip_address in PRIVATE_IPS:
        return True

    private_prefixes = (
        "10.",
        "192.168.",
        "172.16.",
        "172.17.",
        "172.18.",
        "172.19.",
        "172.20.",
        "172.21.",
        "172.22.",
        "172.23.",
        "172.24.",
        "172.25.",
        "172.26.",
        "172.27.",
        "172.28.",
        "172.29.",
        "172.30.",
        "172.31."
    )

    return ip_address.startswith(private_prefixes)


def get_ip_intelligence(ip_address):
    """
    Gets city, country, ISP, latitude, longitude for public IP.
    For local/private IP, returns safe local placeholder.
    """

    if is_private_or_local_ip(ip_address):
        return {
            "city": "Localhost",
            "country": "Private Network",
            "isp": "Local Machine",
            "latitude": 0.0,
            "longitude": 0.0,
            "is_proxy": False,
            "is_vpn": False,
            "source": "local"
        }

    try:
        url = f"http://ip-api.com/json/{ip_address}?fields=status,message,country,city,lat,lon,isp,proxy,hosting,query"
        response = requests.get(url, timeout=5)
        data = response.json()

        if data.get("status") != "success":
            return {
                "city": "Unknown",
                "country": "Unknown",
                "isp": "Unknown",
                "latitude": 0.0,
                "longitude": 0.0,
                "is_proxy": False,
                "is_vpn": False,
                "source": "api-error"
            }

        return {
            "city": data.get("city") or "Unknown",
            "country": data.get("country") or "Unknown",
            "isp": data.get("isp") or "Unknown",
            "latitude": data.get("lat") or 0.0,
            "longitude": data.get("lon") or 0.0,
            "is_proxy": bool(data.get("proxy")),
            "is_vpn": bool(data.get("hosting")),
            "source": "ip-api"
        }

    except Exception:
        return {
            "city": "Unknown",
            "country": "Unknown",
            "isp": "Unknown",
            "latitude": 0.0,
            "longitude": 0.0,
            "is_proxy": False,
            "is_vpn": False,
            "source": "exception"
        }
