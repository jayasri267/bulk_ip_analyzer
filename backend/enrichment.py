# backend/enrichment.py
import requests

IPWHOIS_URL = "https://ipwhois.app/json/{}"

def get_geo_info(ip: str) -> dict:
    try:
        resp = requests.get(IPWHOIS_URL.format(ip), timeout=8)
        data = resp.json()
        return {
            "IP": ip,
            "Country": data.get("country", "N/A"),
            "CountryCode": data.get("country_code", None),
            "Region": data.get("region", "N/A"),
            "City": data.get("city", "N/A"),
            "ISP": data.get("isp", "N/A")
        }
    except Exception:
        return {
            "IP": ip,
            "Country": "N/A",
            "CountryCode": None,
            "Region": "N/A",
            "City": "N/A",
            "ISP": "N/A"
        }
