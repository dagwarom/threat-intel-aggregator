import base64
import ipaddress
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import feedparser
import requests
from cachetools import TTLCache
from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")
MALWAREBAZAAR_AUTH_KEY = os.getenv("MALWAREBAZAAR_AUTH_KEY")
THREATFOX_AUTH_KEY = os.getenv("THREATFOX_AUTH_KEY")
URLHAUS_AUTH_KEY = os.getenv("URLHAUS_AUTH_KEY")

REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "15"))
NEWS_CACHE_SECONDS = int(os.getenv("NEWS_CACHE_SECONDS", "600"))
MAX_IOC_LENGTH = 2048

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")

app = Flask(__name__)
app.logger.setLevel(logging.INFO)

allowed_origins = [
    origin.strip()
    for origin in os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:3000,http://127.0.0.1:3000",
    ).split(",")
    if origin.strip()
]
CORS(app, resources={r"/*": {"origins": allowed_origins}})

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per day", "30 per hour"],
    storage_uri=os.getenv("RATELIMIT_STORAGE_URI", "memory://"),
)

news_cache = TTLCache(maxsize=1, ttl=NEWS_CACHE_SECONDS)
ioc_feed_cache = TTLCache(maxsize=1, ttl=NEWS_CACHE_SECONDS)


def detect_ioc_type(ioc: str):
    if not isinstance(ioc, str):
        return "unknown"

    s = ioc.strip()
    if not s or len(s) > MAX_IOC_LENGTH:
        return "unknown"

    try:
        ipaddress.ip_address(s)
        return "ip"
    except ValueError:
        pass

    if re.fullmatch(r"[A-Fa-f0-9]{32}", s):
        return "md5"
    if re.fullmatch(r"[A-Fa-f0-9]{40}", s):
        return "sha1"
    if re.fullmatch(r"[A-Fa-f0-9]{64}", s):
        return "sha256"

    if EMAIL_RE.fullmatch(s):
        return "email"

    parsed = urlparse(s)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return "url"

    if DOMAIN_RE.fullmatch(s):
        return "domain"

    return "unknown"


def lookup_virustotal(ioc, ioc_type):
    if ioc_type == "email":
        return {"message": "No VirusTotal lookup available for email indicators"}

<<<<<<< Updated upstream
    if not VT_API_KEY:
        app.logger.warning("VirusTotal lookup skipped because VT_API_KEY is not configured")
        return {"error": "VirusTotal API key is not configured"}
=======
    ioc_type = detect_ioc_type(ioc)
    # ✅ NEW: IOC Validation
    if ioc_type == "unknown":
        return jsonify({
            "error": "Invalid IOC format. Enter valid IP, Domain, URL or Hash."
        }), 400
            
    result = {
        "ioc": ioc,
        "type": ioc_type,
        "combined_risk": "Unknown",
        "virustotal": None,
        "abuseipdb": None,
        "otx": None
    }
>>>>>>> Stashed changes

    try:
        if ioc_type == "ip":
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ioc}"
        elif ioc_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{ioc}"
        elif ioc_type == "url":
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().strip("=")
            url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        else:
            url = f"https://www.virustotal.com/api/v3/files/{ioc}"

        resp = requests.get(
            url,
            headers={"x-apikey": VT_API_KEY},
            timeout=REQUEST_TIMEOUT,
        )
        app.logger.info("VirusTotal lookup completed with status=%s", resp.status_code)

        if resp.status_code != 200:
            return {"error": f"VirusTotal lookup failed ({resp.status_code})"}

        payload = resp.json()
        attributes = payload.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        vendors = attributes.get("last_analysis_results", {})

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "country": attributes.get("country"),
            "asn": attributes.get("asn"),
            "vendors": {k: v.get("category") for k, v in vendors.items()},
        }
    except requests.RequestException:
        app.logger.exception("VirusTotal request failed")
        return {"error": "VirusTotal lookup failed"}
    except (KeyError, TypeError, ValueError):
        app.logger.exception("VirusTotal response parsing failed")
        return {"error": "VirusTotal response could not be parsed"}


def lookup_abuseipdb(ioc, ioc_type):
    if ioc_type != "ip":
        return {"message": "No data (not an IP)"}
    if not ABUSEIPDB_API_KEY:
        app.logger.warning("AbuseIPDB lookup skipped because ABUSEIPDB_API_KEY is not configured")
        return {"message": "No data (AbuseIPDB API key is not configured)"}

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ioc, "maxAgeInDays": "90"},
            timeout=REQUEST_TIMEOUT,
        )
        app.logger.info("AbuseIPDB lookup completed with status=%s", resp.status_code)

        if resp.status_code != 200:
            return {"message": "No data found"}

        data = resp.json().get("data", {})
        return {
            "reports": data.get("totalReports"),
            "abuseConfidence": data.get("abuseConfidenceScore"),
            "isp": data.get("isp"),
            "country": data.get("countryCode"),
        }
    except requests.RequestException:
        app.logger.exception("AbuseIPDB request failed")
        return {"error": "AbuseIPDB lookup failed"}
    except (KeyError, TypeError, ValueError):
        app.logger.exception("AbuseIPDB response parsing failed")
        return {"error": "AbuseIPDB response could not be parsed"}


def lookup_otx(ioc, ioc_type):
    if ioc_type not in {"ip", "domain", "md5", "sha1", "sha256"}:
        return {"message": "No data (not supported for this IOC type)"}
    if not OTX_API_KEY:
        app.logger.warning("OTX lookup skipped because OTX_API_KEY is not configured")
        return {"message": "No data (OTX API key is not configured)"}

    try:
        endpoint_type = "file" if ioc_type in {"md5", "sha1", "sha256"} else ioc_type
        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/{endpoint_type}/{ioc}/general",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            timeout=REQUEST_TIMEOUT,
        )
        app.logger.info("OTX lookup completed with status=%s", resp.status_code)

        if resp.status_code != 200:
            return {"message": "No data found"}

        data = resp.json()
        pulses = data.get("pulse_info", {}).get("pulses", [])
        return {
            "pulse_count": len(pulses),
            "malware_families": [pulse.get("name") for pulse in pulses[:5]],
            "summary": f"{len(pulses)} pulse match(es)" if pulses else "No pulse matches found",
        }
    except requests.RequestException:
        app.logger.exception("OTX request failed")
        return {"error": "OTX lookup failed"}
    except (KeyError, TypeError, ValueError):
        app.logger.exception("OTX response parsing failed")
        return {"error": "OTX response could not be parsed"}


def lookup_malwarebazaar(ioc, ioc_type):
    if ioc_type not in {"md5", "sha1", "sha256"}:
        return {"message": "No data (not supported for this IOC type)"}
    if not MALWAREBAZAAR_AUTH_KEY:
        app.logger.warning("MalwareBazaar lookup skipped because MALWAREBAZAAR_AUTH_KEY is not configured")
        return {"message": "No data (MalwareBazaar Auth-Key is not configured)"}

    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            headers={"Auth-Key": MALWAREBAZAAR_AUTH_KEY},
            data={"query": "get_info", "hash": ioc},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("query_status") not in {"ok", "hash_not_found"}:
            return {"message": "No data found"}

        samples = payload.get("data") or []
        if not samples:
            return {"message": "No data found"}

        sample = samples[0]
        signature = sample.get("signature") or "Unknown malware family"
        tags = sample.get("tags") or []
        return {
            "malware_family": signature,
            "tags": tags[:6],
            "file_name": sample.get("file_name"),
            "file_type": sample.get("file_type"),
            "summary": f"{signature} | tags: {', '.join(tags[:4])}" if tags else signature,
        }
    except requests.RequestException:
        app.logger.exception("MalwareBazaar request failed")
        return {"error": "MalwareBazaar lookup failed"}
    except (KeyError, TypeError, ValueError):
        app.logger.exception("MalwareBazaar parsing failed")
        return {"error": "MalwareBazaar response could not be parsed"}


def lookup_threatfox_hash(ioc, ioc_type):
    if ioc_type not in {"md5", "sha256"}:
        return {"message": "No data (not supported for this IOC type)"}
    if not THREATFOX_AUTH_KEY:
        app.logger.warning("ThreatFox hash lookup skipped because THREATFOX_AUTH_KEY is not configured")
        return {"message": "No data (ThreatFox Auth-Key is not configured)"}

    try:
        resp = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": THREATFOX_AUTH_KEY},
            json={"query": "search_hash", "hash": ioc},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        payload = resp.json()
        if payload.get("query_status") not in {"ok", "no_result"}:
            return {"message": "No data found"}

        matches = payload.get("data") or []
        if not matches:
            return {"message": "No data found"}

        first_match = matches[0]
        threats = sorted({
            entry.get("threat_type_desc")
            for entry in matches
            if entry.get("threat_type_desc")
        })
        return {
            "mapping_count": len(matches),
            "ioc_examples": [entry.get("ioc") for entry in matches[:3] if entry.get("ioc")],
            "threat_types": threats[:3],
            "malware_family": first_match.get("malware_printable"),
            "summary": f"{len(matches)} IOC mapping(s)" + (f" | {threats[0]}" if threats else ""),
        }
    except requests.RequestException:
        app.logger.exception("ThreatFox hash lookup failed")
        return {"error": "ThreatFox lookup failed"}
    except (KeyError, TypeError, ValueError):
        app.logger.exception("ThreatFox hash parsing failed")
        return {"error": "ThreatFox response could not be parsed"}


def score_result(result):
    provider_breakdown = []
    explanations = []

    malicious = (
        result["virustotal"].get("malicious", 0)
        if isinstance(result["virustotal"], dict)
        else 0
    )
    suspicious = (
        result["virustotal"].get("suspicious", 0)
        if isinstance(result["virustotal"], dict)
        else 0
    )
    abuse_score = (
        result["abuseipdb"].get("abuseConfidence")
        if isinstance(result["abuseipdb"], dict)
        else None
    )
    otx_hits = (
        result["otx"].get("pulse_count", 0)
        if isinstance(result["otx"], dict)
        else 0
    )
    malwarebazaar = result["malwarebazaar"] if isinstance(result["malwarebazaar"], dict) else {}
    threatfox = result["threatfox"] if isinstance(result["threatfox"], dict) else {}

    if malicious == 0 and suspicious == 0:
        vt_points = 0
    elif malicious <= 2:
        vt_points = 25
    elif malicious <= 5:
        vt_points = 45
    elif malicious <= 10:
        vt_points = 70
    else:
        vt_points = 90
    if suspicious > 0 and vt_points < 90:
        vt_points = min(90, vt_points + 10)
    if vt_points:
        provider_breakdown.append({"provider": "VirusTotal", "score": vt_points})
        explanations.append(f"VirusTotal reported {malicious} malicious and {suspicious} suspicious detection(s).")

    if abuse_score is None:
        abuse_points = 0
    else:
        abuse_value = int(abuse_score or 0)
        if abuse_value < 20:
            abuse_points = 10
        elif abuse_value <= 50:
            abuse_points = 35
        else:
            abuse_points = 60
        provider_breakdown.append({"provider": "AbuseIPDB", "score": abuse_points})
        explanations.append(f"AbuseIPDB confidence score is {abuse_value}.")

    malware_family = malwarebazaar.get("malware_family")
    malware_tags = malwarebazaar.get("tags") or []
    if malware_family or malware_tags:
        malwarebazaar_points = 35
        if malware_family and malware_family.lower() != "unknown malware family":
            malwarebazaar_points += 20
        if malware_tags:
            malwarebazaar_points += min(15, len(malware_tags) * 4)
        malwarebazaar_points = min(70, malwarebazaar_points)
        provider_breakdown.append({"provider": "MalwareBazaar", "score": malwarebazaar_points})
        explanations.append(
            "MalwareBazaar identified sample intelligence"
            + (f" for {malware_family}" if malware_family else "")
            + (f" with tags {', '.join(malware_tags[:4])}." if malware_tags else ".")
        )
    else:
        malwarebazaar_points = 0

    threatfox_count = int(threatfox.get("mapping_count", 0) or 0)
    threat_types = threatfox.get("threat_types") or []
    if threatfox_count > 0:
        threatfox_points = min(60, 20 + threatfox_count * 10 + (10 if threat_types else 0))
        provider_breakdown.append({"provider": "ThreatFox", "score": threatfox_points})
        explanations.append(
            f"ThreatFox mapped the hash to {threatfox_count} IOC record(s)"
            + (f" linked to {', '.join(threat_types[:2])}." if threat_types else ".")
        )
    else:
        threatfox_points = 0

    if otx_hits > 0:
        otx_points = min(45, 15 + otx_hits * 8)
        provider_breakdown.append({"provider": "OTX", "score": otx_points})
        explanations.append(f"OTX returned {otx_hits} contextual pulse match(es).")
    else:
        otx_points = 0

    score = min(100, vt_points + abuse_points + malwarebazaar_points + threatfox_points + otx_points)
    confidence = min(100, score if len(provider_breakdown) >= 2 else max(score - 10, 0))

    if score >= 75:
        verdict = "Malicious"
    elif score >= 35:
        verdict = "Suspicious"
    else:
        verdict = "Clean"

    if score >= 90:
        severity = "Critical"
    elif score >= 70:
        severity = "High"
    elif score >= 35:
        severity = "Medium"
    else:
        severity = "Low"

    highlighted = {
        "malware_family": malware_family or threatfox.get("malware_family"),
        "tags": malware_tags[:6],
        "threat_types": threat_types[:3],
    }

    if not explanations:
        explanations.append("No strong provider-backed threat signals were observed for this indicator.")

    return verdict, severity, score, confidence, provider_breakdown, explanations, highlighted


def get_provider_support(ioc_type):
    support_map = {
        "ip": {
            "virustotal": {"supported": True, "label": "VirusTotal malicious"},
            "abuseipdb": {"supported": True, "label": "AbuseIPDB score"},
            "otx": {"supported": True, "label": "OTX hits"},
            "malwarebazaar": {"supported": False, "label": "Malware Sample Intelligence", "reason": "Not supported for this IOC type"},
            "threatfox": {"supported": False, "label": "IOC / Campaign Intelligence", "reason": "Not supported for this IOC type"},
        },
        "domain": {
            "virustotal": {"supported": True, "label": "VirusTotal malicious"},
            "abuseipdb": {"supported": False, "label": "AbuseIPDB score", "reason": "Not supported for this IOC type"},
            "otx": {"supported": True, "label": "OTX hits"},
            "malwarebazaar": {"supported": False, "label": "Malware Sample Intelligence", "reason": "Not supported for this IOC type"},
            "threatfox": {"supported": False, "label": "IOC / Campaign Intelligence", "reason": "Not supported for this IOC type"},
        },
        "url": {
            "virustotal": {"supported": True, "label": "VirusTotal malicious"},
            "abuseipdb": {"supported": False, "label": "AbuseIPDB score", "reason": "Not supported for this IOC type"},
            "otx": {"supported": False, "label": "OTX hits", "reason": "Not supported for this IOC type"},
            "malwarebazaar": {"supported": False, "label": "Malware Sample Intelligence", "reason": "Not supported for this IOC type"},
            "threatfox": {"supported": False, "label": "IOC / Campaign Intelligence", "reason": "Not supported for this IOC type"},
        },
        "md5": {
            "virustotal": {"supported": True, "label": "VirusTotal malicious"},
            "abuseipdb": {"supported": False, "label": "AbuseIPDB score", "reason": "Not supported for this IOC type"},
            "otx": {"supported": True, "label": "Threat Context"},
            "malwarebazaar": {"supported": True, "label": "Malware Sample Intelligence"},
            "threatfox": {"supported": True, "label": "IOC / Campaign Intelligence"},
        },
        "sha1": {
            "virustotal": {"supported": True, "label": "VirusTotal malicious"},
            "abuseipdb": {"supported": False, "label": "AbuseIPDB score", "reason": "Not supported for this IOC type"},
            "otx": {"supported": True, "label": "Threat Context"},
            "malwarebazaar": {"supported": True, "label": "Malware Sample Intelligence"},
            "threatfox": {"supported": False, "label": "IOC / Campaign Intelligence", "reason": "Not supported for this IOC type"},
        },
        "sha256": {
            "virustotal": {"supported": True, "label": "VirusTotal malicious"},
            "abuseipdb": {"supported": False, "label": "AbuseIPDB score", "reason": "Not supported for this IOC type"},
            "otx": {"supported": True, "label": "Threat Context"},
            "malwarebazaar": {"supported": True, "label": "Malware Sample Intelligence"},
            "threatfox": {"supported": True, "label": "IOC / Campaign Intelligence"},
        },
        "email": {
            "virustotal": {"supported": False, "label": "VirusTotal malicious", "reason": "Not supported for this IOC type"},
            "abuseipdb": {"supported": False, "label": "AbuseIPDB score", "reason": "Not supported for this IOC type"},
            "otx": {"supported": False, "label": "OTX hits", "reason": "Not supported for this IOC type"},
            "malwarebazaar": {"supported": False, "label": "Malware Sample Intelligence", "reason": "Not supported for this IOC type"},
            "threatfox": {"supported": False, "label": "IOC / Campaign Intelligence", "reason": "Not supported for this IOC type"},
        },
    }
    return support_map.get(ioc_type, {
        "virustotal": {"supported": False, "label": "VirusTotal malicious", "reason": "Not supported for this IOC type"},
        "abuseipdb": {"supported": False, "label": "AbuseIPDB score", "reason": "Not supported for this IOC type"},
        "otx": {"supported": False, "label": "OTX hits", "reason": "Not supported for this IOC type"},
        "malwarebazaar": {"supported": False, "label": "Malware Sample Intelligence", "reason": "Not supported for this IOC type"},
        "threatfox": {"supported": False, "label": "IOC / Campaign Intelligence", "reason": "Not supported for this IOC type"},
    })


def severity_from_numeric(value):
    if value >= 85:
        return "critical"
    if value >= 60:
        return "high"
    if value >= 30:
        return "medium"
    return "low"


def normalize_feed_item(indicator, indicator_type, description, severity, source, link=None):
    clean_indicator = (indicator or "").strip()
    if not clean_indicator:
        return None

    type_map = {
        "ipv4": "ip",
        "host": "domain",
        "hostname": "domain",
        "domain": "domain",
        "url": "url",
        "email": "email",
        "md5_hash": "md5",
        "sha1_hash": "sha1",
        "sha256_hash": "sha256",
        "file_hash": detect_ioc_type(clean_indicator),
    }
    indicator_type = type_map.get((indicator_type or "").lower(), (indicator_type or "").lower())

    if indicator_type == "ip:port":
        indicator_type = "ip"
        clean_indicator = clean_indicator.split(":", 1)[0]

    if detect_ioc_type(clean_indicator) == "unknown":
        return None

    return {
        "indicator": clean_indicator,
        "type": indicator_type or detect_ioc_type(clean_indicator),
        "description": description or "Live threat intelligence observation.",
        "severity": severity,
        "source": source,
        "link": link or "#",
    }


def fetch_abuseipdb_blacklist():
    if not ABUSEIPDB_API_KEY:
        return [], {"name": "AbuseIPDB", "status": "unavailable", "message": "API key not configured"}

    try:
        response = requests.get(
            "https://api.abuseipdb.com/api/v2/blacklist",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"confidenceMinimum": "90", "limit": "6"},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        items = []

        for entry in payload.get("data", [])[:6]:
            item = normalize_feed_item(
                entry.get("ipAddress"),
                "ip",
                f"Top malicious IP reported by AbuseIPDB. Confidence score {entry.get('abuseConfidenceScore', 0)}.",
                severity_from_numeric(int(entry.get("abuseConfidenceScore", 0))),
                "AbuseIPDB",
            )
            if item:
                items.append(item)

        return items, {"name": "AbuseIPDB", "status": "ok", "count": len(items)}
    except requests.RequestException:
        app.logger.exception("AbuseIPDB blacklist request failed")
        return [], {"name": "AbuseIPDB", "status": "error", "message": "Top malicious IP feed unavailable"}
    except (TypeError, ValueError, KeyError):
        app.logger.exception("AbuseIPDB blacklist parsing failed")
        return [], {"name": "AbuseIPDB", "status": "error", "message": "Top malicious IP feed could not be parsed"}


def fetch_threatfox_iocs():
    if not THREATFOX_AUTH_KEY:
        return [], {"name": "ThreatFox", "status": "unavailable", "message": "Auth key not configured"}

    try:
        response = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            headers={"Auth-Key": THREATFOX_AUTH_KEY},
            json={"query": "get_iocs", "days": 1},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        items = []

        for entry in payload.get("data", [])[:8]:
            item = normalize_feed_item(
                entry.get("ioc"),
                entry.get("ioc_type"),
                entry.get("threat_type_desc") or entry.get("malware_printable") or "ThreatFox recent IOC.",
                severity_from_numeric(int(entry.get("confidence_level", 0))),
                "ThreatFox",
                entry.get("reference"),
            )
            if item:
                items.append(item)

        return items, {"name": "ThreatFox", "status": "ok", "count": len(items)}
    except requests.RequestException:
        app.logger.exception("ThreatFox request failed")
        return [], {"name": "ThreatFox", "status": "error", "message": "Recent ThreatFox IOC feed unavailable"}
    except (TypeError, ValueError, KeyError):
        app.logger.exception("ThreatFox parsing failed")
        return [], {"name": "ThreatFox", "status": "error", "message": "Recent ThreatFox IOC feed could not be parsed"}


def fetch_otx_pulses():
    if not OTX_API_KEY:
        return [], {"name": "OTX", "status": "unavailable", "message": "API key not configured"}

    try:
        response = requests.get(
            "https://otx.alienvault.com/api/v1/pulses/subscribed",
            headers={"X-OTX-API-KEY": OTX_API_KEY},
            params={"limit": "5"},
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        pulses = payload.get("results") or payload.get("pulses") or payload.get("data") or []
        items = []

        for pulse in pulses:
            pulse_name = pulse.get("name") or "OTX pulse"
            pulse_link = pulse.get("permalink") or pulse.get("references", [None])[0]
            indicators = pulse.get("indicators") or []
            for indicator in indicators[:3]:
                indicator_value = indicator.get("indicator") or indicator.get("value")
                indicator_type = (indicator.get("type") or "").lower()
                item = normalize_feed_item(
                    indicator_value,
                    indicator_type,
                    pulse_name,
                    "medium",
                    "OTX",
                    pulse_link,
                )
                if item:
                    items.append(item)
                if len(items) >= 8:
                    break
            if len(items) >= 8:
                break

        return items, {"name": "OTX", "status": "ok", "count": len(items)}
    except requests.RequestException:
        app.logger.exception("OTX pulse request failed")
        return [], {"name": "OTX", "status": "error", "message": "OTX pulse feed unavailable"}
    except (TypeError, ValueError, KeyError, AttributeError):
        app.logger.exception("OTX pulse parsing failed")
        return [], {"name": "OTX", "status": "error", "message": "OTX pulse feed could not be parsed"}


def fetch_urlhaus_recent():
    if not URLHAUS_AUTH_KEY:
        return [], {"name": "URLhaus", "status": "unavailable", "message": "Auth key not configured"}

    try:
        response = requests.get(
            f"https://urlhaus-api.abuse.ch/v2/files/exports/{URLHAUS_AUTH_KEY}/recent-online.json",
            timeout=REQUEST_TIMEOUT,
        )
        response.raise_for_status()
        payload = response.json()
        entries = payload if isinstance(payload, list) else payload.get("urls", [])
        items = []

        for entry in entries[:8]:
            item = normalize_feed_item(
                entry.get("url"),
                "url",
                entry.get("threat") or entry.get("signature") or "Recent malicious URL tracked by URLhaus.",
                "high",
                "URLhaus",
                entry.get("url"),
            )
            if item:
                items.append(item)

        return items, {"name": "URLhaus", "status": "ok", "count": len(items)}
    except requests.RequestException:
        app.logger.exception("URLhaus request failed")
        return [], {"name": "URLhaus", "status": "error", "message": "URLhaus feed unavailable"}
    except (TypeError, ValueError, KeyError, AttributeError):
        app.logger.exception("URLhaus parsing failed")
        return [], {"name": "URLhaus", "status": "error", "message": "URLhaus feed could not be parsed"}


@app.route("/check", methods=["POST"])
@limiter.limit("10 per minute")
def check_ioc():
    data = request.get_json(silent=True) or {}
    ioc = data.get("ioc")
    if not ioc:
        return jsonify({"error": "No IOC provided"}), 400

    ioc = ioc.strip() if isinstance(ioc, str) else ioc
    ioc_type = detect_ioc_type(ioc)

    if ioc_type == "unknown":
        return jsonify({
            "error": "Invalid IOC format. Enter valid IP, Domain, URL, Hash or Email."
        }), 400

    app.logger.info("IOC check requested: type=%s", ioc_type)

    result = {
        "ioc": ioc,
        "type": ioc_type,
        "combined_risk": "Unknown",
        "verdict": "Unknown",
        "severity": "Unknown",
        "score": 0,
        "virustotal": None,
        "abuseipdb": None,
        "otx": None,
        "malwarebazaar": None,
        "threatfox": None,
        "provider_support": get_provider_support(ioc_type),
    }

    lookups = {}
    if result["provider_support"]["virustotal"]["supported"]:
        lookups["virustotal"] = lambda: lookup_virustotal(ioc, ioc_type)
    if result["provider_support"]["abuseipdb"]["supported"]:
        lookups["abuseipdb"] = lambda: lookup_abuseipdb(ioc, ioc_type)
    if result["provider_support"]["otx"]["supported"]:
        lookups["otx"] = lambda: lookup_otx(ioc, ioc_type)
    if result["provider_support"]["malwarebazaar"]["supported"]:
        lookups["malwarebazaar"] = lambda: lookup_malwarebazaar(ioc, ioc_type)
    if result["provider_support"]["threatfox"]["supported"]:
        lookups["threatfox"] = lambda: lookup_threatfox_hash(ioc, ioc_type)

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {name: executor.submit(func) for name, func in lookups.items()}
        for name, future in futures.items():
            try:
                result[name] = future.result()
            except Exception:
                app.logger.exception("%s lookup failed unexpectedly", name)
                result[name] = {"error": f"{name} lookup failed"}

    verdict, severity, score, confidence, provider_breakdown, explanations, highlighted = score_result(result)
    result["verdict"] = verdict
    result["severity"] = severity
    result["score"] = score
    result["confidence"] = confidence
    result["provider_breakdown"] = provider_breakdown
    result["explanations"] = explanations
    result["highlighted_intelligence"] = highlighted
    result["combined_risk"] = severity

    return jsonify(result)


@app.route("/news")
def get_news():
    if "articles" in news_cache:
        return jsonify(news_cache["articles"])

    feeds = [
        "https://thehackernews.com/feeds/posts/default",
        "https://cybernews.com/feed/",
        "https://thecyberexpress.com/feed/",
    ]
    articles = []
    failed_sources = 0

    for feed_url in feeds:
        try:
            response = requests.get(feed_url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            feed = feedparser.parse(response.content)
            for entry in feed.entries[:5]:
                articles.append({
                    "title": entry.get("title", "Untitled"),
                    "link": entry.get("link", "#"),
                    "source": urlparse(feed_url).netloc,
                    "published": entry.get("published", entry.get("updated", "Latest")),
                })
        except requests.RequestException:
            failed_sources += 1
            app.logger.exception("News feed request failed: source=%s", urlparse(feed_url).netloc)
        except Exception:
            failed_sources += 1
            app.logger.exception("News feed parsing failed: source=%s", urlparse(feed_url).netloc)
    if not articles:
        articles.append({
            "title": "Feed temporarily unavailable",
            "link": "#",
            "source": "",
            "published": "Latest",
        })
    elif failed_sources:
        articles.append({
            "title": "Feed temporarily unavailable",
            "link": "#",
            "source": "",
            "published": "Latest",
        })

    news_cache["articles"] = articles
    return jsonify(articles)


@app.route("/ioc-feed")
def get_ioc_feed():
    if "payload" in ioc_feed_cache:
        return jsonify(ioc_feed_cache["payload"])

    aggregated = []
    source_status = []

    fetchers = [
        fetch_abuseipdb_blacklist,
        fetch_otx_pulses,
        fetch_threatfox_iocs,
        fetch_urlhaus_recent,
    ]

    seen = set()
    for fetcher in fetchers:
        items, status = fetcher()
        source_status.append(status)
        for item in items:
            key = (item["type"], item["indicator"].lower())
            if key in seen:
                continue
            seen.add(key)
            aggregated.append(item)

    payload = {
        "items": aggregated[:18],
        "sources": source_status,
    }
    ioc_feed_cache["payload"] = payload
    return jsonify(payload)


@app.route("/")
def home():
    return jsonify({"status": "Threat Intel Aggregator API is live"})


if __name__ == "__main__":
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
