from flask import Flask, request, jsonify
import requests, os, re, ipaddress, base64
from dotenv import load_dotenv
from flask_cors import CORS
import feedparser

# ------------------ Load API Keys ------------------
load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

if not VT_API_KEY:
    raise SystemExit("❌ VT_API_KEY missing in .env")

HEADERS = {"x-apikey": VT_API_KEY}

# ------------------ Flask Setup ------------------
app = Flask(__name__)
CORS(app)

# ------------------ Detect IOC Type ------------------
def detect_ioc_type(ioc: str):
    s = ioc.strip()
    try:
        ipaddress.ip_address(s)
        return "ip"
    except Exception:
        pass
    if re.fullmatch(r"[A-Fa-f0-9]+", s):
        l = len(s)
        if l == 32: return "md5"
        if l == 40: return "sha1"
        if l == 64: return "sha256"
    if s.startswith("http://") or s.startswith("https://"):
        return "url"
    if " " not in s and "." in s:
        return "domain"
    return "unknown"

# ------------------ IOC Check ------------------
@app.route("/check", methods=["POST"])
def check_ioc():
    print("🔍 /check called with body:", request.json)  # DEBUG

    data = request.json or {}
    ioc = data.get("ioc")
    if not ioc:
        return jsonify({"error": "No IOC provided"}), 400

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

    # -------- VirusTotal Lookup --------
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

        print("📡 VT Request URL:", url)  # DEBUG
        resp = requests.get(url, headers=HEADERS, timeout=30)
        print("📡 VT Response Code:", resp.status_code)  # DEBUG

        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"].get("last_analysis_stats", {})
            vendors = data["data"]["attributes"].get("last_analysis_results", {})

            result["virustotal"] = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "country": data["data"]["attributes"].get("country"),
                "asn": data["data"]["attributes"].get("asn"),
                "vendors": {k: v.get("category") for k, v in vendors.items()}
            }
        else:
            result["virustotal"] = {"error": f"VT API failed ({resp.status_code})"}
    except Exception as e:
        result["virustotal"] = {"error": str(e)}

    # -------- AbuseIPDB Lookup --------
    if ioc_type == "ip" and ABUSEIPDB_API_KEY:
        try:
            abuse_url = "https://api.abuseipdb.com/api/v2/check"
            params = {"ipAddress": ioc, "maxAgeInDays": "90"}
            r = requests.get(abuse_url, headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}, params=params)
            print("📡 AbuseIPDB Response Code:", r.status_code)  # DEBUG
            if r.status_code == 200:
                data = r.json()["data"]
                result["abuseipdb"] = {
                    "reports": data.get("totalReports"),
                    "abuseConfidence": data.get("abuseConfidenceScore"),
                    "isp": data.get("isp"),
                    "country": data.get("countryCode"),
                }
            else:
                result["abuseipdb"] = {"message": "No data found"}
        except Exception as e:
            result["abuseipdb"] = {"error": str(e)}
    else:
        result["abuseipdb"] = {"message": "No data (not an IP or no API key)"}

    # -------- OTX Lookup --------
    if ioc_type in ["ip", "domain"]:
        try:
            otx_url = f"https://otx.alienvault.com/api/v1/indicators/{ioc_type}/{ioc}/general"
            r = requests.get(otx_url, headers={"X-OTX-API-KEY": OTX_API_KEY}, timeout=30)
            print("📡 OTX Response Code:", r.status_code)  # DEBUG
            if r.status_code == 200:
                data = r.json()
                result["otx"] = {
                    "pulse_count": len(data.get("pulse_info", {}).get("pulses", [])),
                    "malware_families": [p.get("name") for p in data.get("pulse_info", {}).get("pulses", [])[:5]],
                }
            else:
                result["otx"] = {"message": "No data found"}
        except Exception as e:
            result["otx"] = {"error": str(e)}
    else:
        result["otx"] = {"message": "No data (not IP/domain)"}

    # -------- Risk Decision --------
    malicious = result["virustotal"]["malicious"] if result["virustotal"] and "malicious" in result["virustotal"] else 0
    abuse_score = result["abuseipdb"]["abuseConfidence"] if result["abuseipdb"] and "abuseConfidence" in result["abuseipdb"] else 0
    otx_hits = result["otx"]["pulse_count"] if result["otx"] and "pulse_count" in result["otx"] else 0

    if malicious > 3 or (abuse_score and abuse_score > 50) or (otx_hits and otx_hits > 5):
        result["combined_risk"] = "High"
    elif malicious > 0 or (abuse_score and abuse_score > 10) or (otx_hits and otx_hits > 0):
        result["combined_risk"] = "Medium"
    else:
        result["combined_risk"] = "Low"

    return jsonify(result)

# ------------------ Cybersecurity News ------------------
@app.route("/news")
def get_news():
    feeds = [
        "https://thehackernews.com/feeds/posts/default",
        "https://cybernews.com/feed/",
        "https://thecyberexpress.com/feed/"
    ]
    articles = []
    for url in feeds:
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries[:5]:
                articles.append({
                    "title": entry.title,
                    "link": entry.link,
                    "source": url.split("/")[2]
                })
        except Exception as e:
            articles.append({"title": f"Failed to fetch {url}", "link": "#", "source": "error"})
    return jsonify(articles)
@app.route("/")
def home():
    return {"status": "Threat Intel Aggregator API is live"}

# ------------------ Run Server ------------------
if __name__ == "__main__":
    print("✅ Backend running at http://127.0.0.1:5000")
    app.run(debug=True, port=5000)

