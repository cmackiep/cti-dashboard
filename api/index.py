import os
import base64
import ipaddress
import time
import requests
from flask import Flask, request, jsonify

# ================= INITIALIZE THE APP =================
app = Flask(__name__)

# ================= SECURE CREDENTIALS CONFIGURATION =================
# Real keys live in Vercel's environment variables. No fallback: if one is missing, fail clearly.
ABUSE_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")

def lookup_vt_url(url, headers):
    # VirusTotal names each URL by its text in "URL-safe base64", with the = padding removed
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    return requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers, timeout=5)

def is_ip(value):
    # True if value is a valid IPv4 or IPv6 address, else False (e.g. a domain)
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

# ================= RATE LIMITING =================
# Each visitor (by IP) gets RATE_LIMIT searches per RATE_WINDOW seconds.
# Counts are kept in this server copy's memory, so on serverless this is best effort.
RATE_LIMIT = 3
RATE_WINDOW = 60
requests_by_ip = {}

def is_rate_limited(ip):
    now = time.time()
    entry = requests_by_ip.get(ip)

    # First search, or their last window has ended: start a fresh count
    if entry is None or now - entry['start'] >= RATE_WINDOW:
        requests_by_ip[ip] = {"count": 1, "start": now}
        return False

    # Already used up their searches for this window
    if entry["count"] >= RATE_LIMIT:
        return True

    # Otherwise, count this search and let it through
    entry["count"] += 1
    return False

@app.route('/api/analyze', methods=['GET'])
def analyze_threat():
    if not VT_API_KEY or not ABUSE_API_KEY:
        print("Config error: VT_API_KEY or ABUSEIPDB_API_KEY is not set")
        return jsonify({"error": "Oops! Something went wrong during the lookup. Try again in a moment."}), 500

    visitor_ip = request.headers.get('x-forwarded-for', request.remote_addr)
    if is_rate_limited(visitor_ip):
        print(f"Rate limited: {visitor_ip}")
        return jsonify({"error": "Slow down cowboy, too many searches! Wait a minute and try again."}), 429
                            
    # Read the search from the URL, e.g. /api/analyze?query=google.com
    target = request.args.get('query', '').strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400

    try:
        # Keep the full original text, and note if it's a full URL (starts with http:// or https://)
        original = target
        is_url = target.lower().startswith(('http://', 'https://'))

        # 1. Clean off prefixes if a user types http:// or https://
        target = target.replace('https://', '').replace('http://', '')
        
        # 2. Keep only the domain or IP, dropping any page path (site.com/login becomes site.com)
        if '/' in target:
            target = target.split('/')[0]

        target = target.replace('www.', '').strip()

        # Detect if the target input is a domain name
        is_domain = not is_ip(target)
        
        report = {
            "search_query": original if is_url else target,
            "search_type": "URL" if is_url else ("Domain Name" if is_domain else "IP Address"),
            "domain": target,
            "resolved_ip": "N/A",
            "virustotal": None,
            "abuseipdb": None,
            "shodan": None
        }

        # ================= 1. VIRUSTOTAL LOOKUP =================
        if is_domain:
            vt_url = f'https://www.virustotal.com/api/v3/domains/{target}'
        else:
            vt_url = f'https://www.virustotal.com/api/v3/ip_addresses/{target}'

        vt_headers = {'accept': 'application/json', 'x-apikey': VT_API_KEY}
        vt_resp = requests.get(vt_url, headers=vt_headers, timeout=5)
        if vt_resp.status_code ==429:
            print("VirusTotal rate limit hit")
            return jsonify({"error": "VirusTotal rate limit hit. Please wait a moment and try again!"}), 503
        ip_to_check = target

        if vt_resp.status_code == 200:
            try:
                vt_json = vt_resp.json()
                vt_data = vt_json.get('data', {})
                vt_attr = vt_data.get('attributes', {})
                stats = vt_attr.get('last_analysis_stats', {'malicious': 0, 'harmless': 0})
                
                report["virustotal"] = {
                    "malicious_flags": stats.get('malicious', 0),
                    "harmless_flags": stats.get('harmless', 0),
                    "network_provider": vt_attr.get('registrar', vt_attr.get('as_owner', 'Unknown Entity'))
                }
                
                if is_domain:
                    last_dns = vt_attr.get('last_dns_records', [])
                    for record in last_dns:
                        if record.get('type') == 'A':
                            ip_to_check = record.get('value')
                            report["resolved_ip"] = ip_to_check
                            break
            except Exception:
                report["virustotal"] = {"error": "Failed to parse VirusTotal data structures"}
        else:
            report["virustotal"] = {"error": f"VirusTotal error code {vt_resp.status_code}."}

        # ================= 1b. VIRUSTOTAL URL LOOKUP (full URLs only) =================
        # A URL scan checks one exact page. Phishing often hides on one page of a clean-looking domain.
        if is_url:
            url_resp = lookup_vt_url(original, vt_headers)

            # VirusTotal can be fussy about a trailing slash, so try once more with one added
            if url_resp.status_code == 404 and not original.endswith('/'):
                url_resp = lookup_vt_url(original + '/', vt_headers)

            if url_resp.status_code == 200:
                url_stats = url_resp.json().get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                provider = (report["virustotal"] or {}).get('network_provider', 'Unknown Entity')
                # Replace the domain's verdict counts with this URL's own counts
                report["virustotal"] = {
                    "malicious_flags": url_stats.get('malicious', 0),
                    "harmless_flags": url_stats.get('harmless', 0),
                    "network_provider": provider,
                    "verdict_source": "url"
                }
            elif url_resp.status_code == 404:
                report["url_note"] = "VirusTotal has never scanned this exact URL, so these results are for the domain."
            else:
                report["url_note"] = f"VirusTotal URL lookup failed with error code {url_resp.status_code}, so these results are for the domain."

        # ================= 2. ABUSEIPDB LOOKUP =================
        if ip_to_check and is_ip(ip_to_check):
            abuse_url = 'https://api.abuseipdb.com/api/v2/check'
            abuse_headers = {'Accept': 'application/json', 'Key': ABUSE_API_KEY}
            abuse_params = {'ipAddress': ip_to_check, 'maxAgeInDays': '90'}
            abuse_resp = requests.get(abuse_url, headers=abuse_headers, params=abuse_params, timeout=5)
            
            if abuse_resp.status_code == 200:
                try:
                    a_data = abuse_resp.json().get('data', {})
                    report["abuseipdb"] = {
                        "confidence_score": a_data.get('abuseConfidenceScore', 0),
                        "total_reports": a_data.get('totalReports', 0),
                        "hosting_country": a_data.get('countryCode', 'Unknown')
                    }
                except Exception:
                    report["abuseipdb"] = {"error": "Failed to parse AbuseIPDB data structures"}
            else:
                report["abuseipdb"] = {"error": f"AbuseIPDB error code {abuse_resp.status_code}."}
        else:
            report["abuseipdb"] = {"notice": "Skipped infrastructure lookup (No valid IP resolved)"}

        # ================= 3. SHODAN INTERNETDB LOOKUP =================
        # Free, no key. Shows which ports are open on the IP and any known vulnerabilities (CVEs).
        # Extra context only, so if Shodan fails we show a note instead of failing the whole search.
        if ip_to_check and is_ip(ip_to_check):
            try:
                shodan_resp = requests.get(f'https://internetdb.shodan.io/{ip_to_check}', timeout=5)
                if shodan_resp.status_code == 200:
                    s_data = shodan_resp.json()
                    report["shodan"] = {
                        "open_ports": s_data.get('ports', []),
                        "vulns": s_data.get('vulns', []),
                        "tags": s_data.get('tags', []),
                        "hostnames": s_data.get('hostnames', [])
                    }
                elif shodan_resp.status_code == 404:
                    report["shodan"] = {"notice": "Shodan has no scan data for this IP."}
                else:
                    report["shodan"] = {"error": f"Shodan error code {shodan_resp.status_code}."}
            except requests.RequestException as e:
                print(f"Shodan lookup failed for {ip_to_check!r}: {e}")
                report["shodan"] = {"error": "Shodan is unavailable right now."}
        else: 
            report["shodan"] = {"notice": "Skipped Shodan lookup (no valid IP resolved)"}

        return jsonify(report)

    except Exception as e:
        print(f"Lookup failed for {target!r}: {e}")
        response = jsonify({"error": "Oops! Something went wrong during the lookup. Try again in a moment."})
        return response, 500

if __name__ == '__main__':
    # Only runs when you start this file yourself, for local testing on port 8080
    app.run(host='localhost', port=8080, debug=True)