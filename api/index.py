import os
import base64
import requests
from flask import Flask, request, jsonify
from flask_cors import CORS

# ================= INITIALIZE THE APP =================
app = Flask(__name__)
# Global open CORS mapping to guarantee your React app connects instantly
CORS(app)

# ================= SECURE CREDENTIALS CONFIGURATION =================
# No more hardcoded strings! Vercel pulls these safely from its secure cloud vaults.
# For local fallback testing, you can place your key strings here if needed.
ABUSE_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "YOUR_LOCAL_FALLBACK_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY", "YOUR_LOCAL_FALLBACK_KEY")

def lookup_vt_url(url, headers):
    # VirusTotal names each URL by its text in "URL-safe base64", with the = padding removed
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
    return requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers, timeout=5)

@app.route('/api/analyze', methods=['GET', 'OPTIONS'])
def analyze_threat():
    if request.method == 'OPTIONS':
        return jsonify({"status": "CORS preflight ok"}), 200

    # Aligned with Claude's new dashboard config which looks up via the 'query' variable parameter
    target = request.args.get('query', '').strip()
    if not target:
        return jsonify({"error": "No target provided"}), 400

    try:
        raise Exception("test crash")
        # Keep the full original text, and note if it's a full URL (starts with http:// or https://)
        original = target
        is_url = target.lower().startswith(('http://', 'https://'))

        # 1. Clean off prefixes if a user types http:// or https://
        target = target.replace('https://', '').replace('http://', '')
        
        # 2. Extract the clean base target as pure text string characters (No split array lists)
        if '/' in target:
            target = target.split('/')[0]

        target = target.replace('www.', '').strip()

        # Detect if the target input is a domain name
        is_domain = any(c.isalpha() for c in target)
        
        report = {
            "search_query": original if is_url else target,
            "search_type": "URL" if is_url else ("Domain Name" if is_domain else "IP Address"),
            "domain": target,
            "resolved_ip": "N/A",
            "virustotal": None,
            "abuseipdb": None
        }

        # ================= 1. VIRUSTOTAL LOOKUP =================
        if is_domain:
            vt_url = f'https://www.virustotal.com/api/v3/domains/{target}'
        else:
            vt_url = f'https://www.virustotal.com/api/v3/ip_addresses/{target}'

        vt_headers = {'accept': 'application/json', 'x-apikey': VT_API_KEY}
        vt_resp = requests.get(vt_url, headers=vt_headers, timeout=5)
        
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
        if ip_to_check and not any(c.isalpha() for c in str(ip_to_check)):
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

        return jsonify(report)

    except Exception as e:
        print(f"Lookup failed for {target!r}: {e}")
        response = jsonify({"error": "Oops! Something went wrong during the lookup. Try again in a moment."})
        return response, 500

if __name__ == '__main__':
    # Local microservice engine fallback loop running on clear port 8080
    app.run(host='localhost', port=8080, debug=True)