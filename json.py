import json
import re
import os

def get_latest_report_file():
    """
    Scans the current directory for scan_results_*.txt,
    opens the last one created, and extracts the filename
    from the last line if available.
    """
    candidates = [f for f in os.listdir() if f.startswith("scan_results_") and f.endswith(".txt")]
    if not candidates:
        print("❌ No scan report files found.")
        return None

    # Sort by modification time, descending
    latest_file = sorted(candidates, key=os.path.getmtime, reverse=True)[0]

    # Optional: confirm by reading last line
    with open(latest_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for line in reversed(lines):
            if "Report saved to" in line:
                match = re.search(r"scan_results_.*?\.txt", line)
                if match:
                    return match.group(0)
    return latest_file  # fallback

def extract_keywords(report_path):
    keywords = set()
    with open(report_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    for i, line in enumerate(lines):

        # WHOIS
        if "Registrant Country" in line and ("Unknown" in line or "None" in line):
            keywords.add("missing whois registrant info")

        # DNS
        if "MX Records" in line and "0 ." in lines[i + 1]:
            keywords.add("missing MX record")
        if "TXT Records" in line and not any("spf" in l.lower() for l in lines[i+1:i+5]):
            keywords.add("missing SPF record")

        # Subdomains
        if "Found subdomain" in line:
            keywords.add("enumerated subdomains")

        # SSL/TLS
        if "TLSv1.0" in line or "TLSv1.1" in line:
            keywords.add("weak TLS version in use")
        if "self-signed" in line.lower() or "invalid" in line.lower():
            keywords.add("self-signed or expired certificate")

        # Headers
        header_map = {
            "Strict-Transport-Security": "HSTS missing vulnerability",
            "X-Frame-Options": "clickjacking vulnerability",
            "X-XSS-Protection": "XSS protection header missing",
            "X-Content-Type-Options": "MIME sniffing vulnerability",
            "Content-Security-Policy": "content injection vulnerability",
            "Referrer-Policy": "referrer policy vulnerability",
            "Permissions-Policy": "browser feature abuse"
        }
        for header, keyword in header_map.items():
            if header in line and ("missing" in line.lower() or "not enabled" in line.lower()):
                keywords.add(keyword)

        # Ports
        if "filtered tcp ports" in line or "open" in line:
            keywords.add("exposed network ports")

        # Technologies
        tech_map = {
            "WordPress": "WordPress vulnerabilities",
            "Drupal": "Drupal vulnerabilities",
            "Joomla": "Joomla vulnerabilities",
            "Apache": "Apache vulnerabilities",
            "Nginx": "Nginx vulnerabilities",
            "PHP": "PHP vulnerabilities",
            "jQuery": "jQuery vulnerabilities",
            "Bootstrap": "Bootstrap vulnerabilities",
            "Node.js": "Node.js vulnerabilities",
            "Express": "Express JS security risks"
        }
        for tech, keyword in tech_map.items():
            if tech.lower() in line.lower():
                keywords.add(keyword)

        # Nikto
        if "nikto" in line.lower() and "host(s) tested" not in line:
            keywords.add("nikto web vulnerability findings")
        if "TRACE" in line or "X-XSS" in line or "cookie" in line.lower():
            keywords.add("weak HTTP application security")

        # Misconfigs
        if "/admin" in line or "directory listing is enabled" in line.lower():
            keywords.add("directory indexing enabled")
        if "robots.txt" in line.lower():
            keywords.add("robots.txt exposed sensitive paths")

        # Email
        if "SPF Record" in line and ("missing" in line.lower() or "-all" not in line):
            keywords.add("insecure SPF policy")
        if "DMARC Record" in line and "reject" not in line:
            keywords.add("missing strict DMARC policy")
        if "DKIM Record" in line and "Found" not in line:
            keywords.add("DKIM not configured")

        # Blacklist
        if "blacklist" in line.lower() and ("listed" in line.lower() or "check failed" in line.lower()):
            keywords.add("blacklisted domain or IP")

        # CVE section
        if "CVE-" in line:
            keywords.add("known CVEs matched")

    return sorted(list(keywords))

def save_keywords_json(report_file):
    domain_match = re.search(r"scan_results_(.*?)_", report_file)
    domain = domain_match.group(1) if domain_match else "domain"

    keywords = extract_keywords(report_file)
    output = {
        "domain": domain,
        "keywords_for_cve_mapping": keywords
    }

    json_file = f"{domain}_keywords_auto.json"
    with open(json_file, "w", encoding='utf-8') as f:
        json.dump(output, f, indent=4)
    print(f"✅ Extracted keywords saved to: {json_file}")

# === Run Automatically ===
if __name__ == "__main__":
    latest_report = get_latest_report_file()
    if latest_report:
        save_keywords_json(latest_report)
