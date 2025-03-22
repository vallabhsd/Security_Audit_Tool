#!/bin/bash

# Security Scan Tool - External Testing (Public Data-Based)
# Author: Your Name
# Usage: ./security_scan.sh <target_url>

NIST_API_KEY="your_nist_api_key"

# Validate Input
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <target_url>"
    exit 1
fi

TARGET=$1
DOMAIN=$(echo "$TARGET" | awk -F[/:] '{print $4}')  # Extract domain

echo "Starting security scan for: $TARGET"
echo "-----------------------------------"

# 1. Check HTTP Security Headers
echo "[+] Checking HTTP Security Headers..."
curl -s -I "$TARGET" > headers.txt
grep -E "Strict-Transport-Security|Content-Security-Policy|X-Frame-Options|X-Content-Type-Options|Referrer-Policy|Permissions-Policy" headers.txt || echo "[-] Missing security headers!"

# 2. Check SSL/TLS Security
echo "[+] Checking SSL/TLS Configuration..."
openssl s_client -connect "$DOMAIN":443 -servername "$DOMAIN" -quiet < /dev/null 2>/dev/null | openssl x509 -noout -dates -issuer -subject

# 3. Open Port Scan (if nmap is installed)
if command -v nmap &>/dev/null; then
    echo "[+] Scanning Open Ports..."
    nmap -F "$DOMAIN" | grep "open"
else
    echo "[-] Skipping port scan (nmap not installed)"
fi

# 4. Retrieve DNS Records
echo "[+] Retrieving DNS Records..."
dig ANY "$DOMAIN" +short

# 5. WHOIS Lookup
echo "[+] Performing WHOIS Lookup..."
whois "$DOMAIN" | grep -E "Registrar|Creation Date|Updated Date|Expiration Date" || echo "[-] WHOIS data not available"

# 6. Vulnerability Mapping (NIST NVD API)
echo "[+] Checking for Known Vulnerabilities..."
CPE_QUERY=$(curl -s "https://services.nvd.nist.gov/rest/json/cpes/1.0?keyword=$DOMAIN&apiKey=$NIST_API_KEY" | jq -r '.result.cpes[].cpe23Uri' 2>/dev/null)

if [ -z "$CPE_QUERY" ]; then
    echo "[-] No software vulnerabilities found."
else
    echo "Possible software vulnerabilities found:"
    echo "$CPE_QUERY"
    CVE_QUERY=$(curl -s "https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=$CPE_QUERY&apiKey=$NIST_API_KEY" | jq -r '.result.CVE_Items[].cve.CVE_data_meta.ID' 2>/dev/null)
    echo "$CVE_QUERY"
fi

echo "-----------------------------------"
echo "Scan completed for: $TARGET"
