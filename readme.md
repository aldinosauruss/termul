
**Testing for Exposed Routes & Missing User Logic (TERMUL)**

TERMUL adalah CLI security testing tool yang fokus pada:
- exposed endpoint
- missing authentication
- authorization & logic flaws
- workflow bypass

Bukan vulnerability scanner CVE.
Ini adalah **logic breaker**.

---

## Fitur Utama
- Async scanning (aiohttp)
- Smart stop saat CRITICAL ditemukan
- WAF-aware (delay & throttling)
- Logic correlation (attack chain)
- Fokus OWASP API Top 10 

---

## Instalasi
```bash
pip install aiohttp

TARGET = "https://target.com"
USER_TOKEN = "JWT_TOKEN"

python termul_async.py
