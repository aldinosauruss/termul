import asyncio
import aiohttp
import time
from collections import defaultdict

# ================= CONFIG =================
MAX_CONCURRENCY = 10
TIMEOUT = 5
CRITICAL_STOP_THRESHOLD = 2     # smart stop
WAF_DELAY = 1.5                # waf aware delay
WAF_STATUS = [429, 403]        # common WAF signals

# ================= GLOBAL STATE =================
findings = []
critical_count = 0
stop_scan = False
logic_graph = defaultdict(list)

# ================= UTIL =================

def add_finding(f):
    global critical_count, stop_scan
    findings.append(f)

    if f["risk"] == "CRITICAL":
        critical_count += 1

    # smart stop
    if critical_count >= CRITICAL_STOP_THRESHOLD:
        stop_scan = True


def correlate(source, target):
    logic_graph[source].append(target)


# ================= ASYNC CHECKERS =================

async def fetch(session, method, url, headers=None, json=None):
    try:
        async with session.request(
            method,
            url,
            headers=headers,
            json=json,
            timeout=TIMEOUT
        ) as r:
            status = r.status
            text = await r.text()
            return status, text
    except:
        return None, None


async def check_exposed_route(session, url):
    global stop_scan
    if stop_scan:
        return

    status, _ = await fetch(session, "GET", url)

    if status == 200:
        add_finding({
            "type": "EXPOSED_ROUTE",
            "endpoint": url,
            "risk": "HIGH"
        })


async def check_missing_auth(session, url):
    global stop_scan
    if stop_scan:
        return

    status, _ = await fetch(session, "GET", url)

    if status == 200:
        add_finding({
            "type": "MISSING_AUTH",
            "endpoint": url,
            "risk": "CRITICAL"
        })


async def check_idor(session, base, token):
    global stop_scan
    headers = {"Authorization": f"Bearer {token}"}

    for i in range(1, 6):
        if stop_scan:
            return

        url = f"{base}?id={i}"
        status, body = await fetch(session, "GET", url, headers)

        if status == 200:
            add_finding({
                "type": "IDOR",
                "endpoint": url,
                "risk": "CRITICAL"
            })
            correlate("IDOR", "DATA_DISCLOSURE")


async def check_privilege(session, url, token):
    global stop_scan
    if stop_scan:
        return

    headers = {"Authorization": f"Bearer {token}"}
    status, _ = await fetch(session, "POST", url, headers)

    if status == 200:
        add_finding({
            "type": "PRIVILEGE_ESCALATION",
            "endpoint": url,
            "risk": "CRITICAL"
        })
        correlate("PRIVILEGE_ESCALATION", "ADMIN_ACTION")


async def check_workflow(session, url, token):
    global stop_scan
    if stop_scan:
        return

    headers = {"Authorization": f"Bearer {token}"}
    payload = {"status": "completed"}

    status, _ = await fetch(session, "POST", url, headers, payload)

    if status == 200:
        add_finding({
            "type": "WORKFLOW_BYPASS",
            "endpoint": url,
            "risk": "HIGH"
        })
        correlate("WORKFLOW_BYPASS", "FINANCIAL_IMPACT")


# ================= WAF AWARE WRAPPER =================

async def waf_guarded(task):
    await asyncio.sleep(WAF_DELAY)
    await task


# ================= FULL ASYNC ENGINE =================

async def termul_full_async(base_url, token):
    connector = aiohttp.TCPConnector(limit=MAX_CONCURRENCY)
    async with aiohttp.ClientSession(connector=connector) as session:

        tasks = []

        exposed = [
            "admin", "api/admin", "debug", "internal"
        ]

        for r in exposed:
            tasks.append(
                waf_guarded(
                    check_exposed_route(
                        session,
                        f"{base_url}/{r}"
                    )
                )
            )

        missing_auth = [
            "/api/admin",
            "/api/internal/report"
        ]

        for ep in missing_auth:
            tasks.append(
                waf_guarded(
                    check_missing_auth(
                        session,
                        base_url + ep
                    )
                )
            )

        tasks.append(
            waf_guarded(
                check_idor(
                    session,
                    base_url + "/api/user/profile",
                    token
                )
            )
        )

        admin_eps = [
            "/api/admin/approve",
            "/api/admin/delete"
        ]

        for ep in admin_eps:
            tasks.append(
                waf_guarded(
                    check_privilege(
                        session,
                        base_url + ep,
                        token
                    )
                )
            )

        tasks.append(
            waf_guarded(
                check_workflow(
                    session,
                    base_url + "/api/order/complete",
                    token
                )
            )
        )

        await asyncio.gather(*tasks)


# ================= REPORT =================

def report():
    print("\n========== TERMUL FINDINGS ==========")
    for f in findings:
        print(f"[{f['risk']}] {f['type']} -> {f['endpoint']}")

    print("\n========== RISK SUMMARY ==========")
    summary = defaultdict(int)
    for f in findings:
        summary[f["risk"]] += 1
    for k,v in summary.items():
        print(f"{k}: {v}")

    print("\n========== LOGIC CORRELATION ==========")
    for k,v in logic_graph.items():
        print(f"{k} => {', '.join(v)}")


# ================= MAIN =================

if __name__ == "__main__":
    TARGET = "https://target.com"
    USER_TOKEN = "USER_JWT_TOKEN"

    print("[*] TERMUL ASYNC FULL SCAN STARTED")
    asyncio.run(termul_full_async(TARGET, USER_TOKEN))
    report()
    print("\n[*] TERMUL SCAN FINISHED")

