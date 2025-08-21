# modules/web_vuln_scanner.py
"""
Simple Web Application Vulnerability Scanner (educational).

Features:
 - Crawl a start URL (only same-origin links, depth-limited)
 - Find links and forms
 - Test GET parameters for:
     * Simple SQLi indicators (error strings or content delta)
     * Reflected XSS (reflective payload detection)
 - Check common security headers (CSP, X-XSS-Protection, X-Frame-Options, HSTS)
 - Export results to reports/vuln_report.json and vuln_report.md

USAGE (lab only):
    python3 modules/web_vuln_scanner.py https://127.0.0.1:3000 --max-pages 20

IMPORTANT:
 - Run only on targets you own or have permission to test.
 - This is a lightweight *scanner* with heuristics — NOT a replacement for professional scanners.
"""
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import time
import json
import os
import sys

# Basic payloads and SQL error signatures
XSS_PAYLOAD = "<script>alert(1)</script>"
SQLI_TESTS = ["' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1 -- ", "\" OR 1=1 -- "]
SQLI_ERROR_SIGNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sqlite3.OperationalError",
    "pg_query():",
]

HEADERS_TO_CHECK = [
    "Content-Security-Policy",
    "X-XSS-Protection",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "Referrer-Policy",
]

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

session = requests.Session()
session.headers.update({"User-Agent": "Pentoolkit-WebVulnScanner/1.0 (+lab-only)"})
# polite delay between requests (configurable)
REQUEST_DELAY = 0.8

def fetch(url):
    try:
        r = session.get(url, timeout=8, verify=False, allow_redirects=True)
        return r
    except Exception as e:
        return None

def same_origin(base, other):
    b = urlparse(base)
    o = urlparse(other)
    return (b.scheme, b.hostname, b.port) == (o.scheme, o.hostname, o.port)

def extract_links_and_forms(base_url, html_text):
    soup = BeautifulSoup(html_text, "html.parser")
    links = set()
    forms = []

    # links
    for a in soup.find_all("a", href=True):
        href = urljoin(base_url, a["href"])
        if href.startswith("javascript:"):
            continue
        links.add(href.split("#")[0])

    # forms
    for form in soup.find_all("form"):
        action = form.get("action") or base_url
        method = (form.get("method") or "get").lower()
        inputs = []
        for inp in form.find_all(["input", "textarea", "select"]):
            name = inp.get("name")
            if not name:
                continue
            typ = inp.get("type") or inp.name
            value = inp.get("value") or ""
            inputs.append({"name": name, "type": typ, "value": value})
        forms.append({"action": urljoin(base_url, action), "method": method, "inputs": inputs})
    return links, forms

def check_security_headers(response):
    missing = []
    present = {}
    if response is None:
        return {"error": "no response"}
    for h in HEADERS_TO_CHECK:
        v = response.headers.get(h)
        if v:
            present[h] = v
        else:
            missing.append(h)
    return {"present": present, "missing": missing}

def test_reflected_xss(url, param, base_response_text):
    # Inject payload into a single parameter in a GET request
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return {"tested": False}
    original = qs.get(param, [""])[0]
    qs[param] = XSS_PAYLOAD
    new_q = urlencode({k: v[0] for k, v in qs.items()})
    test_url = parsed._replace(query=new_q).geturl()
    r = fetch(test_url)
    time.sleep(REQUEST_DELAY)
    if not r:
        return {"tested": True, "vulnerable": False, "reason": "no response"}
    if XSS_PAYLOAD in r.text:
        return {"tested": True, "vulnerable": True, "evidence": "payload reflected in response"}
    # small heuristic: content length increase and suspicious html
    if len(r.text) > len(base_response_text) + 10 and ("<script" in r.text.lower() or "alert(" in r.text.lower()):
        return {"tested": True, "vulnerable": True, "evidence": "script/alert present or large reflection"}
    return {"tested": True, "vulnerable": False}

def test_sqli(url, param, base_response_text):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return {"tested": False}
    findings = []
    original = qs.get(param, [""])[0]
    for payload in SQLI_TESTS:
        qs[param] = payload
        new_q = urlencode({k: v[0] for k, v in qs.items()})
        test_url = parsed._replace(query=new_q).geturl()
        r = fetch(test_url)
        time.sleep(REQUEST_DELAY)
        if not r:
            findings.append({"payload": payload, "result": "no response"})
            continue
        lowtxt = r.text.lower()
        # check for SQL error strings
        for sig in SQLI_ERROR_SIGNS:
            if sig in lowtxt:
                findings.append({"payload": payload, "result": "error-signature", "signature": sig})
                break
        else:
            # content-length heuristic: significant change might indicate different result
            if abs(len(r.text) - len(base_response_text)) > 100:
                findings.append({"payload": payload, "result": "response-size-diff", "delta": len(r.text) - len(base_response_text)})
    if findings:
        return {"tested": True, "vulnerable": True, "evidence": findings}
    return {"tested": True, "vulnerable": False}

def test_url_params_for_vulns(url):
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return {"tested": False}
    base_resp = fetch(url)
    time.sleep(REQUEST_DELAY)
    base_text = base_resp.text if base_resp else ""
    results = {}
    for param in qs.keys():
        xss = test_reflected_xss(url, param, base_text)
        sqli = test_sqli(url, param, base_text)
        results[param] = {"xss": xss, "sqli": sqli}
    return {"tested": True, "param_results": results}

def test_forms(forms):
    results = []
    for form in forms:
        action = form["action"]
        method = form["method"]
        inputs = form["inputs"]
        # Try to build a GET-style query for quick checks (if method is POST we still attempt a GET check to detect reflection)
        params = {}
        for inp in inputs:
            params[inp["name"]] = inp.get("value") or "test"
        test_url = action
        try:
            if method == "get":
                # attach sample param if none exist
                url_with_qs = test_url
                if "?" not in test_url:
                    url_with_qs = f"{test_url}?{urlencode(params)}"
                # run param-based tests
                r = fetch(url_with_qs)
                time.sleep(REQUEST_DELAY)
                link_results = test_url_params_for_vulns(url_with_qs)
                results.append({"form": form, "quick_test": link_results})
            else:
                # For POST, do small reflective check by sending a payload and seeing if it's reflected
                # (We do not perform login brute-forcing or authenticated assaults.)
                payload = {"_pentoolkit_test": XSS_PAYLOAD}
                try:
                    r = session.post(action, data=payload, timeout=8, verify=False, allow_redirects=True)
                    time.sleep(REQUEST_DELAY)
                    if XSS_PAYLOAD in r.text:
                        results.append({"form": form, "quick_test": {"reflected_xss": True}})
                    else:
                        results.append({"form": form, "quick_test": {"reflected_xss": False}})
                except Exception:
                    results.append({"form": form, "quick_test": {"error": "posting failed"}})
        except Exception as e:
            results.append({"form": form, "error": str(e)})
    return results

def crawl_and_scan(start_url, max_pages=30):
    parsed_base = urlparse(start_url)
    to_visit = [start_url]
    visited = set()
    vulnerabilities = []
    pages_scanned = 0

    while to_visit and pages_scanned < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        pages_scanned += 1
        print(f"[scan] fetching: {url}")
        r = fetch(url)
        time.sleep(REQUEST_DELAY)
        if not r:
            continue
        # security headers check
        sec_headers = check_security_headers(r)
        links, forms = extract_links_and_forms(url, r.text)
        # filter same origin links
        same_origin_links = [l for l in links if same_origin(start_url, l)]
        # param tests on this url (if contains querystring)
        param_tests = test_url_params_for_vulns(url) if urlparse(url).query else {"tested": False}
        # test forms
        forms_test = test_forms(forms) if forms else []
        vulnerabilities.append({
            "url": url,
            "status_code": r.status_code,
            "security_headers": sec_headers,
            "param_tests": param_tests,
            "forms_test": forms_test
        })
        # queue new same-origin links
        for l in same_origin_links:
            if l not in visited and l not in to_visit:
                to_visit.append(l)
    return {"start_url": start_url, "pages_scanned": pages_scanned, "results": vulnerabilities}

def generate_reports(scan_result):
    ts = int(time.time())
    json_path = os.path.join(REPORTS_DIR, f"vuln_report_{ts}.json")
    md_path = os.path.join(REPORTS_DIR, f"vuln_report_{ts}.md")
    with open(json_path, "w") as jf:
        json.dump(scan_result, jf, indent=2)
    # simple markdown
    lines = [f"# Vulnerability Scan Report", f"Start URL: {scan_result.get('start_url')}", f"Pages scanned: {scan_result.get('pages_scanned')}", ""]
    for page in scan_result.get("results", []):
        lines.append(f"## {page.get('url')}")
        lines.append(f"- Status: {page.get('status_code')}")
        sh = page.get("security_headers", {})
        if sh.get("error"):
            lines.append(f"- Security headers: error fetching")
        else:
            lines.append(f"- Present headers: {', '.join(sh.get('present', {}).keys()) or 'None'}")
            lines.append(f"- Missing headers: {', '.join(sh.get('missing') or []) or 'None'}")
        pt = page.get("param_tests")
        if pt and pt.get("tested"):
            lines.append(f"- Parameter tests:")
            for p, res in pt.get("param_results", {}).items():
                lines.append(f"  - Param `{p}`: XSS: {res['xss'].get('vulnerable')} | SQLi: {res['sqli'].get('vulnerable')}")
        if page.get("forms_test"):
            lines.append("- Form quick-tests:")
            for f in page.get("forms_test", []):
                if f.get("quick_test", {}).get("reflected_xss") is True:
                    lines.append(f"  - Form at {f.get('form', {}).get('action')} appears to reflect payloads (possible XSS).")
        lines.append("")
    with open(md_path, "w") as mf:
        mf.write("\n".join(lines))
    return json_path, md_path

def run_scan(start_url, max_pages=15):
    print("[*] Starting lightweight vulnerability scan (lab-only).")
    res = crawl_and_scan(start_url, max_pages=max_pages)
    print("[*] Scan complete — generating reports.")
    j, m = generate_reports(res)
    print(f"[+] JSON report: {j}")
    print(f"[+] Markdown report: {m}")
    return res

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Pentoolkit - lightweight web vuln scanner (lab only)")
    parser.add_argument("start_url", help="Starting URL (include scheme, e.g., http://localhost:3000)")
    parser.add_argument("--max-pages", type=int, default=12, help="Maximum pages to crawl (limit)")
    args = parser.parse_args()
    run_scan(args.start_url, max_pages=args.max_pages)
