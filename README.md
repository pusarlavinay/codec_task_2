🔍 Web Application Vulnerability Scanner

A lightweight Python-based vulnerability scanner designed for educational and lab environments.
This tool helps identify common web application vulnerabilities such as SQL Injection (SQLi) and Cross-Site Scripting (XSS) by crawling and testing web pages.

⚠️ Disclaimer: This tool is for educational and authorized penetration testing only. Do not use it on systems you don’t own or have explicit permission to test.

✨ Features

✅ Crawl and scan multiple pages (--max-pages option)

✅ Detect SQL Injection points

✅ Detect Reflected XSS vulnerabilities

✅ Generate reports in JSON and Markdown

✅ Built with requests + BeautifulSoup

📂 Project Structure
web-vuln-scanner/
│── modules/
│   └── web_vuln_scanner.py   # Main vulnerability scanner
│── reports/                  # Auto-generated scan reports
│── requirements.txt          # Dependencies
│── README.md                 # Documentation

⚙️ Installation

Clone the repo:

git clone https://github.com/your-username/web-vuln-scanner.git
cd web-vuln-scanner


Create virtual environment (recommended):

python3 -m venv venv
source venv/bin/activate


Install dependencies:

pip install -r requirements.txt

🚀 Usage

Run the scanner against a target (lab/local environment only):

python3 modules/web_vuln_scanner.py http://127.0.0.1:8000 --max-pages 10

📊 Output
[*] Starting lightweight vulnerability scan (lab-only).
[scan] fetching: http://127.0.0.1:8000
[*] Scan complete — generating reports.
[+] JSON report: reports/vuln_report_1755795214.json
[+] Markdown report: reports/vuln_report_1755795214.md


📜 Reports

The scanner generates two reports:

JSON Report → machine-readable results
Output: reports/vuln_report_1755795214.json

Markdown Report → human-readable results
Output: reports/vuln_report_1755795214.md

🔧 Future Enhancements

Add CSRF vulnerability detection

Add command injection detection

Export results to HTML

👨‍💻 Author
Pusarla Vinay
