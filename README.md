# ⚡ NMAP XML SECURITY ANALYZER

### `SCAN DATA → SECURITY INTELLIGENCE → PRIORITIZED FINDINGS`

<p align="center">

![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Security](https://img.shields.io/badge/Domain-Cybersecurity-00D4AA?style=for-the-badge&logo=hackthebox&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-7B61FF?style=for-the-badge)
![Dependencies](https://img.shields.io/badge/Dependencies-Zero-00C853?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

**A lightweight Python-based security analysis tool that transforms raw Nmap XML scan results into structured, prioritized security intelligence.**

</p>

---

## 🔷 01. PROJECT OVERVIEW

Nmap is widely used for network discovery, port scanning, and service enumeration. However, reviewing large XML scan reports manually can be time-consuming.

**Nmap XML Security Analyzer** simplifies this process.

It reads existing Nmap XML reports, identifies hosts, analyzes open ports, extracts service information, and detects explicit vulnerability evidence from supported NSE script output.

The results are converted into a clean, prioritized security report directly inside your terminal.

### 🎯 Core Objective

Transform raw network scan data into an organized security assessment report that helps analysts quickly identify and review potentially vulnerable services.

**This tool is an XML analyzer, not a network scanner.** It does not initiate scans or perform exploitation.

---

## 🚀 02. KEY FEATURES

| Feature | Description |
|---|---|
| 📂 XML Parsing | Processes existing Nmap XML reports |
| 🌐 Host Discovery | Identifies hosts and their status |
| 🔓 Port Analysis | Extracts open TCP and UDP ports |
| 🔍 Service Detection | Displays detected services and versions |
| 🛡️ CVE Detection | Extracts explicit CVE references from NSE output |
| 📊 CVSS Analysis | Reads reported CVSS scores |
| ⚡ Risk Prioritization | Classifies findings by severity |
| 📑 JSON Export | Generates structured JSON reports |
| 📝 Markdown Export | Creates readable Markdown reports |
| 🧪 Automated Testing | Includes test cases for analysis logic |
| 💻 CLI Reporting | Displays formatted results in CMD/Terminal |

### Additional Security Logic

- Closed ports are not treated as vulnerabilities.
- Unknown service versions are not considered vulnerability evidence.
- Ordinary NSE script output is not automatically classified as a vulnerability.
- Explicit safe results are ignored.
- Service banners alone do not establish a vulnerability.

---

## 🧠 03. HOW IT WORKS

The analyzer follows a simple processing pipeline:

```text
       EXISTING NMAP SCAN
               |
               ▼
        NMAP XML REPORT
               |
               ▼
        XML FILE PARSER
               |
               ▼
      HOST & PORT EXTRACTION
               |
               ▼
       SERVICE INFORMATION
               |
               ▼
       NSE SCRIPT ANALYSIS
               |
               ▼
        CVE / CVSS DETECTION
               |
               ▼
       SEVERITY CLASSIFICATION
               |
          ┌────┴────┐
          ▼         ▼
      TERMINAL    REPORT EXPORT
       OUTPUT     JSON / MARKDOWN
```

### Processing Stages

**01 — XML Input**

The tool accepts an existing Nmap XML file as input.

**02 — Host Analysis**

Extracts available host information, including IP addresses, hostnames, and host status.

**03 — Port & Service Analysis**

Identifies open TCP/UDP ports and associated service information, including detected product and version details.

**04 — Vulnerability Evidence Extraction**

Examines port-level NSE script output for explicit CVE identifiers, CVSS scores, and supported vulnerability indicators.

**05 — Risk Classification**

Assigns a priority level using the CVSS score available in the XML report.

**06 — Report Generation**

Displays a formatted security summary and optionally exports JSON and Markdown reports.

---

## 🔥 04. SEVERITY CLASSIFICATION

The analyzer organizes detected vulnerability evidence into five priority categories.

| Severity | CVSS Score | Priority |
|---|---:|---|
| 🔴 CRITICAL | 9.0 – 10.0 | Immediate Review |
| 🟠 HIGH | 7.0 – 8.9 | High Priority |
| 🟡 MEDIUM | 4.0 – 6.9 | Moderate Priority |
| 🔵 LOW | Below 4.0 | Low Priority |
| ⚪ INFO | Reserved | Informational |

**Special Handling:**

If NSE output explicitly identifies a result as `VULNERABLE` but does not provide a CVSS score, the analyzer assigns HIGH as a review priority.

This is a prioritization decision, not a verified CVSS rating.

> Important: Severity is based on evidence found in the XML file. The analyzer does not independently verify vulnerabilities or calculate CVSS scores.

---

## 🖥️ 05. TERMINAL OUTPUT

Example of the expected analysis report:

```text
==========================================================
              NMAP XML SECURITY ANALYZER
==========================================================

[+] Analysis Status     : Completed
[+] Hosts in XML        : 1
[+] Active Hosts        : 1
[+] Open Ports          : 3

----------------------------------------------------------
                    PRIORITY SUMMARY
----------------------------------------------------------

[CRITICAL]  1
[HIGH]      0
[MEDIUM]    0
[LOW]       0
[INFO]      0

----------------------------------------------------------
             VULNERABILITY / SECURITY FINDINGS
----------------------------------------------------------

[01] [CRITICAL] Potential vulnerability reported by vulners

     Target       : demo-server.example
     Port         : 80/tcp
     Service      : HTTP
     CVE          : CVE-2021-41773
     Reported CVSS: 9.8

----------------------------------------------------------
                 ANALYSIS COMPLETED
----------------------------------------------------------
```

*Illustrative output based on the included sample XML. Actual formatting may vary.*

---

## 📦 06. REPORT EXPORT

The analyzer supports multiple output formats.

### JSON Export

Suitable for structured data processing, automation, and integration with other security tools.

```bash
python nmap_analyzer.py -i samples/sample_scan.xml --json report.json
```

### Markdown Export

Suitable for documentation, GitHub repositories, and security assessment notes.

```bash
python nmap_analyzer.py -i samples/sample_scan.xml --markdown report.md
```

### Combined Export

Generate both reports in one execution:

```bash
python nmap_analyzer.py -i samples/sample_scan.xml --json report.json --markdown report.md
```

---

## ⚙️ 07. INSTALLATION & SETUP

### Requirements

- Python 3.9 or newer
- Windows, Linux, or macOS
- Existing Nmap XML scan report

**No external Python packages are required.**

### Step 1 — Clone Repository

```bash
git clone https://github.com/shivkumaarr/nmap-xml-security-analyzer.git
```

### Step 2 — Open Project Directory

```bash
cd nmap-xml-security-analyzer
```

### Step 3 — Run the Analyzer

```bash
python nmap_analyzer.py -i samples/sample_scan.xml
```

That's it! The analyzer is ready to process the sample XML report.

### Optional: Install Requirements

```bash
pip install -r requirements.txt
```

The requirements file does not contain third-party dependencies.

---

## 💻 08. USAGE GUIDE

### Basic Analysis

```bash
python nmap_analyzer.py --input samples/sample_scan.xml
```

### Short Command

```bash
python nmap_analyzer.py -i samples/sample_scan.xml
```

### Windows CMD

```cmd
python nmap_analyzer.py -i samples\sample_scan.xml
```

### Custom XML File

```bash
python nmap_analyzer.py -i my_scan.xml
```

### Export Reports

```bash
python nmap_analyzer.py -i my_scan.xml --json output.json --markdown output.md
```

**Note:** The input XML file is read-only and is not modified.

---

## 🧪 09. TESTING & VALIDATION

The project includes automated unit tests to validate the analyzer's core functionality.

Run the test suite:

```bash
python -m unittest discover -s tests -v
```

### Test Coverage

| Test Case | Expected Result |
|---|---|
| Explicit CVE and CVSS evidence | Detected and prioritized |
| Closed port | Not reported as vulnerable |
| Unknown service version | Not treated as vulnerability |
| Ordinary NSE output | Not treated as vulnerability |
| Explicit safe NSE result | Ignored |
| XML parsing | Correctly processes sample data |

### Sample Test Files

- `sample_scan.xml` — Contains example vulnerability evidence.
- `clean_scan.xml` — Used for clean scan testing.

---

## 🏗️ 10. PROJECT ARCHITECTURE

```text
nmap-xml-security-analyzer/
│
├── nmap_analyzer.py
│
├── requirements.txt
│
├── README.md
│
├── AI_USAGE.md
│
├── samples/
│   ├── sample_scan.xml
│   └── clean_scan.xml
│
└── tests/
    └── test_analyzer.py
```

### Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core programming language |
| ElementTree | XML parsing |
| Argparse | Command-line interface |
| JSON | Structured report export |
| Regex | CVE/CVSS evidence extraction |
| Unittest | Automated testing |

All functionality uses Python's standard library.

---

## 🔐 11. SECURITY & RESPONSIBLE USAGE

Security analysis requires accurate interpretation of scan results.

This project follows these principles:

- Designed for authorized security assessments and educational labs.
- Does not initiate network connections.
- Does not execute Nmap NSE scripts.
- Does not exploit identified vulnerabilities.
- Does not automatically classify every open port as a security issue.
- Treats XML content as untrusted input.
- Requires manual verification of vulnerability evidence.

**Important:** A detected CVE does not automatically mean that the target is vulnerable. Verify affected versions, configurations, and vendor advisories before making security decisions.

---

## ⚠️ 12. CURRENT LIMITATIONS

The current version has some limitations:

1. Detection depends on the information already available in the XML report.
2. It does not independently verify CVEs against vulnerability databases.
3. It currently analyzes port-level NSE scripts, not host-level vulnerability scripts.
4. Unusual NSE output formats may not be recognized.
5. CVSS extraction uses intentionally simple text parsing.
6. Absence of findings does not guarantee that a system is secure.

---

## 🔮 13. FUTURE ROADMAP

The project can be expanded into a more advanced network security intelligence platform.

| Planned Feature | Description | Status |
|---|---|---|
| Extended NSE Support | Additional NSE output formats | 🔜 Planned |
| Host-Level Analysis | Host-level vulnerability script support | 🔜 Planned |
| CSV Export | Additional report format | 🔜 Planned |
| CVE Intelligence | Verified vulnerability database integration | 🔜 Planned |
| Remediation Guidance | Actionable security recommendations | 🔜 Planned |
| Advanced Filtering | Filter by host, port, and severity | 🔜 Planned |
| Configurable Severity | Custom risk thresholds | 🔜 Planned |
| Dashboard Interface | Visual security analysis interface | 💡 Future Idea |

*The roadmap represents possible future development, not currently implemented functionality.*

---

## 👨‍💻 14. AUTHOR & PROJECT INFORMATION

**Developed by: Shiv Kumar**

Cybersecurity | Vulnerability Assessment & Penetration Testing | Python Automation

This project demonstrates practical implementation of:

- Network security data analysis
- Nmap XML report processing
- Vulnerability evidence extraction
- CVE/CVSS-based prioritization
- Python scripting and automation
- Security report generation

### Connect With Me

[![GitHub](https://img.shields.io/badge/GitHub-Profile-181717?style=for-the-badge&logo=github)](https://github.com/shivkumaarr)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Profile-0A66C2?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/shiv-kumar-0797733b1/)

---

## 📜 15. LICENSE

This project is intended for educational purposes, security research, and authorized network assessment.

Released under the **MIT License**.

---

<p align="center">

### ⚡ TURN RAW SCAN DATA INTO ACTIONABLE SECURITY INSIGHTS.

**NMAP XML SECURITY ANALYZER**

<sub>Built with Python. Designed for Security Analysis. Focused on Practical Cybersecurity.</sub>

</p>
