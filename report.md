# Nmap XML Security Analysis

```text

====================================================================
             NMAP XML SECURITY ANALYSIS REPORT
====================================================================
 Source XML       : sample_scan.xml
 Generated        : 2026-10-31T15:32:07+00:00
 Hosts in XML     : 1 (up: 1)
 Open ports       : 3
--------------------------------------------------------------------
 PRIORITY SUMMARY
 CRITICAL  : 1
 HIGH      : 0
 MEDIUM    : 0
 LOW       : 0
 INFO      : 0
--------------------------------------------------------------------
 OPEN SERVICE INVENTORY

 Host: demo-server.example [up]
   22/tcp  ssh  (OpenSSH 8.2)
   80/tcp  http  (Apache httpd 2.4.49)
   443/tcp  https  (nginx 1.24.0)

--------------------------------------------------------------------
 VULNERABILITY / SECURITY FINDINGS

 [1] [CRITICAL] Potential vulnerability reported by vulners
     Target      : demo-server.example - 80/tcp (http)
     Details     : CVEs: CVE-2021-41773 | Reported CVSS: 9.8 | NSE script: vulners | Evidence: CVE-2021-41773 CVSS: 9.8 Potentially vulnerable version reported
     Action      : Verify the affected software/version with the vendor advisory, patch if applicable, and rescan.

--------------------------------------------------------------------
 SCOPE & LIMITATIONS
 - This report summarizes evidence present in the supplied XML; it does not perform a scan.
 - A service/version or open port alone is not proof of a vulnerability.
 - NSE output and CVSS values may be incomplete, stale, or require manual verification.
 - No finding does not mean the host is secure.
====================================================================
```
