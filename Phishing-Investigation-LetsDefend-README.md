# Phishing Investigation Case Study — LetsDefend SOC Lab

**Type:** Security Operations (SOC) Investigation  
**Category:** Phishing | Threat Hunting | Incident Response  
**Platform:** LetsDefend.io  
**Skills Demonstrated:** Threat Intelligence • Email Analysis • Log Analysis • OSINT • Endpoint Investigation • Firewall Analysis • IOC Extraction • Containment • Reporting

---

## Overview

This case study documents a full phishing investigation performed on LetsDefend.  
The incident involved an impersonating domain **letsdefwnd.io** targeting an employee.  
The investigation includes:

- Email analysis  
- Threat intelligence enrichment  
- OSINT validation  
- Browser & firewall log correlation  
- Endpoint inspection  
- IOC extraction  
- Containment & response  

This demonstrates a complete Tier-1/Tier-2 SOC workflow.

---

## Initial Log Alert (Starting Point)

The first alert originated from the CTI brand protection system:

```
EventID: 304
Rule: SOC326 - Impersonating Domain MX Record Change Detected
Source: no-reply@cti-report.io
Destination: soc@letsdefend.io
Trigger Reason: MX record of suspicious domain changed
Domain: letsdefwnd[.]io
MX Record: mail.mailerhost[.]net
Action: Allowed
```

**Interpretation**
- A domain similar to "letsdefend.io" had its **MX records changed**, a common precursor to phishing activity.
- Domain resembled a typosquatting attack: `letsdefend.io` → `letsdefwnd.io`
- This signaled that attackers were preparing to send emails from this impersonating domain.

---

## Incident Summary

Shortly after the CTI alert, a phishing email was delivered to employee **Mateo**:

```
From: voucher@letsdefwnd.io
Subject: "Congratulations! You’ve Won a Voucher"
URL: http://letsdefwnd.io/
```

The email used branding, social engineering, and a fraudulent voucher link.

---

## Investigation Steps

### 1. Email Analysis
- Sender domain was the same impersonating domain flagged earlier.
- Email included a phishing link redirecting to `letsdefwnd.io`.
- Email templates resembled standard phishing reward schemes.

**Action:** Identified as phishing — removed from mailbox.

---

### 2. Threat Intelligence Review
Using LetsDefend Threat Intel:
- `letsdefwnd.io` tagged as **phishing**
- Associated with multiple VPS IPs
- Not owned by LetsDefend
- Risk score elevated

**VirusTotal Findings**
- Domain inactive at time of scan (likely taken down)
- Previously associated with multiple Linode/Akamai cloud IPs  
- IP `45.33.23.183` flagged as **malicious**  
  (Criminal IP, Forcepoint ThreatSeeker, CyRadar)

---

### 3. OSINT & Reputation Checks

Tools used:
- VirusTotal  
- URLscan.io  
- IPinfo  
- BrowserLeaks  
- WHOIS / DNS lookup  

**OSINT Outcome**
- Domain hosted on **Linode/Akamai Cloud**, commonly used for phishing kits
- IP `45.33.23.183` appears in:
  - Malware reports  
  - Security community warnings  
  - Lists of suspicious VPS hosting clusters

This matched attacker infrastructure patterns.

---

## Endpoint Investigation

### Browser History (Key Evidence)
```
2024-09-18 13:32:13
http://www.letsdefwnd.io/
```

This confirms:
- The user clicked the phishing link
- The phishing domain was active during that time

---

### Firewall Log Correlation
Two outbound HTTPS connections were recorded:

```
source_address: 172.16.17.162 (Mateo)
destination_address: 45.33.23.183
destination_port: 443
```

**Importance**
- Destination IP is confirmed malicious
- This validates that the endpoint successfully communicated with the attacker-controlled server
- This eliminates the possibility of a false click or blocked attempt — actual connection was made

---

### Process & Terminal Log Review
- No execution of scripts (PowerShell, CMD, WScript, MSHTA)
- No suspicious parent-child process behavior  
- No downloads (.exe, .zip, .js, .scr)  

**Conclusion:** This was a **credential phishing attempt**, not a malware dropper.

---

## Containment & Response

**Actions Taken**
- Deleted the phishing email  
- Added IOC entries:
  - `letsdefwnd[.]io`
  - `45.33.23.183`
  - `mail.mailerhost.net`
- Blocked IP + domain in security layers  
- Contained the endpoint  
- Reset Mateo’s credentials  
- Terminated active sessions  
- User informed & trained  
- Verified no lateral movement or malware activity

---

## Indicators of Compromise (IOC)

**Malicious URL**
```
letsdefwnd[.]io
```

**Malicious IP**
```
45.33.23.183
```

**Attacker MX Record**
```
mail.mailerhost.net
```

---

## Final Conclusion

This was a **confirmed phishing attack** using an impersonating domain.  
The user clicked the link, and the endpoint connected to a malicious server, but no malware was executed.

The incident was contained through:
- IOC blocking  
- Endpoint containment  
- Credential reset  
- Email removal  
- User training  

This investigation demonstrates:
- SOC Tier-1/Tier-2 investigation workflow  
- Log correlation (email + endpoint + firewall)  
- IOC extraction & threat intel enrichment  
- OSINT analysis  
- Incident containment & remediation  
- Clear reporting and documentation

---

## Repository Structure Suggestion

```
phishing-investigation-letsdefend/
├── screenshots/
│   ├── email-analysis.png
│   ├── browser-history.png
│   └── firewall-logs.png
├── README.md
└── IOCs.txt
```

---

*If you want, I can also create a downloadable PDF version, add a table of contents, or insert screenshot placeholders with captions (and blur sensitive data).*