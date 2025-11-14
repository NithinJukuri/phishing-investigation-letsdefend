📂 Phishing Investigation Case Study — LetsDefend SOC Lab
Type: Security Operations (SOC) Investigation
Category: Phishing | Threat Hunting | Incident Response
Platform: LetsDefend.io
Skills Demonstrated: Threat Intelligence, Log Analysis, Email Analysis, OSINT, Endpoint Investigation, IOC Extraction, Containment, Reporting
📝 Overview

This case study documents a complete phishing investigation performed on LetsDefend.
The incident involved an impersonating domain (letsdefwnd.io) targeting a user inside the organization. The analysis covers email inspection, threat intelligence enrichment, firewall and endpoint logs, and final remediation actions.

This write-up demonstrates full SOC workflow handling — from detection to containment and eradication.

🚨 Incident Summary

LetsDefend alerted on a suspicious domain whose MX records had changed, indicating possible phishing setup.

Shortly after, a phishing email was delivered to the user Mateo, claiming he had “won a voucher” and directing him to a fake LetsDefend domain:

http://letsdefwnd.io/

🔍 Investigation Steps
1. Email Analysis

Sender: voucher@letsdefwnd.io

Subject: “Congratulations! You’ve Won a Voucher”

Contained a button redirecting to the impersonating domain

Email content and structure matched common phishing patterns

Action: Phishing email identified and removed.

2. Threat Intelligence Review

Using LetsDefend Threat Intel:

Domain: letsdefwnd.io

Flagged as phishing

Associated with multiple suspicious IPs

Not a legitimate LetsDefend asset

VirusTotal Findings

Domain not currently active but previously used for phishing

IPs associated with similar malicious hosting infrastructure

3. OSINT & Reputation Checks

Checked using:

VirusTotal

URLscan.io

IPinfo

BrowserLeaks

WHOIS & DNS

Key outcomes:

Domain hosted on Linode / Akamai Connected Cloud, common for phishing kits

One of the IPs (45.33.23.183) was flagged as malicious by several vendors

4. Endpoint Investigation
Browser History

Mateo’s endpoint recorded a visit to:

http://www.letsdefwnd.io/


Timestamp matched the email receipt → User clicked the phishing link.

Firewall Logs

The endpoint made two outbound HTTPS connections to:

45.33.23.183


This IP is:

Malicious in VirusTotal

Known for phishing campaigns

Belongs to Akamai Connected Cloud (Linode)

This confirms direct communication between the endpoint and the attacker infrastructure.

Process & Terminal Logs

No suspicious PowerShell, cmd, mshta, or file downloads detected

No malware execution observed

Conclusion:
The attack was a credential phishing attempt, not a malware infection.

🛡️ Containment & Response
Actions Taken

Deleted phishing email from mailbox

Extracted and blocked IOCs

letsdefwnd[.]io

45.33.23.183

Contained the endpoint as precaution

Reset Mateo’s credentials and invalidated sessions

Educated user on phishing awareness

No malware found, but credentials were potentially exposed.
📌 Indicators of Compromise (IOC)

Malicious URL:

letsdefwnd[.]io


Malicious IP:

45.33.23.183


MX Record Used by Attackers:

mail.mailerhost.net

📊 Conclusion

This incident was a successful phishing lure where the user clicked a malicious link.
Investigation confirmed communication with a known phishing server, but no further compromise occurred.

The incident was contained, user credentials were protected, and preventative measures were implemented to block future attempts.

This lab provided hands-on experience in:

✔ SOC Tier-1/Tier-2 investigation workflows
✔ Log correlation (email, firewall, endpoint)
✔ Threat intel enrichment
✔ OSINT validation
✔ IOC extraction & blocking
✔ User awareness training
✔ Writing SOC case reports
