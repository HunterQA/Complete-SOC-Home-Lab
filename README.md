# 🛡️ Complete SOC Home Lab — Active Directory + Sysmon + Splunk

An end-to-end Security Operations Center home lab that simulates a small enterprise: an attacker (Kali) targets a Windows Active Directory environment, endpoint & security telemetry is collected with **Sysmon** and forwarded to **Splunk Enterprise**, and the attacks are **detected, investigated, and then defeated through hardening**.

**Author:** Manea Al-Shabrain · [GitHub](https://github.com/HunterQA) · [LinkedIn](https://www.linkedin.com/in/manea-al-shabrain)

📖 **Full write-up:** [SOC-Home-Lab-Complete-Documentation-Phase-0-to-10.pdf](SOC-Home-Lab-Complete-Documentation-Phase-0-to-10.pdf) — the complete Phase 0–10 build, detection, investigation, and hardening documentation.

---

## 🎯 What this project demonstrates
- Building a Windows **Active Directory** domain (`soclab.local`) from scratch.
- Deploying **Splunk Enterprise** as a SIEM and shipping logs via **Universal Forwarder**.
- Endpoint visibility with **Sysmon** (process creation, network connections).
- **Detecting** real attacks (network scanning, SMB brute force) with SPL.
- **Investigating** an incident end-to-end (attacker IP, targeted account, timeline).
- **Hardening** the environment and **validating** that the same attack is now blocked.

## 🗺️ Architecture
```
[ Kali Linux ]  --attack-->  [ Windows 11 Client ]
  192.168.10.30                192.168.10.20
  (attacker)                   (Sysmon + Splunk UF)
                                     |
                                     | logs (fwd :9997)
                                     v
   [ Windows Server 2022 (DC01) ]  — 192.168.10.10
   AD + DNS + Splunk Enterprise (SIEM, index: main)
```

## 🧩 Lab components
| Host | IP | Role |
|------|-----|------|
| DC01 (Windows Server 2022) | 192.168.10.10 | Active Directory + DNS + **Splunk Enterprise** (SIEM) |
| WIN11-01 (Windows 11) | 192.168.10.20 | Domain-joined endpoint + Sysmon + UF |
| KALI01 (Kali Linux) | 192.168.10.30 | Attack simulation (isolated lab only) |

Network: isolated Host-Only network · Domain: `soclab.local`

---

## 🛠️ Build phases
| Phase | What was done | Evidence |
|------:|---------------|----------|
| 1 | Domain Controller + AD users/OUs | [screenshots/phase1-DC01](screenshots/phase1-DC01) |
| 2 | Join Windows 11 to the domain (+ connectivity) | [screenshots/phase2-Windows11](screenshots/phase2-Windows11) |
| 3 | Active Directory users & domain login | [screenshots/Phase-03_ActiveDirectory](screenshots/Phase-03_ActiveDirectory) |
| 4 | Sysmon install + event verification | [screenshots/Phase-04_Sysmon](screenshots/Phase-04_Sysmon) |
| 5 | Splunk Enterprise + Universal Forwarder (port 9997) | [screenshots/Phase-05_Splunk](screenshots/Phase-05_Splunk) |
| 6 | Kali attacker VM + network verification | [screenshots/Phase-06_Kali](screenshots/Phase-06_Kali) |
| 7 | Attacks: Nmap scans + NetExec SMB brute force | [screenshots/Phase-07_Attacks](screenshots/Phase-07_Attacks) |
| 8 | Detection in Splunk (SPL + dashboard) | [screenshots/Phase-08_Detection](screenshots/Phase-08_Detection) |
| 9 | Incident investigation & report | [screenshots/Phase-09_Investigation](screenshots/Phase-09_Investigation) |
| 10 | Hardening + validation (attack re-tested & blocked) | [screenshots/Phase-10_Hardening](screenshots/Phase-10_Hardening) |

## 🔎 Detection scenarios (SPL)
All logs land in a single Splunk index (`main`) and are filtered by `source`.

**1) Port-scan detection (Nmap)** — after enabling Windows Filtering Platform auditing:
```spl
index=main source="WinEventLog:Security" (EventCode=5156 OR EventCode=5157)
| stats dc(Dest_Port) as scanned_ports by Source_Address
| where scanned_ports > 20
```
**2) SMB brute force — failed logons (Event 4625):**
```spl
index=main source="WinEventLog:Security" EventCode=4625
| table _time, Account_Name, Source_Network_Address, Failure_Reason, Sub_Status
| sort -_time
```
**3) Brute force followed by success (compromise check):**
```spl
index=main source="WinEventLog:Security" (EventCode=4625 OR EventCode=4624) Account_Name="localadmin"
| table _time, EventCode, Account_Name, Source_Network_Address, Logon_Type
| sort _time
```
**4) Account lockout (Event 4740) — proof of hardening:**
```spl
index=main source="WinEventLog:Security" EventCode=4740
| table _time, TargetUserName, CallerComputerName
```
**5) Sysmon network connections (Event 3):**
```spl
index=main (source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" OR source="WinEventLog:Microsoft-Windows-Sysmon/Operational") EventCode=3
| stats count by SourceIp, DestinationIp, DestinationPort
```

## 🧭 Incident investigation (highlights)
Traced a **NetExec SMB brute-force** attack from `192.168.10.30` against the **local account `localadmin`** on WIN11-01: **31 failed logons (Event 4625)** followed by **4 successful logons (Event 4624)**, all **Logon Type 3** (network). Identified the attacker IP and targeted account, reconstructed the attack timeline, and correlated Security logs with Sysmon Event 3.
→ Full write-up: **[Phase09-Incident-Report-BruteForce-Final.pdf](Phase09-Incident-Report-BruteForce-Final.pdf)**

## 🔒 Hardening & validation (the standout)
Applied and **validated** defensive controls, then **re-ran the same attack to prove it was blocked**:
- **Account-lockout policy** (threshold = 5 failed attempts, 15-min duration/observation window)
- **SMBv1 disabled** + SMB signing, RDP disabled, Windows Firewall enforced (all profiles), admin shares reviewed
- Verified telemetry (Sysmon + Universal Forwarder) still healthy after hardening
- **Result:** the repeated NetExec attack returned `STATUS_ACCOUNT_LOCKED_OUT` — **no successful logon after lockout** ✅
→ Full write-up: **[Phase10-Hardening-Validation-Report-Final.pdf](Phase10-Hardening-Validation-Report-Final.pdf)**

## 📊 Dashboard
A SOC monitoring dashboard summarizing events, top hosts, failed/successful logons, and scan/brute-force detections.
→ **[soc_monitoring_Dashboard.pdf](soc_monitoring_Dashboard.pdf)**

## 🎯 MITRE ATT&CK mapping
| Technique | ID | Where |
|-----------|----|-------|
| Network Service Discovery | T1046 | Nmap scans → Splunk detection |
| Brute Force: Password Guessing | T1110.001 | NetExec SMB → 4625 detection |
| Valid Accounts | T1078 | post-brute-force logon check |
| SMB/Windows Admin Shares | T1021.002 | SMB access + hardening |

## 🧠 Skills demonstrated
Active Directory · Windows Event Logging · Sysmon telemetry · Splunk SPL · SIEM log collection (Universal Forwarder) · attack detection · incident investigation & reporting · **system hardening & validation**.

## 📁 Repository contents
- `SOC-Home-Lab-Complete-Documentation-Phase-0-to-10.pdf` — **full Phase 0–10 build & analysis documentation**
- `Phase09-Incident-Report-BruteForce-Final.pdf` — incident report
- `Phase10-Hardening-Validation-Report-Final.pdf` — hardening & validation report
- `soc_monitoring_Dashboard.pdf` — SOC dashboard
- `screenshots/` — 78 phase-by-phase screenshots (evidence)

## 🚀 Future improvements
Add Splunk Security Essentials · more Sysmon detections (encoded PowerShell, LOLBins) · pfSense firewall logs · threat-intel enrichment · SOAR automation.

---
> ⚠️ All offensive activity was performed inside an **isolated Host-Only lab** on systems I own, strictly for educational and defensive purposes.
