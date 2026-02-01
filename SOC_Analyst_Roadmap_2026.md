# **SOC Analyst L1/L2 Roadmap - 2026 Edition**
*Optimized for 2027 Job Market Entry*

**Timeline**: 14-16 months  
**Study Schedule**: 5-6 hours daily (35-42 hours/week)  
**Philosophy**: Deep knowledge over superficial coverage. Foundation + AI-augmented skills.

---

## **Executive Summary**

This roadmap prepares you for the modern SOC environment where:
- **AI copilots handle 60-90% of L1 triage** (you supervise and validate)
- **Identity is the new perimeter** (cloud-first security)
- **Detection quality > volume** (behavioral analytics, not just signatures)
- **SIEM platforms integrate AI/ML** natively (UEBA, Fusion, anomaly detection)

**Key Differentiators for 2026-2027**:
- Microsoft Sentinel + Elastic Stack mastery (90% of job market)
- AI Copilot proficiency (Security Copilot, prompt engineering)
- Cloud identity security (Azure AD/Entra ID, OAuth attacks)
- Behavioral analytics understanding (UEBA, ML-driven detection)
- Detection-as-Code mindset (Sigma rules, KQL, version control)

---

## **Phase 1: Unshakeable Foundation (5 months)**
*This foundation determines your career ceiling. Don't rush.*

### **Month 1-1.5: Networking Fundamentals (6 weeks)**

**Why 6 weeks**: Network analysis is 40% of SOC work. You must understand traffic patterns instinctively.

#### **Week 1-2: TCP/IP Deep Dive**

**Daily Schedule** (6 hours):
- **Hours 1-2**: Theory - TCP/IP stack, OSI model
- **Hours 3-4**: Wireshark - capture and analyze real traffic
- **Hours 5-6**: Lab work - Packet Tracer/GNS3 network building

**Must-Master Concepts**:
- **TCP 3-way handshake**: SYN → SYN-ACK → ACK (explain while asleep)
- **Subnetting**: Instant CIDR and subnet mask calculations
- **Routing fundamentals**: How packets traverse networks
- **Normal vs Suspicious Traffic**: Baseline understanding of HTTP, DNS, SSH patterns

**Practical Validation**:
- Identify port scans in pcaps within 30 seconds
- Spot DNS tunneling attempts
- Recognize data exfiltration patterns
- Differentiate legitimate bulk transfers from malicious activity

#### **Week 3-4: Protocol Analysis**

**Focus Protocols**:

**HTTP/HTTPS**:
- Status codes (200, 301, 403, 404, 500)
- Headers analysis (User-Agent, Referer, Authorization)
- Request/response structure
- Common attack patterns (SQLi, XSS, directory traversal)

**DNS**:
- Query types (A, AAAA, MX, TXT, CNAME)
- Resolution process (recursive vs iterative)
- DNS tunneling detection
- DGA (Domain Generation Algorithm) patterns

**Email Protocols** (SMTP/POP3/IMAP):
- Email flow and headers
- SPF, DKIM, DMARC validation
- Phishing indicators

**Secure Protocols** (SSH/RDP/VPN):
- Normal authentication patterns
- Brute force detection
- Lateral movement indicators

#### **Week 5-6: Network Security Foundations**

**Technologies**:
- **Firewalls**: Stateful vs stateless, rule analysis, policy review
- **VPN**: Tunneling protocols, encryption standards
- **Proxies**: Forward vs reverse, traffic inspection capabilities
- **IDS/IPS**: Signature vs anomaly-based detection

**Hands-on Requirements**:
- Build multi-VM network topology (minimum 5 VMs)
- Capture and analyze 100+ diverse traffic samples
- Document your network architecture with diagrams
- Create a personal reference library of "normal" vs "suspicious" traffic

**Resources**:
- Wireshark Network Analysis (book)
- Chris Greer's YouTube channel
- Cisco Packet Tracer labs
- PracticalPacketAnalysis.com

---

### **Month 2-3.5: Operating Systems Mastery (8 weeks)**

**Critical Reality**: OS knowledge is 50% of SOC work. Logs, processes, and system behavior are your primary data sources.

#### **Month 2 (Weeks 7-10): Windows Deep Dive**

**Week 7-8: Windows Server & Active Directory**

**Core Skills**:
- Windows Server 2022 installation and configuration
- **Active Directory structure**:
  - Users, groups, Organizational Units (OUs)
  - Group Policy Objects (GPOs)
  - Domain Services (DNS, DHCP)
  - Trust relationships
- **Permissions**: NTFS permissions, share permissions, inheritance models

**Daily Practice**:
- Create realistic AD environment (departments, roles, nested groups)
- Practice intentional misconfigurations → document fixes
- User lifecycle management (creation, modification, lockout, deletion)
- GPO troubleshooting and analysis

**Week 9-10: Windows Security & Event Logs**

**Critical Event IDs** (memorize these):

| Event ID | Description | SOC Significance |
|----------|-------------|------------------|
| 4624 | Successful logon | Understand all logon types (2=interactive, 3=network, 10=RDP) |
| 4625 | Failed logon | Brute force detection, account enumeration |
| 4648 | Explicit credentials | Lateral movement indicator (RunAs, PSExec) |
| 4672 | Admin privileges assigned | Privilege escalation monitoring |
| 4720 | User account created | Persistence mechanism detection |
| 4688 | Process creation | Command execution tracking (enable with Sysmon) |
| 4768/4769 | Kerberos TGT/TGS | Kerberoasting, Golden/Silver ticket detection |
| 4776 | NTLM authentication | Pass-the-hash detection |

**PowerShell Essentials**:
```powershell
# Log querying
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}
Get-EventLog -LogName Security -After (Get-Date).AddHours(-24)

# System enumeration
Get-Process | Where-Object {$_.Company -eq $null}
Get-Service | Where-Object {$_.Status -eq 'Running'}
Get-NetTCPConnection -State Established

# Basic automation
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} | 
  Group-Object -Property {$_.Properties[5].Value} | 
  Where-Object {$_.Count -gt 5} | 
  Select-Object Name, Count
```

**Hands-on Projects**:
1. Install Sysmon with SwiftOnSecurity configuration
2. Generate and analyze authentication events (simulate attacks safely)
3. **Build detection scripts**: 
   - Failed login threshold alerting
   - Unusual process execution detection
   - Lateral movement indicators
4. Document every simulation with screenshots and analysis

**2026 Addition**: Understand Windows Defender for Endpoint integration (logs, alerts, response actions)

---

#### **Month 3-3.5 (Weeks 11-14): Linux Deep Dive**

**Philosophy**: Be fluent in CLI, not isolated from GUI. Modern SOC uses both.

**Week 11-12: Linux Command Line Mastery**

**Essential Commands**:

**File Operations**:
```bash
ls -lah          # Detailed listing with hidden files
find / -name "*.log" -mtime -1    # Recently modified logs
locate filename  # Fast file search
```

**Text Processing** (Critical for log analysis):
```bash
grep -r "Failed password" /var/log/
awk '{print $1, $4}' access.log | sort | uniq -c
sed 's/pattern/replacement/g' file.txt
cut -d: -f1,3 /etc/passwd
```

**Log Analysis**:
```bash
tail -f /var/log/auth.log    # Real-time monitoring
head -n 50 /var/log/syslog
less +F /var/log/apache2/access.log
cat /var/log/nginx/error.log | grep "404"
```

**Process Management**:
```bash
ps aux | grep suspicious
top / htop       # Resource monitoring
kill -9 PID
systemctl status service_name
```

**Network Analysis**:
```bash
netstat -tulpn   # All listening ports
ss -tunap        # Modern netstat alternative
lsof -i :80      # What's using port 80
tcpdump -i eth0 port 443
iptables -L -v   # Firewall rules
```

**Week 13-14: Linux Security & Services**

**Infrastructure Setup**:
- Ubuntu Server 24.04 LTS (headless) installation
- **SSH hardening**:
  - Key-based authentication
  - Disable root login
  - Change default port
  - Fail2ban configuration
- **Web server deployment**: Nginx or Apache
- **Log rotation**: Understanding logrotate
- **Cron jobs**: Scheduled tasks, persistence detection

**Critical Log Files**:
```
/var/log/auth.log          # Authentication events
/var/log/syslog            # System events
/var/log/nginx/access.log  # Web access
/var/log/nginx/error.log   # Web errors
/var/log/kern.log          # Kernel messages
```

**Hands-on Requirements**:
- Deploy LAMP/LEMP stack from scratch
- Practice log parsing with grep/awk/sed pipelines
- Detect SSH brute force in auth.log
- Identify web attacks (SQLi, directory traversal) in access logs
- Write bash scripts for automated log analysis

**2026 Update**: 
- **Container awareness**: Understand Docker/Podman basics (many SOC tools now containerized)
- **Cloud Linux**: Practice with Ubuntu 24.04 LTS (current standard)

---

### **Month 4: Security Fundamentals (4 weeks)**

#### **Week 15-16: Core Security Concepts**

**Foundational Frameworks**:
- **CIA Triad + AAA**: Confidentiality, Integrity, Availability + Authentication, Authorization, Accounting
- **Threat Modeling**: STRIDE, DREAD methodologies
- **Risk Management**: Qualitative vs quantitative approaches
- **OWASP Top 10 (2025)**: Web application vulnerabilities
- **Kill Chain & Diamond Model**: Attack lifecycle understanding

**2026 Focus**: Cloud security principles (shared responsibility model, zero trust)

#### **Week 17-18: MITRE ATT&CK Framework**

**Critical Understanding**: Don't memorize everything. Understand the concept and focus on prevalent techniques.

**Top 15 Techniques** (prioritize these):

| Technique ID | Name | Detection Focus |
|--------------|------|-----------------|
| T1566 | Phishing | Email analysis, user behavior |
| T1059 | Command/Scripting Interpreter | PowerShell, cmd, bash execution |
| T1055 | Process Injection | Abnormal process relationships |
| T1003 | Credential Dumping | LSASS access, memory dumps |
| T1021 | Remote Services | RDP, SSH, WinRM lateral movement |
| T1078 | Valid Accounts | Behavior analytics, impossible travel |
| T1071 | Application Layer Protocol | C2 communication over HTTP/DNS |
| T1105 | Ingress Tool Transfer | File downloads, suspicious uploads |
| T1053 | Scheduled Task/Job | Persistence via cron/Task Scheduler |
| T1082 | System Information Discovery | Reconnaissance commands |
| T1069 | Permission Groups Discovery | Enumeration activity |
| T1087 | Account Discovery | User/group enumeration |
| T1018 | Remote System Discovery | Network reconnaissance |
| T1210 | Exploitation of Remote Services | Vulnerability exploitation |
| T1110 | Brute Force | Password attacks |

**Practical Exercises**:
- Map real APT reports to ATT&CK Navigator
- Understand data sources for each technique
- Practice writing detection logic in pseudocode
- Study detection engineering for top 5 techniques

**2026 Addition**: Focus on cloud-specific techniques (T1078.004 Cloud Accounts, T1550 Use Alternate Authentication Material)

---

### **Month 5: First Certification (4 weeks)**

#### **CompTIA Security+ (SY0-701)**

**Why Now**: Validates foundation before moving to specialized skills. Opens 70% of entry-level SOC doors.

**Study Strategy**:
- **Hours 1-3**: Study domain material
- **Hours 4-5**: Practice exams (target 90%+ accuracy)
- **Hour 6**: Review mistakes, create Anki flashcards

**Domain Focus**:
1. **General Security Concepts** (12%)
2. **Threats, Vulnerabilities, and Mitigations** (22%) ← Leverage your OS work
3. **Security Architecture** (18%)
4. **Security Operations** (28%) ← Critical for SOC roles
5. **Security Program Management and Oversight** (20%)

**Performance-Based Questions** (PBQs):
- Log analysis scenarios
- Network diagram interpretation
- Firewall rule configuration
- Incident response procedures

**Resources**:
- Professor Messer (free video series + study groups)
- Jason Dion practice exams (Udemy - highest rated)
- Official CompTIA CertMaster Practice
- Exam Cram book for quick review

**Goal**: Pass Security+ by end of Month 5

---

## **Phase 2: SIEM Mastery + AI Integration (5.5 months)**
*This phase makes you employable and competitive*

### **Month 6-7: Elastic Security Stack (8 weeks)**

**Why Elastic**: Open-source, widely adopted, excellent for learning SIEM fundamentals and ML-based detection.

#### **Month 6 (Weeks 23-26): ELK Deployment**

**Week 23-24: Core Stack Architecture**

**Components Understanding**:
- **Elasticsearch**: Indexing engine, sharding, replication, cluster health
- **Logstash**: ETL pipeline, grok patterns, filters (mutate, geoip, date)
- **Kibana**: Visualization interface, dashboards, Discover, Lens
- **Beats**: Lightweight shippers (Filebeat, Metricbeat, Winlogbeat, Packetbeat)

**Hands-on Deployment**:
1. Deploy ELK stack (Docker recommended for easy management)
2. Configure Winlogbeat on Windows VMs → collect Event Logs
3. Configure Filebeat on Linux VMs → collect syslog, auth.log, nginx logs
4. Create index patterns and data views
5. Build basic dashboards for system monitoring

**Week 25-26: Elastic Security Module**

**Detection Capabilities**:
- **Detection Rules**: Create rules for common attack patterns
  - Brute force detection
  - Process injection indicators
  - Suspicious PowerShell
  - Unusual network connections
- **Machine Learning Jobs** (intro):
  - Rare process detection
  - Unusual user behavior
  - Anomalous network traffic
- **Timelines**: Investigation workflow
- **Cases**: Incident management

**Hands-on Projects**:
- Import Elastic prebuilt detection rules
- Create 10+ custom detection rules
- Build security dashboards (authentication, network, endpoint)
- Configure alerting for critical events

---

#### **Month 7 (Weeks 27-30): ML Analytics & Advanced Detection**

**Week 27-28: Machine Learning Jobs** (2026 Critical Skill)

**Anomaly Detection Theory**:
- How ML identifies statistical outliers
- Baseline establishment (initial learning period)
- Scoring and thresholds
- False positive management

**Prebuilt ML Jobs**:
- Rare process execution
- DNS tunneling detection
- Unusual network activity
- Suspicious login patterns
- Data exfiltration indicators

**Custom ML Job Creation**:
- Define data source (indices)
- Select influencers and partition fields
- Set bucket span appropriately
- Tune sensitivity based on environment

**Practical Exercises**:
1. Deploy 5+ prebuilt ML jobs
2. Wait for baseline period (2-3 weeks minimum)
3. Analyze anomalies: true positives vs false positives
4. Create 2+ custom ML jobs for your environment
5. Document tuning process

**Week 29-30: Advanced Hunting with EQL**

**Event Query Language (EQL)**:
```
sequence by user.name
  [authentication where event.outcome == "failure"]
  [authentication where event.outcome == "failure"]
  [authentication where event.outcome == "success"]
| head 10
```

**Capabilities**:
- Sequence queries (detect attack chains)
- Correlation across multiple events
- Temporal logic (within timeframe)
- Complex boolean logic

**Investigation Workflows**:
- Alert triage methodology
- Timeline reconstruction
- Root cause analysis
- Evidence collection
- Incident documentation

**Portfolio Project**: Document 5+ complete investigations with:
- Initial alert/indicator
- Investigation steps
- Timeline analysis
- Evidence collected
- Conclusion and recommendations

---

### **Month 8-9.5: Microsoft Sentinel Mastery (8 weeks)**

**Why Sentinel**: #1 enterprise SIEM for 2026. Azure integration, native AI/ML, and dominant market presence in Europe/US.

#### **Month 8 (Weeks 31-34): Sentinel Fundamentals**

**Week 31-32: Azure & Sentinel Setup**

**Prerequisites**:
- Azure free account ($200 credit)
- Understanding of Azure resource groups and subscriptions
- Basic RBAC concepts

**Deployment Steps**:
1. Create Log Analytics Workspace
2. Enable Microsoft Sentinel
3. Configure data retention policies
4. Set up RBAC (Reader, Responder, Contributor roles)

**Data Connectors** (configure these):
- Microsoft 365 Defender
- Azure Active Directory (Entra ID)
- Azure Activity
- Windows Security Events (via AMA - Azure Monitor Agent)
- Linux Syslog (via AMA)
- Threat Intelligence Platforms

**Week 33-34: KQL Mastery**

**Kusto Query Language = Your Native Language**

**Essential Operators**:

```kql
// Basic querying
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailedAttempts = count() by Account, Computer
| where FailedAttempts > 5
| order by FailedAttempts desc

// Advanced: Lateral movement detection
let timeframe = 14d;
let threshold = 3;
SecurityEvent
| where TimeGenerated > ago(timeframe)
| where EventID == 4624 and LogonType == 3
| summarize DistinctSources = dcount(IpAddress) by Account
| where DistinctSources > threshold

// Joining tables
SecurityEvent
| where EventID == 4688  // Process creation
| join kind=inner (
    SecurityEvent
    | where EventID == 4625  // Failed login
) on Computer
| project TimeGenerated, Computer, ProcessName, Account

// Time series analysis
SecurityAlert
| where TimeGenerated > ago(30d)
| summarize Count = count() by bin(TimeGenerated, 1d), AlertSeverity
| render timechart
```

**Daily KQL Practice** (30-60 minutes):
1. Write 10+ queries daily
2. Convert MITRE techniques to KQL
3. Practice joins, unions, summarizations
4. Master visualization (timechart, make-series, render)
5. Create a personal KQL query library

**Resources**:
- Microsoft's KQL from scratch (free)
- KQL Cafe (interactive learning)
- Sentinel Ninja training
- MustLearnKQL blog

---

#### **Month 9-9.5 (Weeks 35-38): AI-Powered Detection**

**Week 35-36: UEBA (User and Entity Behavior Analytics)** ← 2026 CRITICAL

**What is UEBA**:
- Machine learning that establishes behavioral baselines for users and entities
- Risk scoring based on deviations from normal behavior
- Peer group analysis (compares user to similar users)
- Timeline visualization of behavior changes

**UEBA Configuration**:
1. **Enable UEBA** in Sentinel (Settings → UEBA)
2. **Data sources**: Azure AD, AWS, Office 365, network logs
3. **Entities to monitor**: Users, hosts, IP addresses, cloud resources
4. **Baseline period**: 30+ days for accurate modeling

**UEBA Behaviors Layer** (NEW 2025-2026):
- Access the `BehaviorAnalytics` table in Sentinel
- AI-generated plain-language descriptions (e.g., "Suspicious mass secret access")
- Anomaly scores and risk levels
- Investigation priority recommendations

**Critical Understanding**:
- **First 30 days** = noisy baseline establishment
- Expect 10+ false positives daily initially
- Focus on **persistent anomalies** (repeated over multiple days)
- Context is everything (understand user's role, department, normal activities)

**Real-World UEBA Use Cases**:

| Scenario | UEBA Detection | Investigation Focus |
|----------|----------------|---------------------|
| Insider Threat | User accessing unusual file shares outside normal pattern | File access logs, data classification |
| Account Compromise | Behavioral change after credential theft (new locations, times, activities) | Authentication logs, impossible travel |
| Privilege Abuse | Admin account used for non-admin activities or unusual times | Command execution, privilege usage |
| Data Exfiltration | Unusual data download/upload patterns or volumes | Network logs, file access, cloud storage |

**Hands-on Requirements**:
1. Deploy UEBA in lab environment
2. Wait for 30-day baseline period (critical - don't skip)
3. Analyze 50+ anomalies, classify true/false positives
4. Create custom UEBA activities for organization-specific scenarios
5. Document false positive triage process

**Week 37-38: Fusion & Advanced Analytics**

**Fusion Technology** (ML-Powered Multi-Stage Attack Detection):

**How Fusion Works**:
- Correlates **low-confidence signals** from multiple sources
- Produces **high-confidence incidents** when attack chain detected
- Identifies multi-stage attacks automatically:
  - Initial Access → Lateral Movement → Exfiltration
  - Credential Theft → Privilege Escalation → Persistence

**Example Fusion Scenario**:
```
1. Anomalous sign-in (UEBA) - Medium severity
2. Mass file download (Cloud App Security) - Low severity
3. Data upload to personal cloud (UEBA) - Low severity

→ Fusion creates: "Potential data exfiltration" - High severity
```

**Fusion Rule Types**:
- Advanced multistage attack detection
- Impossible travel scenarios
- Suspicious IP address correlation
- Ransomware activity patterns

**Analytics Rules Deep Dive**:

| Rule Type | Use Case | Detection Speed |
|-----------|----------|-----------------|
| Scheduled | Traditional time-based detection | 5-10 minute intervals |
| Near Real-Time (NRT) | Critical threats requiring sub-minute detection | ~1 minute |
| ML Behavior Analytics | Leverage machine learning models | Continuous |
| Anomaly | Statistical deviation detection | Continuous |
| Threat Intelligence | IOC matching from TI feeds | Continuous |
| Microsoft Security | Pre-built by Microsoft | Varies |

**SOAR & Automation**:

**Logic Apps / Playbooks**:
```
Trigger: High-severity incident created
Actions:
  1. Enrich with threat intelligence
  2. Query related logs
  3. Check user risk score (UEBA)
  4. Isolate device (if score > threshold)
  5. Create ticket in ticketing system
  6. Notify SOC team
  7. Generate investigation summary
```

**Common Automation Use Cases**:
- Automated IOC enrichment (VirusTotal, AbuseIPDB)
- User investigation (AD lookups, recent activities)
- Asset investigation (device information, patch status)
- Response actions (isolation, account disable, password reset)
- Notification and ticketing

**Practical Exercise**: Build 3+ playbooks for common scenarios (phishing, malware, brute force)

---

### **Month 9.5-10: AI Copilots & Agentic SOC** ← 2026 NEW CRITICAL SECTION

**Week 39-40: Microsoft Security Copilot**

**What is Security Copilot**:
- Generative AI assistant integrated with Microsoft Security products
- Natural language querying of security data
- Automated investigation summaries
- AI-driven response recommendations
- Contextual threat intelligence

**Core Capabilities**:

**1. Natural Language to KQL**:
```
You ask: "Show me failed logins from the last 24 hours for admin accounts"
Copilot generates:
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| where Account contains "admin"
| summarize count() by Account, Computer
```

**2. Incident Investigation Assistance**:
- Automatic timeline generation
- Related entity discovery
- Impact assessment
- Guided response recommendations

**3. Threat Intelligence Summarization**:
- Aggregate intelligence from multiple feeds
- Contextualize threats to your environment
- Explain complex attack techniques in plain language

**4. AI-Driven Playbook Generation**:
- Analyze incident types
- Suggest automation workflows
- Generate Logic App templates

**Critical Skills for 2026**:

**Prompt Engineering for Security**:
```
❌ Poor prompt:
"Show threats"

✅ Effective prompt:
"Analyze the last 7 days of authentication events for user john.doe@company.com. 
Identify any anomalies including unusual sign-in times, new locations, or failed 
authentication attempts. Correlate with any related security alerts."
```

**AI Validation Skills**:
- **Never trust AI blindly**: Always validate recommendations
- Understand when AI might hallucinate or misinterpret
- Verify AI-generated queries before execution
- Cross-reference AI threat intel with authoritative sources

**Hands-on Practice**:
1. Use Security Copilot trial (if available) or study documentation
2. Practice prompt engineering techniques
3. Validate AI-generated KQL queries
4. Compare AI investigation summaries with manual analysis
5. Document scenarios where AI helps vs misleads

**Week 40: Agentic SOC Concepts** ← 2026 NEW

**What is Agentic SOC**:
- AI agents that autonomously investigate and triage alerts
- Full investigation reports generated without human intervention
- Integration with existing SIEM platforms
- Human oversight on high-risk actions

**Key Concepts to Understand**:

**Autonomous Alert Investigation**:
- AI receives alert from SIEM
- Automatically queries relevant data sources
- Correlates events across multiple systems
- Assesses risk and impact
- Generates analyst-style report
- Escalates to human analyst if needed

**Why This Matters for Your Career**:
- Agentic platforms now handle 60-90% of L1 triage
- Your role shifts from "alert analyst" to "AI supervisor"
- Focus becomes: validating AI decisions, handling complex cases, tuning AI behavior

**Interview Preparedness**:
Even if you don't work with these specific platforms, understand the concepts:
- Autonomous triage vs human-in-the-loop
- AI decision validation
- False positive management in AI systems
- When to override AI recommendations

**Study Resources**:
- Read whitepapers from Dropzone AI, Radiant Security
- Understand the shift in SOC analyst responsibilities
- Practice explaining how you would validate AI-generated investigations

---

### **Month 10.5-11: Detection Engineering (4 weeks)**

**Week 41-42: Sigma Rules & Detection-as-Code**

**What is Sigma**:
- Generic signature format for SIEM systems
- YAML-based detection rules
- Platform-agnostic (converts to Splunk, Elastic, Sentinel, etc.)
- Version control friendly

**Sigma Rule Structure**:
```yaml
title: Suspicious PowerShell Execution
id: 12345678-1234-1234-1234-123456789abc
status: stable
description: Detects suspicious PowerShell commands often used in attacks
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: Your Name
date: 2026-02-01
modified: 2026-02-01
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    product: windows
    service: powershell
detection:
    selection:
        EventID: 4104
        ScriptBlockText|contains:
            - 'IEX'
            - 'Invoke-Expression'
            - 'DownloadString'
            - '-encodedcommand'
    condition: selection
falsepositives:
    - Legitimate administrative scripts
level: high
```

**Week 41 Focus**:
- Sigma syntax and structure
- Detection logic development
- MITRE ATT&CK mapping
- False positive identification

**Week 42 Focus**:
- Rule testing and validation
- Platform conversion (Sigma → KQL, Sigma → Elastic)
- Version control with Git
- Continuous improvement process

**Week 43-44: Advanced Detection & Behavioral Analytics**

**Behavioral Detection Techniques**:

**Statistical Baselines**:
```kql
// Establish baseline for file access volume
let baseline = 
    FileAccessEvents
    | where TimeGenerated between (ago(30d) .. ago(7d))
    | summarize AvgAccess = avg(count()) by User, bin(TimeGenerated, 1d);

// Detect deviations
FileAccessEvents
| where TimeGenerated > ago(7d)
| summarize CurrentAccess = count() by User, bin(TimeGenerated, 1d)
| join kind=inner baseline on User
| extend Deviation = (CurrentAccess - AvgAccess) / AvgAccess
| where Deviation > 2.0  // More than 2x normal
```

**Threat Hunting Queries**:
- Proactive search for unknown threats
- Hypothesis-driven investigation
- Anomaly-based discovery

**Detection Optimization**:
- Performance tuning (query efficiency)
- False positive reduction techniques
- Alert fatigue management
- Severity and priority calibration

**Portfolio Requirement**: Create 25-30 custom Sigma rules covering:
- 10+ MITRE ATT&CK techniques
- Different log sources (Windows, Linux, network, cloud)
- Various attack stages (reconnaissance, execution, lateral movement, exfiltration)

---

### **Month 11.5-12: Incident Response Tools (4 weeks)**

**Week 45-46: Velociraptor**

**What is Velociraptor**:
- Open-source endpoint visibility and forensics
- Agent-based collection
- VQL (Velociraptor Query Language)
- Live response capabilities

**Core Capabilities**:
- Forensic artifact collection
- Real-time endpoint querying
- Memory analysis
- File system investigation
- Network connection enumeration

**Practical Skills**:
- Deploy Velociraptor server
- Install agents on endpoints
- Create VQL queries for common scenarios
- Collect forensic artifacts
- Analyze collected data

**Week 47-48: TheHive & Integration**

**TheHive**:
- Incident response platform
- Case management
- Task assignment and tracking
- Evidence collection and organization
- Collaboration features

**Cortex**:
- Automated analysis engine
- Observable enrichment (IP, domain, hash analysis)
- Integration with threat intelligence feeds
- Responder actions

**Integration Workflow**:
```
SIEM Alert → TheHive Case Creation → Cortex Enrichment → 
Human Analysis → Response Actions → Case Documentation
```

**Practical Project**: Build complete IR workflow connecting Sentinel → TheHive → Cortex

---

### **Month 12: Cloud Identity & Modern Attacks** ← 2026 CRITICAL ADDITION

**Week 49-50: Azure AD / Entra ID Security**

**Why This is Critical**:
- Identity is the new perimeter
- 80%+ of breaches involve identity compromise
- Cloud-first organizations dominate 2026 job market

**Key Concepts**:

**Azure AD Fundamentals**:
- Users, groups, roles
- Multi-factor authentication (MFA)
- Conditional Access policies
- Identity Protection
- Privileged Identity Management (PIM)

**Common Identity Attacks**:

| Attack Type | Description | Detection |
|-------------|-------------|-----------|
| Password Spray | Low-volume password attempts across many accounts | Failed auth + multiple users |
| MFA Fatigue | Repeated MFA prompts until user approves | MFA push notification patterns |
| OAuth Token Theft | Stealing access tokens | Anomalous OAuth grants, token replay |
| Consent Phishing | Tricking users into granting app permissions | Unusual app consent events |
| Golden SAML | Forging SAML tokens | Unusual SAML token creation |

**Azure AD Logs**:
- Sign-in logs (SigninLogs table)
- Audit logs (AuditLogs table)
- Risky sign-ins and users
- Conditional Access policy triggers

**KQL Examples**:
```kql
// Detect password spray
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != 0  // Failed sign-in
| summarize FailedAccounts = dcount(UserPrincipalName) by IPAddress
| where FailedAccounts > 10

// MFA fatigue detection
SigninLogs
| where AuthenticationRequirement == "multiFactorAuthentication"
| where TimeGenerated > ago(1h)
| summarize MFAPrompts = count() by UserPrincipalName, bin(TimeGenerated, 5m)
| where MFAPrompts > 5
```

**Week 51-52: Cloud Security & Alert Triage**

**Alert Triage Methodology** (2026 Reality):

**The 60-70% Rule**: In real SOC, triage and false positive management is the majority of your work.

**Triage Framework**:
1. **Initial Assessment** (30 seconds):
   - Alert severity and confidence
   - Affected asset criticality
   - User/entity context
   
2. **Quick Validation** (2-5 minutes):
   - Is activity expected? (known change, business process)
   - Does it match known false positive patterns?
   - Check asset and user baselines
   
3. **Investigation Decision**:
   - True Positive → Escalate/Investigate
   - False Positive → Document and tune detection
   - Benign True Positive → Close with notes

**Alert Fatigue Reduction**:
- Tune detection rules continuously
- Create exceptions for known benign activity
- Adjust severity based on context
- Implement alert aggregation
- Use AI-assisted filtering (Security Copilot)

**Cloud-Specific Security**:
- Shared responsibility model
- Cloud configuration auditing
- Identity-based access control
- API security monitoring
- Container and serverless security basics

---

## **Phase 3: Certification & Job Market Entry (2 months)**

### **Month 13: Microsoft SC-200 Certification**

**Why SC-200**: Validates Sentinel, UEBA, Fusion, and Microsoft security ecosystem expertise. Highest ROI for SOC roles in 2026.

**Exam Domains**:
1. **Mitigate threats using Microsoft Defender** (25-30%)
   - Defender for Endpoint
   - Defender for Office 365
   - Defender for Identity
   - Defender for Cloud Apps
   
2. **Mitigate threats using Microsoft Sentinel** (50-55%)
   - Data connectors and ingestion
   - KQL queries
   - Analytics rules
   - SOAR and automation
   - Threat hunting
   - Notebooks
   
3. **Mitigate threats using Microsoft Defender for Cloud** (15-20%)
   - Cloud security posture management
   - Compliance and regulatory standards
   - Threat protection

**Study Resources**:
- Microsoft Learn (official free training paths)
- SC-200 labs (hands-on practice in Azure)
- John Savill's SC-200 study guide
- MeasureUp practice exams
- Whizlabs practice tests

**Study Schedule** (4 weeks):
- **Week 1-2**: Microsoft Defender ecosystem
- **Week 3**: Sentinel deep dive (you already know this well)
- **Week 4**: Practice exams and weak area review

**Critical**: Use Microsoft Defender Portal (not just Azure Portal) for practice, as Sentinel is migrating to unified interface.

**Goal**: Pass SC-200 by end of Month 13

---

### **Month 14: Portfolio, Resume, & Active Job Search**

**Week 53-54: Portfolio Completion**

**GitHub Portfolio Structure**:
```
SOC-Analyst-Portfolio/
├── README.md (Overview, skills, certifications)
├── Lab-Environment/
│   ├── Architecture-Diagram.png
│   ├── Tools-and-Configuration.md
│   └── Screenshots/
├── Investigation-Reports/
│   ├── 01-Brute-Force-Detection.md
│   ├── 02-Lateral-Movement-Analysis.md
│   ├── 03-Data-Exfiltration-Investigation.md
│   ├── ... (10+ reports)
├── Detection-Rules/
│   ├── Sigma-Rules/
│   │   ├── PowerShell-Abuse.yml
│   │   ├── Credential-Dumping.yml
│   │   └── ... (25-30 rules)
│   ├── KQL-Queries/
│   │   ├── Threat-Hunting-Queries.md
│   │   └── Detection-Analytics.md
├── Automation/
│   ├── Sentinel-Playbooks/
│   ├── PowerShell-Scripts/
│   └── Bash-Scripts/
└── Certifications/
    ├── Security-Plus-Badge.png
    └── SC-200-Badge.png
```

**10+ Investigation Reports** must include:
- Executive summary
- Initial indicator/alert
- Investigation methodology
- Timeline of events
- Evidence collected (screenshots, logs)
- MITRE ATT&CK mapping
- Conclusion and remediation recommendations

**Quality over Quantity**: 10 detailed, professional reports > 50 superficial ones.

**Week 55-56: Resume & Job Applications**

**Resume Optimization**:

**Header Section**:
- GitHub portfolio link (prominently displayed)
- LinkedIn profile
- Email and phone
- Location (if relevant)

**Certifications** (list first):
- CompTIA Security+ (SY0-701)
- Microsoft Security Operations Analyst (SC-200)

**Technical Skills**:
```
SIEM Platforms: Microsoft Sentinel (KQL, UEBA, Fusion), Elastic Stack (EQL, ML Jobs)
Security Tools: Sysmon, Velociraptor, TheHive, Cortex, Wireshark
Operating Systems: Windows Server (AD, Event Logs, PowerShell), Linux (Ubuntu, CLI, Log Analysis)
Cloud Security: Azure AD/Entra ID, Identity Protection, Conditional Access
Detection Engineering: Sigma rules, MITRE ATT&CK mapping, behavioral analytics
AI/ML Security: Security Copilot, UEBA, anomaly detection, agentic SOC concepts
Scripting: PowerShell, Bash, KQL
```

**Experience Section** (even without professional experience):

```
SOC Analyst Lab Environment | Self-Directed Learning | [Dates]
- Deployed Microsoft Sentinel and Elastic Stack in hybrid environment (20+ VMs)
- Analyzed 500+ security events, triaging true vs false positives
- Created 30+ Sigma detection rules mapped to MITRE ATT&CK framework
- Conducted 10+ simulated incident investigations with full documentation
- Implemented UEBA and behavioral analytics for anomaly detection
- Built automated response playbooks using Logic Apps
- GitHub Portfolio: [link]
```

**Quantify Everything**:
- "Analyzed 500+ security events" (not "analyzed logs")
- "Created 30+ detection rules" (not "wrote some rules")
- "Reduced false positives by 40%" (if applicable)

**Job Application Strategy**:

**Target Companies**:
- MSSPs (Managed Security Service Providers)
- Enterprise SOCs (Fortune 500, large corporations)
- Government contractors (especially relevant for security clearance paths)
- Cloud-native companies (high demand for Azure/cloud skills)

**Application Volume**: 10-15 quality applications per week
- Tailor resume for each application
- Reference specific tools/technologies from job description
- Highlight matching skills

**Networking**:
- LinkedIn optimization (headline: "SOC Analyst | Security+ | SC-200 | Sentinel & Elastic")
- Join Discord communities (BlueTeamLabs, Cybersecurity, Sentinel)
- Attend virtual security conferences and meetups
- Engage with SOC professionals on Twitter/LinkedIn
- Join local cybersecurity groups

**Interview Preparation**:

**Technical Scenarios** (practice daily):
- "Walk me through investigating a brute force alert"
- "How would you detect lateral movement in Windows?"
- "What's your process for triaging high-severity alerts?"
- "Explain UEBA and when it's most valuable"
- "How do you handle alert fatigue?"
- "Describe a time you reduced false positives" (use lab examples)

**Behavioral Questions**:
- "Why SOC analyst?"
- "How do you stay current with security trends?"
- "How do you handle stress during incidents?"
- "Describe your learning process for new tools"

**Questions to Ask Interviewers**:
- "What SIEM platform do you use?" (gauge fit with your skills)
- "How do you handle alert fatigue and false positives?"
- "What's the ratio of L1 to L2 analysts?"
- "Is there a career progression path?"
- "How much automation/AI do you use for triage?"

---

## **Realistic Timeline Summary**

| Months | Phase | Key Deliverables | Validation |
|--------|-------|------------------|------------|
| 1-5 | Foundation | Networking, Windows, Linux, Security+ | Security+ certification |
| 6-7 | Elastic Stack | SIEM fundamentals, ML jobs, EQL | 5+ documented investigations |
| 8-9.5 | Microsoft Sentinel | KQL, UEBA, Fusion, analytics | Advanced KQL queries, UEBA analysis |
| 9.5-10 | AI Copilots | Security Copilot, agentic SOC | Prompt engineering skills |
| 10.5-11 | Detection Engineering | Sigma rules, behavioral detection | 30+ Sigma rules in GitHub |
| 11.5-12 | IR Tools & Cloud | Velociraptor, TheHive, Azure AD | IR workflow integration |
| 13 | SC-200 Certification | Advanced Microsoft security | SC-200 certification |
| 14 | Job Market | Portfolio, resume, applications | Active job search |

---

## **Critical Success Factors**

### **What Makes This 2026-Relevant**:

✅ **AI/ML Integration**: UEBA, Fusion, Security Copilot, agentic concepts
✅ **Cloud-First Security**: Azure AD, identity attacks, cloud monitoring
✅ **Behavioral Analytics**: Statistical baselines, anomaly detection, ML understanding
✅ **Modern SIEM Platforms**: Sentinel (dominant) + Elastic (foundational)
✅ **Detection-as-Code**: Sigma rules, version control, automation
✅ **Alert Triage Reality**: Focus on false positive management, decision frameworks
✅ **Defender Portal Migration**: Unified SOC interface (2026 standard)

### **What to Avoid**:

❌ **Over-engineering foundation**: No need to manually recreate every attack
❌ **Too many tools superficially**: Master 2 SIEMs deeply > 5 tools poorly
❌ **Ignoring AI capabilities**: AI is integral to 2026 SOC, not optional
❌ **Pure on-host thinking**: Modern SOC is signal analysis, not constant SSH tunneling
❌ **Skipping certifications**: Security+ and SC-200 open doors significantly

### **2026 Job Market Expectations**:

**SOC L1 Requirements** (Typical):
- Security+ or equivalent
- SIEM experience (Sentinel preferred, Elastic acceptable)
- KQL proficiency
- Understanding of UEBA and ML-based detection
- Basic cloud security knowledge (Azure AD)
- Incident investigation methodology
- Strong documentation skills

**SOC L2 Requirements** (Typical):
- L1 requirements +
- SC-200 or equivalent advanced certification
- Advanced KQL and detection engineering
- Threat hunting experience
- IR tool proficiency (Velociraptor, forensics tools)
- Automation/SOAR experience
- MITRE ATT&CK expertise


**Global Remote Opportunities**:
- Security+ and SC-200 critical for international roles
- English proficiency essential

### **Growth Path Beyond SOC L2**:

**6-12 months after L1**:
- SOC L2 Analyst (senior investigator, lead on complex cases)

**12-24 months**:
- **Threat Hunter** (proactive threat detection)
- **Detection Engineer** (focus on rule creation and tuning)
- **Incident Response Specialist** (forensics, remediation)

**24-36 months**:
- **SOC Team Lead** (mentor L1/L2, process improvement)
- **Security Engineer** (architecture, tool deployment)
- **Threat Intelligence Analyst** (tactical intel, adversary tracking)

**3-5 years**:
- **SOC Manager** (team management, strategy)
- **Senior Detection Engineer** (advanced analytics, ML tuning)
- **Principal Security Architect** (enterprise security design)

---

## **Daily Study Routine Template**

**5-6 Hour Daily Schedule**:

**Hour 1-2**: Theoretical study
- Read documentation, watch tutorials
- Review security concepts
- Study MITRE ATT&CK techniques

**Hour 3-4**: Hands-on lab work
- Configure tools
- Capture and analyze logs
- Create detection rules
- Simulate attacks

**Hour 5**: Practice and reinforcement
- KQL/EQL query practice
- Work through scenarios
- Review previous day's notes

**Hour 6**: Documentation and review
- Document what you learned
- Update GitHub portfolio
- Create Anki flashcards
- Plan next day

**Weekly Review** (2-3 hours Sunday):
- Review week's accomplishments
- Update learning tracker
- Identify gaps and adjust next week
- Practice explaining concepts (to yourself or others)

---

## **Essential Resources**

### **Learning Platforms**:
- **Microsoft Learn** (free, official Sentinel/Azure training)
- **TryHackMe** (SOC Level 1 learning path)
- **CyberDefenders** (Blue team challenges)
- **LetsDefend** (SOC analyst simulations)

### **YouTube Channels**:
- John Hammond (security fundamentals)
- IppSec (though offense-focused, useful for understanding attacks)
- 13Cubed (forensics and DFIR)
- Black Hills Information Security (SOC and blue team)

### **Books**:
- "Blue Team Handbook" by Don Murdoch
- "Practical Packet Analysis" by Chris Sanders
- "The Practice of Network Security Monitoring" by Richard Bejtlich
- "Intelligence-Driven Incident Response" by Scott J. Roberts

### **Communities**:
- /r/cybersecurity and /r/AskNetsec (Reddit)
- Blue Team Labs Online Discord
- Microsoft Sentinel Community
- SANS Internet Storm Center

### **Blogs to Follow**:
- Microsoft Security Blog
- Elastic Security Labs
- SANS Internet Storm Center
- KQL Cafe
- MustLearnKQL

---

## **Portfolio Quality Checklist**

**Before declaring your portfolio complete**:

✅ **GitHub Repository**:
- [ ] Professional README with skills summary
- [ ] Clear folder structure
- [ ] 10+ detailed investigation reports
- [ ] 25-30 Sigma rules with documentation
- [ ] Lab architecture diagram
- [ ] Screenshots of your environment

✅ **Investigation Reports**:
- [ ] Executive summary (2-3 sentences)
- [ ] Clear investigation methodology
- [ ] Evidence with timestamps
- [ ] MITRE ATT&CK mapping
- [ ] Professional formatting
- [ ] Proper grammar and spelling

✅ **Detection Rules**:
- [ ] Covers multiple MITRE techniques
- [ ] Includes false positive considerations
- [ ] Well-documented (why it detects, when it triggers)
- [ ] Tested in your lab
- [ ] Version controlled

✅ **Technical Skills Demonstration**:
- [ ] KQL queries with comments
- [ ] PowerShell/Bash scripts
- [ ] UEBA configuration examples
- [ ] Automation playbooks

---

## **Final Thoughts**

**This roadmap is realistic because**:
1. **14-16 months** allows deep learning, not superficial coverage
2. **70% hands-on** practice embeds knowledge
3. **2 strong certifications** validate skills
4. **2 dominant SIEMs** cover 90% of job market
5. **AI/ML integration** matches 2026 reality
6. **Portfolio-driven** approach demonstrates capability

**You will be job-ready when**:
- You can explain any security concept to a non-technical person
- You can triage 50 alerts and correctly identify 5 true positives
- You can write KQL queries from memory for common scenarios
- You understand when to trust AI and when to validate manually
- Your GitHub portfolio demonstrates real skill, not just completion

**Remember**:
- **Quality > Speed**: Don't rush foundations
- **Document Everything**: Your portfolio is your proof
- **Stay Current**: Security evolves; continuous learning is mandatory
- **Network Actively**: Many jobs come through referrals
- **Be Patient**: Good jobs take time; don't settle for poor fit

**Success Metric**: When you can confidently discuss a sophisticated attack scenario, map it to MITRE ATT&CK, write detection logic, and explain how UEBA would help identify it - you're ready.

---

**Prepared for**: 2027 Job Market Entry  
**Last Updated**: February 2026  
**Roadmap Version**: 2.0 (2026 Edition)

*This roadmap reflects the current state of SOC operations, incorporating AI-assisted triage, cloud-first security, and behavioral analytics that define modern security operations centers.*
