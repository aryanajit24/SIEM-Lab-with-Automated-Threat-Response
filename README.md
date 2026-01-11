# 🛡️ Enterprise-Grade SIEM Lab with Automated Threat Response

An advanced Security Operations Center (SOC) automation platform demonstrating professional-level security monitoring, threat detection, and automated incident response capabilities.

---

## 🎯 Overview

This project showcases **enterprise-level cybersecurity skills** by building a fully functional SIEM (Security Information and Event Management) platform with automated threat response capabilities. Perfect for demonstrating **CompTIA Security+, CySA+, and GIAC-level** competencies.

### Key Features

✅ **Full SIEM Stack** - Wazuh + Elasticsearch + Suricata IDS  
✅ **Threat Intelligence** - AbuseIPDB & VirusTotal integration  
✅ **Automated Response** - Real-time IP blocking and host isolation  
✅ **Case Management** - TheHive integration for incident tracking  
✅ **MITRE ATT&CK Mapping** - 30+ detection rules aligned with ATT&CK framework  
✅ **Compliance Monitoring** - PCI-DSS, GDPR, ISO 27001 coverage  
✅ **Threat Hunting** - Custom detection rules and hunting queries  
✅ **Python Automation** - 500+ lines of professional security automation  
✅ **Ransomware Detection** - Advanced behavioral detection rules  

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MANAGEMENT CONSOLE                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   Wazuh      │  │   TheHive    │  │    MISP      │      │
│  │  Dashboard   │  │  (Cases)     │  │ (Threat Intel)│      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            │
                ┌───────────┴───────────┐
                │                       │
    ┌───────────▼──────────┐  ┌────────▼──────────┐
    │   SIEM CORE          │  │  IDS/IPS          │
    │  - Wazuh Manager     │  │  - Suricata       │
    │  - Elasticsearch     │  │  - Custom Rules   │
    │  - Logstash          │  │  - Traffic Mirror │
    └──────────┬───────────┘  └────────┬──────────┘
               │                       │
    ┌──────────▼───────────────────────▼──────────┐
    │       AUTOMATION ENGINE (Python)             │
    │  - Auto-blocking                             │
    │  - Threat hunting                            │
    │  - Case creation                             │
    │  - Compliance checks                         │
    └──────────┬───────────────────────┬──────────┘
               │                       │
    ┌──────────▼──────────┐  ┌────────▼──────────┐
    │  Windows Server     │  │  Linux Server     │
    │  - AD Controller    │  │  - Web Server     │
    │  - File Server      │  │  - Database       │
    │  - Agents           │  │  - Agents         │
    └─────────────────────┘  └───────────────────┘
```

---

## 🛠️ Tech Stack

**SIEM Platform:**
- Wazuh 4.7+ (Security monitoring)
- Elasticsearch (Log indexing & search)
- Suricata (Network intrusion detection)

**Threat Intelligence:**
- AbuseIPDB API (IP reputation)
- VirusTotal API (Malware detection)
- MISP (Threat intelligence platform)

**Case Management:**
- TheHive 5.2+ (Incident response)

**Automation:**
- Python 3.8+
- Flask (API integration)
- Requests library

**Detection:**
- 30+ custom MITRE ATT&CK rules
- Behavioral analysis
- Compliance monitoring

---

## 📋 Prerequisites

- **Operating System:** Ubuntu 20.04+ or Debian 11+
- **RAM:** Minimum 8GB (16GB recommended)
- **Disk Space:** 50GB+ available
- **Docker:** Version 20.10+
- **Python:** 3.8 or higher
- **API Keys:**
  - AbuseIPDB (Free tier: 1000 checks/day)
  - VirusTotal (Free tier: 4 requests/minute)

---

## 🚀 Installation

### Step 1: Clone the Repository

```bash
git clone https://github.com/aryanajit24/SIEM-Lab-with-Automated-Threat-Response.git
cd SIEM-Lab-with-Automated-Threat-Response
```

### Step 2: Deploy Wazuh SIEM Stack

```bash
# Clone Wazuh Docker deployment
git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.0
cd wazuh-docker/single-node

# Generate SSL certificates
docker-compose -f generate-indexer-certs.yml run --rm generator

# Start Wazuh stack
docker-compose up -d

# Wait 2-3 minutes for initialization
# Access dashboard at https://localhost
# Default credentials: admin / SecretPassword
```

### Step 3: Install Suricata IDS

```bash
# Install Suricata
sudo apt update
sudo apt install suricata -y

# Download enterprise threat detection rules
sudo suricata-update
sudo suricata-update enable-source et/open
sudo suricata-update enable-source oisf/trafficid

# Configure Suricata to monitor your network interface
sudo nano /etc/suricata/suricata.yaml
# Change 'eth0' to your network interface (find with 'ip a')

# Start Suricata
sudo systemctl enable suricata
sudo systemctl start suricata
```

### Step 4: Configure API Keys

```bash
cd ~/SIEM-Lab-with-Automated-Threat-Response

# Copy environment template
cp .env.example .env

# Edit with your API keys
nano .env
```

**Get your API keys:**

1. **AbuseIPDB:**
   - Register at https://www.abuseipdb.com/register
   - Navigate to Account → API → Create Key
   - Copy key to `.env` file

2. **VirusTotal:**
   - Register at https://www.virustotal.com/gui/join-us
   - Click your profile → API Key
   - Copy key to `.env` file

### Step 5: Install Python Dependencies

```bash
# Create virtual environment
python3 -m venv venv

# Activate environment
source venv/bin/activate  # Linux/Mac
# OR
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### Step 6: Deploy Custom Detection Rules

```bash
# Copy custom rules to Wazuh
sudo cp custom_detection_rules.xml /var/ossec/etc/rules/

# Restart Wazuh manager
sudo systemctl restart wazuh-manager
```

### Step 7: Run Automation Engine

```bash
# Start the automation platform
python3 soc_automation.py
```

---

## 📖 Usage

### Starting the Platform

1. **Start Wazuh Stack:**
   ```bash
   cd wazuh-docker/single-node
   docker-compose up -d
   ```

2. **Start Automation Engine:**
   ```bash
   cd ~/SIEM-Lab-with-Automated-Threat-Response
   source venv/bin/activate
   python3 soc_automation.py
   ```

3. **Access Dashboards:**
   - Wazuh: https://localhost
   - TheHive: http://localhost:9000
   - MISP: https://localhost:8443

### Automated Response Actions

The platform automatically performs these actions when threats are detected:

✅ **IP Blocking** - Malicious IPs blocked via iptables  
✅ **Threat Intelligence** - Real-time enrichment from AbuseIPDB & VirusTotal  
✅ **Case Creation** - Automatic incident tickets in TheHive  
✅ **MITRE Mapping** - Alerts mapped to ATT&CK techniques  
✅ **Logging** - All actions logged to `soc_automation.log`  

### Example Test Scenarios

1. **Test Brute Force Detection:**
   ```bash
   # Simulate SSH brute force
   hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://your-lab-ip
   ```

2. **Test Malware Detection:**
   ```bash
   # Download EICAR test file
   wget https://secure.eicar.org/eicar.com
   ```

3. **Test Port Scanning:**
   ```bash
   # Run nmap scan
   nmap -sS -p- your-lab-ip
   ```

---

## 🔍 Features in Detail

### 1. Threat Intelligence Integration

The automation engine enriches every alert with:
- **AbuseIPDB:** Abuse confidence score, report count, last seen
- **VirusTotal:** Malicious detections from 70+ vendors
- **MISP:** Threat indicators and IoCs

### 2. MITRE ATT&CK Mapping

All 30+ detection rules are mapped to MITRE ATT&CK:
- **Initial Access** - Brute force, phishing detection
- **Execution** - PowerShell, command shell monitoring
- **Persistence** - Registry, scheduled tasks, services
- **Privilege Escalation** - Process injection, valid accounts
- **Defense Evasion** - AV disabling, log clearing
- **Credential Access** - Mimikatz, SAM dumping
- **Discovery** - Network scanning, account enumeration
- **Lateral Movement** - RDP, SMB, pass-the-hash
- **Collection** - Data staging, screen capture
- **Exfiltration** - Cloud uploads, large transfers
- **Impact** - Ransomware, shadow copy deletion

### 3. Automated Incident Response

**Response Actions:**
- Block malicious IPs (iptables)
- Isolate compromised hosts (network segmentation)
- Kill malicious processes (active response)
- Create incident cases (TheHive)
- Generate alerts (email, Slack, webhook)

### 4. Compliance Monitoring

Detection rules cover:
- **PCI-DSS** - Cardholder data access monitoring
- **GDPR** - Personal data access tracking
- **ISO 27001** - Security policy violations
- **NIST CSF** - Framework alignment

---

## 📁 Project Structure

```
SIEM-Lab-with-Automated-Threat-Response/
├── soc_automation.py              # Main automation engine
├── custom_detection_rules.xml     # 30+ MITRE ATT&CK rules
├── requirements.txt               # Python dependencies
├── .env.example                   # API key template
├── .gitignore                     # Security exclusions
├── LICENSE                        # MIT License
└── README.md                      # This file
```

---

## 🔒 Security Notes

⚠️ **Important Security Practices:**

- Never commit `.env` file (contains API keys)
- Use read-only API keys when possible
- Respect API rate limits
- Run in isolated lab environment
- Review all detection rules before production use
- Change default Wazuh credentials immediately
- Use HTTPS for all dashboard access
- Implement proper firewall rules

---

## 🛣️ Roadmap

**Planned Enhancements:**
- [ ] Automated threat hunting playbooks
- [ ] Integration with additional threat feeds (AlienVault OTX, Shodan)
- [ ] Machine learning anomaly detection
- [ ] Advanced correlation rules
- [ ] Automated forensics data collection
- [ ] Custom dashboard with Grafana
- [ ] Slack/Teams webhook notifications
- [ ] Kubernetes deployment manifests
- [ ] CI/CD pipeline integration
- [ ] Cloud SIEM connector (AWS Security Hub, Azure Sentinel)

---

## 💡 Skills Demonstrated

This project showcases proficiency in:

✅ **Security Monitoring** - SIEM deployment and configuration  
✅ **Threat Detection** - Custom rule development  
✅ **Incident Response** - Automated response orchestration  
✅ **Threat Intelligence** - Multi-source enrichment  
✅ **Detection Engineering** - MITRE ATT&CK alignment  
✅ **Python Development** - Security automation scripting  
✅ **Log Analysis** - Correlation and pattern detection  
✅ **Compliance** - PCI-DSS, GDPR, ISO 27001 knowledge  
✅ **Network Security** - IDS/IPS configuration  
✅ **Case Management** - SOC workflow implementation  

---

## 📚 Learning Resources

**Recommended for understanding this project:**

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Suricata User Guide](https://suricata.readthedocs.io/)
- [TheHive Documentation](https://docs.thehive-project.org/)
- [AbuseIPDB API Docs](https://docs.abuseipdb.com/)
- [VirusTotal API v3](https://developers.virustotal.com/reference/overview)

**Training Platforms:**
- TryHackMe - SOC Level 1 & 2 paths
- LetsDefend - Blue Team training
- CyberDefenders - Blue Team CTF challenges

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author

**Aryan Panicker**

- 💼 LinkedIn: [linkedin.com/in/aryanajit24](https://linkedin.com/in/aryanajit24)
- 🐙 GitHub: [@aryanajit24](https://github.com/aryanajit24)
- 📧 Email: aryanajit24@gmail.com

---

## ⚠️ Disclaimer

This tool is designed for **educational purposes and legitimate security research only**. 

- Only use in isolated lab environments
- Do not deploy in production without proper security review
- Ensure you have authorization before monitoring any systems
- Respect API terms of service and rate limits
- Misuse of this tool may be illegal

---

## ⭐ Show Your Support

If this project helped you learn SIEM, threat detection, or security automation, please give it a star! ⭐

---

**Built with 🛡️ by security enthusiasts, for security enthusiasts**