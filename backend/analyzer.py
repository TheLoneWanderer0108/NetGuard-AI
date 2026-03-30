from typing import Optional

# Each rule has:
# - keywords: list of strings to match (ANY match triggers the rule)
# - threat: human-readable threat name
# - severity: none, low, medium, high, critical
# - mitre_technique_id: MITRE ATT&CK technique ID
# - mitre_technique_name: MITRE ATT&CK technique name
# - mitre_tactic: MITRE ATT&CK tactic

RULES = [
    
    {
        "keywords": ["failed login", "authentication failure", "invalid password",
                     "logon failure", "wrong password", "bad password",
                     "event id 4625", "pam_unix: authentication failure"],
        "threat": "Brute Force / Credential Attack",
        "severity": "high",
        "mitre_technique_id": "T1110",
        "mitre_technique_name": "Brute Force",
        "mitre_tactic": "Credential Access"
    },
    {
        "keywords": ["account locked", "account lockout", "too many failed attempts",
                     "event id 4740"],
        "threat": "Account Lockout",
        "severity": "high",
        "mitre_technique_id": "T1110.001",
        "mitre_technique_name": "Password Guessing",
        "mitre_tactic": "Credential Access"
    },
    {
        "keywords": ["new user created", "user account created", "useradd",
                     "net user /add", "event id 4720"],
        "threat": "Unauthorized Account Creation",
        "severity": "high",
        "mitre_technique_id": "T1136",
        "mitre_technique_name": "Create Account",
        "mitre_tactic": "Persistence"
    },
    {
        "keywords": ["privilege escalation", "sudo su", "sudo -i", "runas",
                     "event id 4672", "special privileges assigned"],
        "threat": "Privilege Escalation",
        "severity": "critical",
        "mitre_technique_id": "T1078",
        "mitre_technique_name": "Valid Accounts",
        "mitre_tactic": "Privilege Escalation"
    },

    
    {
        "keywords": ["port scan", "nmap", "syn scan", "xmas scan", "fin scan",
                     "masscan", "zenmap"],
        "threat": "Reconnaissance / Port Scanning",
        "severity": "medium",
        "mitre_technique_id": "T1046",
        "mitre_technique_name": "Network Service Discovery",
        "mitre_tactic": "Discovery"
    },
    {
        "keywords": ["directory traversal", "../", "..\\", "%2e%2e%2f",
                     "path traversal"],
        "threat": "Directory Traversal Attempt",
        "severity": "high",
        "mitre_technique_id": "T1083",
        "mitre_technique_name": "File and Directory Discovery",
        "mitre_tactic": "Discovery"
    },

    
    {
        "keywords": ["sql injection", "sqlmap", "' or '1'='1", "union select",
                     "drop table", "insert into", "xp_cmdshell", "'; --"],
        "threat": "SQL Injection Attempt",
        "severity": "critical",
        "mitre_technique_id": "T1190",
        "mitre_technique_name": "Exploit Public-Facing Application",
        "mitre_tactic": "Initial Access"
    },
    {
        "keywords": ["<script>", "xss", "javascript:", "onerror=", "onload=",
                     "alert(", "document.cookie"],
        "threat": "Cross-Site Scripting (XSS) Attempt",
        "severity": "high",
        "mitre_technique_id": "T1059.007",
        "mitre_technique_name": "JavaScript",
        "mitre_tactic": "Execution"
    },
    {
        "keywords": ["cmd.exe", "/bin/sh", "/bin/bash", "wget http", "curl http",
                     "powershell -enc", "powershell -nop", "base64 decode",
                     "whoami", "net localgroup administrators"],
        "threat": "Command Injection / Remote Code Execution",
        "severity": "critical",
        "mitre_technique_id": "T1059",
        "mitre_technique_name": "Command and Scripting Interpreter",
        "mitre_tactic": "Execution"
    },

    
    {
        "keywords": ["malware", "ransomware", "trojan", "backdoor", "rootkit",
                     "keylogger", "spyware", "cryptominer", "coinminer"],
        "threat": "Malware Detected",
        "severity": "critical",
        "mitre_technique_id": "T1204",
        "mitre_technique_name": "User Execution",
        "mitre_tactic": "Execution"
    },
    {
        "keywords": ["crontab", "scheduled task", "schtasks", "at command",
                     "event id 4698", "registry run key"],
        "threat": "Persistence Mechanism Detected",
        "severity": "high",
        "mitre_technique_id": "T1053",
        "mitre_technique_name": "Scheduled Task/Job",
        "mitre_tactic": "Persistence"
    },

    
    {
        "keywords": ["data exfiltration", "large outbound transfer", "unusual dns",
                     "dns tunneling", "dnscat"],
        "threat": "Possible Data Exfiltration",
        "severity": "critical",
        "mitre_technique_id": "T1048",
        "mitre_technique_name": "Exfiltration Over Alternative Protocol",
        "mitre_tactic": "Exfiltration"
    },
    {
        "keywords": ["ddos", "flood attack", "syn flood", "udp flood",
                     "icmp flood", "amplification attack"],
        "threat": "DDoS / Flood Attack",
        "severity": "high",
        "mitre_technique_id": "T1498",
        "mitre_technique_name": "Network Denial of Service",
        "mitre_tactic": "Impact"
    },
    {
        "keywords": ["reverse shell", "nc -e", "netcat", "bash -i >& /dev/tcp",
                     "meterpreter", "metasploit"],
        "threat": "Reverse Shell / C2 Activity",
        "severity": "critical",
        "mitre_technique_id": "T1059",
        "mitre_technique_name": "Command and Scripting Interpreter",
        "mitre_tactic": "Command and Control"
    },

    
    {
        "keywords": ["firewall rule disabled", "firewall stopped", "ufw disable",
                     "netsh advfirewall set allprofiles state off"],
        "threat": "Firewall Disabled",
        "severity": "critical",
        "mitre_technique_id": "T1562.004",
        "mitre_technique_name": "Disable or Modify System Firewall",
        "mitre_tactic": "Defense Evasion"
    },
    {
        "keywords": ["unauthorized access", "403 forbidden", "401 unauthorized",
                     "access denied", "permission denied"],
        "threat": "Unauthorized Access Attempt",
        "severity": "medium",
        "mitre_technique_id": "T1078",
        "mitre_technique_name": "Valid Accounts",
        "mitre_tactic": "Initial Access"
    },

    
    {
        "keywords": ["log cleared", "event log cleared", "audit log deleted",
                     "event id 1102", "event id 104"],
        "threat": "Log Tampering / Audit Log Cleared",
        "severity": "critical",
        "mitre_technique_id": "T1070.001",
        "mitre_technique_name": "Clear Windows Event Logs",
        "mitre_tactic": "Defense Evasion"
    },
    {
        "keywords": ["antivirus disabled", "defender disabled", "av stopped",
                     "tamper protection off"],
        "threat": "Security Tool Disabled",
        "severity": "critical",
        "mitre_technique_id": "T1562.001",
        "mitre_technique_name": "Disable or Modify Tools",
        "mitre_tactic": "Defense Evasion"
    },
]


SEVERITY_ORDER = ["critical", "high", "medium", "low", "none"]
SEVERITY_CONFIDENCE = {
    "critical": 0.95,
    "high": 0.88,
    "medium": 0.76,
    "low": 0.62,
    "none": 0.30,
}


def analyze_log(log: str) -> dict:
    log_lower = log.lower()

    matched_rules = []

    for rule in RULES:
        for keyword in rule["keywords"]:
            if keyword.lower() in log_lower:
                matched_rules.append(rule)
                break  # Don't match same rule twice

    if not matched_rules:
        return {
            "is_suspicious": False,
            "threat": "No Known Threat Detected",
            "severity": "none",
            "confidence": 0.05,
            "threats": [],
            "matched_rules": [],
            "mitre_attack": None,
            "note": "Rule-based scan found no matches. Review AI analysis for deeper insights."
        }

    matched_rules.sort(key=lambda r: SEVERITY_ORDER.index(r["severity"]))
    top_rule = matched_rules[0]

    threats = []
    for r in matched_rules:
        technique = f"{r['mitre_technique_id']} - {r['mitre_technique_name']}"
        threats.append(
            {
                "threat": r["threat"],
                "severity": r["severity"].upper(),
                "confidence": SEVERITY_CONFIDENCE.get(r["severity"], 0.50),
                "technique": technique,
                "mitre_attack": {
                    "tactic": r["mitre_tactic"],
                    "technique_id": r["mitre_technique_id"],
                    "technique_name": r["mitre_technique_name"],
                },
            }
        )

    overall_confidence = min(
        0.99,
        SEVERITY_CONFIDENCE.get(top_rule["severity"], 0.50) + (0.03 * (len(threats) - 1)),
    )

    mitre_mappings = []
    seen_techniques = set()
    for t in threats:
        tid = t["mitre_attack"]["technique_id"]
        if tid in seen_techniques:
            continue
        seen_techniques.add(tid)
        mitre_mappings.append(
            {
                "tactic": t["mitre_attack"]["tactic"],
                "technique_id": tid,
                "technique_name": t["mitre_attack"]["technique_name"],
                "technique": t["technique"],
            }
        )

    return {
        "is_suspicious": True,
        "threat": top_rule["threat"],
        "severity": top_rule["severity"].upper(),
        "confidence": round(overall_confidence, 2),
        "threats": threats,
        "matched_rules": [
            {
                "threat": r["threat"],
                "severity": r["severity"].upper(),
                "mitre_technique_id": r["mitre_technique_id"],
                "mitre_technique_name": r["mitre_technique_name"],
                "mitre_tactic": r["mitre_tactic"],
                "technique": f"{r['mitre_technique_id']} - {r['mitre_technique_name']}",
            }
            for r in matched_rules
        ],
        "mitre_mappings": mitre_mappings,
        "mitre_attack": {
            "tactic": top_rule["mitre_tactic"],
            "technique_id": top_rule["mitre_technique_id"],
            "technique_name": top_rule["mitre_technique_name"]
        }
    }