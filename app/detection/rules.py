"""
Rule-based threat detection engine.
Detects various attack patterns across Linux, Windows, and Web logs.
"""
import re
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from collections import defaultdict, Counter


class ThreatDetectionEngine:
    """Engine for detecting threats based on configurable rules."""
    
    def __init__(self):
        self.rules = self._load_rules()
        self.alert_counter = 0
    
    def _load_rules(self) -> List[Dict[str, Any]]:
        """Load detection rules."""
        return [
            # === SSH BRUTE FORCE ===
            {
                "id": "RULE-001",
                "name": "SSH Brute Force Attack",
                "description": "Multiple failed SSH login attempts from the same IP",
                "category": "brute_force",
                "severity": "high",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Brute Force",
                "mitre_id": "T1110",
                "condition": self._check_ssh_brute_force,
                "threshold": 5,
                "time_window": 300,  # 5 minutes
            },
            {
                "id": "RULE-002",
                "name": "Multiple Failed Logins",
                "description": "Multiple failed authentication attempts across different services",
                "category": "brute_force",
                "severity": "high",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "Brute Force",
                "mitre_id": "T1110",
                "condition": self._check_multiple_failed_logins,
                "threshold": 10,
                "time_window": 600,
            },
            # === PRIVILEGE ESCALATION ===
            {
                "id": "RULE-003",
                "name": "Suspicious Sudo Usage",
                "description": "Suspicious sudo command execution detected",
                "category": "privilege_escalation",
                "severity": "critical",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Abuse Elevation Control Mechanism",
                "mitre_id": "T1548",
                "condition": self._check_sudo_abuse,
                "threshold": 1,
                "time_window": 0,
            },
            {
                "id": "RULE-004",
                "name": "Windows Privilege Escalation",
                "description": "Suspicious privilege assignment or process creation",
                "category": "privilege_escalation",
                "severity": "critical",
                "mitre_tactic": "Privilege Escalation",
                "mitre_technique": "Process Injection",
                "mitre_id": "T1055",
                "condition": self._check_windows_privesc,
                "threshold": 1,
                "time_window": 0,
            },
            # === WEB ATTACKS ===
            {
                "id": "RULE-005",
                "name": "SQL Injection Attempt",
                "description": "SQL injection pattern detected in web request",
                "category": "web_attack",
                "severity": "critical",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "mitre_id": "T1190",
                "condition": self._check_sql_injection,
                "threshold": 1,
                "time_window": 0,
            },
            {
                "id": "RULE-006",
                "name": "Cross-Site Scripting (XSS) Attempt",
                "description": "XSS payload detected in web request",
                "category": "web_attack",
                "severity": "high",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Drive-by Compromise",
                "mitre_id": "T1189",
                "condition": self._check_xss,
                "threshold": 1,
                "time_window": 0,
            },
            {
                "id": "RULE-007",
                "name": "Path Traversal Attempt",
                "description": "Directory traversal attack detected",
                "category": "web_attack",
                "severity": "high",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "Exploit Public-Facing Application",
                "mitre_id": "T1190",
                "condition": self._check_path_traversal,
                "threshold": 1,
                "time_window": 0,
            },
            {
                "id": "RULE-008",
                "name": "Web Scanning Activity",
                "description": "Automated scanning/scanning tool detected",
                "category": "reconnaissance",
                "severity": "medium",
                "mitre_tactic": "Reconnaissance",
                "mitre_technique": "Active Scanning",
                "mitre_id": "T1046",
                "condition": self._check_scanning,
                "threshold": 10,
                "time_window": 60,
            },
            # === POWERSHELL / WINDOWS ATTACKS ===
            {
                "id": "RULE-009",
                "name": "Suspicious PowerShell Execution",
                "description": "Suspicious PowerShell command detected",
                "category": "malicious_execution",
                "severity": "critical",
                "mitre_tactic": "Execution",
                "mitre_technique": "Command and Scripting Interpreter",
                "mitre_id": "T1059.001",
                "condition": self._check_suspicious_powershell,
                "threshold": 1,
                "time_window": 0,
            },
            {
                "id": "RULE-010",
                "name": "Encoded PowerShell Command",
                "description": "Base64 encoded PowerShell command detected",
                "category": "malicious_execution",
                "severity": "critical",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "Obfuscated Files or Information",
                "mitre_id": "T1027",
                "condition": self._check_encoded_powershell,
                "threshold": 1,
                "time_window": 0,
            },
            {
                "id": "RULE-011",
                "name": "Credential Dumping Indicator",
                "description": "Possible credential dumping activity detected",
                "category": "credential_access",
                "severity": "critical",
                "mitre_tactic": "Credential Access",
                "mitre_technique": "OS Credential Dumping",
                "mitre_id": "T1003",
                "condition": self._check_credential_dumping,
                "threshold": 1,
                "time_window": 0,
            },
            # === RDP ATTACKS ===
            {
                "id": "RULE-012",
                "name": "RDP Brute Force",
                "description": "Multiple failed RDP login attempts",
                "category": "brute_force",
                "severity": "high",
                "mitre_tactic": "Initial Access",
                "mitre_technique": "External Remote Services",
                "mitre_id": "T1133",
                "condition": self._check_rdp_brute_force,
                "threshold": 5,
                "time_window": 300,
            },
            # === MALWARE ===
            {
                "id": "RULE-013",
                "name": "Malware Execution Chain",
                "description": "Suspicious process execution chain detected",
                "category": "malware",
                "severity": "critical",
                "mitre_tactic": "Execution",
                "mitre_technique": "Malicious File",
                "mitre_id": "T1204.002",
                "condition": self._check_malware_chain,
                "threshold": 1,
                "time_window": 0,
            },
            {
                "id": "RULE-014",
                "name": "Defender Tampering",
                "description": "Windows Defender tampering detected",
                "category": "defense_evasion",
                "severity": "critical",
                "mitre_tactic": "Defense Evasion",
                "mitre_technique": "Impair Defenses",
                "mitre_id": "T1562.001",
                "condition": self._check_defender_tampering,
                "threshold": 1,
                "time_window": 0,
            },
            # === LATERAL MOVEMENT ===
            {
                "id": "RULE-015",
                "name": "Possible Lateral Movement",
                "description": "Indicators of lateral movement detected",
                "category": "lateral_movement",
                "severity": "critical",
                "mitre_tactic": "Lateral Movement",
                "mitre_technique": "Remote Services",
                "mitre_id": "T1021",
                "condition": self._check_lateral_movement,
                "threshold": 1,
                "time_window": 0,
            },
            # === DATA EXFILTRATION ===
            {
                "id": "RULE-016",
                "name": "Potential Data Exfiltration",
                "description": "Large data transfer or unusual outbound connection",
                "category": "exfiltration",
                "severity": "high",
                "mitre_tactic": "Exfiltration",
                "mitre_technique": "Exfiltration Over C2 Channel",
                "mitre_id": "T1041",
                "condition": self._check_data_exfiltration,
                "threshold": 1,
                "time_window": 0,
            },
            # === PORT SCANNING ===
            {
                "id": "RULE-017",
                "name": "Port Scanning Activity",
                "description": "Network port scanning detected",
                "category": "reconnaissance",
                "severity": "medium",
                "mitre_tactic": "Reconnaissance",
                "mitre_technique": "Port Scanning",
                "mitre_id": "T1046",
                "condition": self._check_port_scan,
                "threshold": 20,
                "time_window": 60,
            },
            # === SERVICE INSTALLATION ===
            {
                "id": "RULE-018",
                "name": "Suspicious Service Installation",
                "description": "Suspicious Windows service installation",
                "category": "persistence",
                "severity": "high",
                "mitre_tactic": "Persistence",
                "mitre_technique": "Create or Modify System Process",
                "mitre_id": "T1543.003",
                "condition": self._check_service_installation,
                "threshold": 1,
                "time_window": 0,
            },
        ]
    
    def analyze_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze a batch of logs and generate alerts."""
        alerts = []
        
        # Group logs by source IP for correlation
        ip_logs = defaultdict(list)
        for log in logs:
            ip = log.get("source_ip")
            if ip:
                ip_logs[ip].append(log)
        
        # Apply rules
        for rule in self.rules:
            detected = rule["condition"](logs, ip_logs, rule)
            if detected:
                for detection in detected:
                    self.alert_counter += 1
                    alert = {
                        "alert_id": f"ALERT-{self.alert_counter:06d}",
                        "rule_id": rule["id"],
                        "severity": rule["severity"],
                        "attack_type": rule["name"],
                        "category": rule["category"],
                        "description": detection.get("description", rule["description"]),
                        "source_ip": detection.get("source_ip"),
                        "affected_system": detection.get("affected_system"),
                        "mitre_tactic": rule.get("mitre_tactic"),
                        "mitre_technique": rule.get("mitre_technique"),
                        "mitre_technique_id": rule.get("mitre_id"),
                        "recommendation": self._get_recommendation(rule["category"]),
                        "risk_score": self._calculate_risk_score(rule, detection),
                        "confidence": detection.get("confidence", 0.8),
                        "related_logs": detection.get("related_logs", []),
                        "timestamp": datetime.utcnow(),
                    }
                    alerts.append(alert)
        
        return alerts
    
    def analyze_single_log(self, log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Analyze a single log entry for immediate threats."""
        alerts = self.analyze_logs([log])
        return alerts[0] if alerts else None
    
    # === RULE CONDITIONS ===
    
    def _check_ssh_brute_force(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for SSH brute force attacks."""
        detections = []
        threshold = rule["threshold"]
        
        for ip, ip_log_list in ip_logs.items():
            failed_logins = [l for l in ip_log_list 
                           if l.get("event_type") in ["failed_login", "auth_failure"] 
                           and l.get("source_type") in ["linux_auth", "linux_ssh"]]
            
            if len(failed_logins) >= threshold:
                detections.append({
                    "source_ip": ip,
                    "description": f"SSH brute force attack from {ip} with {len(failed_logins)} failed login attempts",
                    "affected_system": failed_logins[0].get("hostname"),
                    "confidence": min(0.95, 0.7 + (len(failed_logins) - threshold) * 0.02),
                    "related_logs": [l.get("id") for l in failed_logins[:10]],
                })
        
        return detections
    
    def _check_multiple_failed_logins(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for multiple failed logins across services."""
        detections = []
        threshold = rule["threshold"]
        
        for ip, ip_log_list in ip_logs.items():
            failed_logins = [l for l in ip_log_list 
                           if l.get("event_type") in ["failed_login", "auth_failure"]]
            
            if len(failed_logins) >= threshold:
                detections.append({
                    "source_ip": ip,
                    "description": f"Multiple failed login attempts ({len(failed_logins)}) from {ip} across different services",
                    "affected_system": failed_logins[0].get("hostname"),
                    "confidence": min(0.9, 0.6 + (len(failed_logins) - threshold) * 0.01),
                    "related_logs": [l.get("id") for l in failed_logins[:10]],
                })
        
        return detections
    
    def _check_sudo_abuse(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for suspicious sudo usage."""
        detections = []
        suspicious_commands = [
            "chmod", "chown", "useradd", "usermod", "passwd", 
            "shadow", "sudoers", "visudo", "nmap", "nc -", "netcat",
            "python -m http.server", "curl.*|.*sh", "wget.*|.*sh",
            "rm -rf /", "mkfs.", "dd if=", ":(){ :|:& };:",
        ]
        
        for log in logs:
            if log.get("event_type") == "sudo_command":
                command = log.get("parsed_data", {}).get("command", "")
                for suspicious in suspicious_commands:
                    if re.search(suspicious, command, re.IGNORECASE):
                        detections.append({
                            "source_ip": log.get("source_ip"),
                            "affected_system": log.get("hostname"),
                            "description": f"Suspicious sudo command detected: {command[:100]}",
                            "confidence": 0.9,
                        })
                        break
        
        return detections
    
    def _check_windows_privesc(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for Windows privilege escalation."""
        detections = []
        
        privesc_event_ids = ["4672", "4688", "4697"]
        for log in logs:
            if log.get("event_id") in privesc_event_ids:
                parsed = log.get("parsed_data", {})
                if isinstance(parsed, dict):
                    process = parsed.get("NewProcessName", parsed.get("ProcessName", ""))
                    if process and not any(safe in process.lower() for safe in ["\\windows\\", "\\program files\\", "system32"]):
                        detections.append({
                            "source_ip": log.get("source_ip"),
                            "affected_system": log.get("hostname"),
                            "description": f"Potential privilege escalation: {process}",
                            "confidence": 0.75,
                        })
        
        return detections
    
    def _check_sql_injection(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for SQL injection attempts."""
        detections = []
        sql_patterns = [
            r"(\%27)|(\')|(\-\-)|(\%23)",
            r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
            r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
            r"((\%27)|(\'))union",
            r"exec(\s|\+)+(s|x)p\w+",
            r"UNION\s+SELECT",
            r"INSERT\s+INTO",
            r"DELETE\s+FROM",
            r"DROP\s+TABLE",
            r"1\s*=\s*1",
            r"OR\s+1\s*=\s*1",
        ]
        
        for log in logs:
            endpoint = log.get("endpoint", "")
            raw = log.get("raw_log", "")
            content = f"{endpoint} {raw}"
            
            for pattern in sql_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    detections.append({
                        "source_ip": log.get("source_ip"),
                        "affected_system": log.get("hostname"),
                        "description": f"SQL injection attempt detected in request",
                        "confidence": 0.85,
                    })
                    break
        
        return detections
    
    def _check_xss(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for XSS attempts."""
        detections = []
        xss_patterns = [
            r"<script[^>]*>[\s\S]*?</script>",
            r"javascript:",
            r"on\w+\s*=\s*['\"][^'\"]*[\"']",
            r"<iframe",
            r"<object",
            r"<embed",
            r"alert\s*\(",
            r"document\.cookie",
        ]
        
        for log in logs:
            endpoint = log.get("endpoint", "")
            for pattern in xss_patterns:
                if re.search(pattern, endpoint, re.IGNORECASE):
                    detections.append({
                        "source_ip": log.get("source_ip"),
                        "description": f"XSS payload detected in request",
                        "confidence": 0.9,
                    })
                    break
        
        return detections
    
    def _check_path_traversal(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for path traversal attempts."""
        detections = []
        traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%252e%252e%252f",
            r"/etc/passwd",
            r"/etc/shadow",
            r"win\.ini",
            r"boot\.ini",
        ]
        
        for log in logs:
            endpoint = log.get("endpoint", "")
            for pattern in traversal_patterns:
                if re.search(pattern, endpoint, re.IGNORECASE):
                    detections.append({
                        "source_ip": log.get("source_ip"),
                        "description": f"Path traversal attempt detected",
                        "confidence": 0.85,
                    })
                    break
        
        return detections
    
    def _check_scanning(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for scanning activity."""
        detections = []
        threshold = rule["threshold"]
        
        scan_indicators = ["404", "400", "403", "405"]
        for ip, ip_log_list in ip_logs.items():
            scan_logs = [l for l in ip_log_list 
                        if str(l.get("status_code", "")) in scan_indicators]
            
            if len(scan_logs) >= threshold:
                detections.append({
                    "source_ip": ip,
                    "description": f"Scanning activity detected: {len(scan_logs)} errors from {ip}",
                    "confidence": 0.7,
                })
        
        return detections
    
    def _check_suspicious_powershell(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for suspicious PowerShell execution."""
        detections = []
        suspicious_cmds = [
            "-enc", "-encodedcommand", "downloadstring", "downloadfile",
            "invoke-expression", "iex", "invoke-shellcode", "mimikatz",
            "get-wmiobject", "win32_process", "create(",
            "net.webclient", "socket", "reverse", "bypass",
            "noprofile", "noninteractive", "windowstyle hidden",
        ]
        
        for log in logs:
            raw = log.get("raw_log", "")
            for cmd in suspicious_cmds:
                if cmd.lower() in raw.lower():
                    detections.append({
                        "source_ip": log.get("source_ip"),
                        "affected_system": log.get("hostname"),
                        "description": f"Suspicious PowerShell command detected: {cmd}",
                        "confidence": 0.9,
                    })
                    break
        
        return detections
    
    def _check_encoded_powershell(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for encoded PowerShell commands."""
        detections = []
        
        for log in logs:
            raw = log.get("raw_log", "")
            if re.search(r"-enc\s+[A-Za-z0-9+/]{100,}=?=?", raw, re.IGNORECASE):
                detections.append({
                    "source_ip": log.get("source_ip"),
                    "affected_system": log.get("hostname"),
                    "description": "Encoded PowerShell command detected - possible obfuscation",
                    "confidence": 0.95,
                })
        
        return detections
    
    def _check_credential_dumping(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for credential dumping indicators."""
        detections = []
        dump_indicators = [
            "lsass.exe", "sam", "security account manager",
            "sekurlsa", "wdigest", "kerberos::list",
            "mimikatz", "procdump", "rundll32",
        ]
        
        for log in logs:
            raw = log.get("raw_log", "")
            for indicator in dump_indicators:
                if indicator.lower() in raw.lower():
                    detections.append({
                        "source_ip": log.get("source_ip"),
                        "affected_system": log.get("hostname"),
                        "description": f"Credential dumping indicator detected: {indicator}",
                        "confidence": 0.9,
                    })
                    break
        
        return detections
    
    def _check_rdp_brute_force(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for RDP brute force."""
        detections = []
        threshold = rule["threshold"]
        
        for ip, ip_log_list in ip_logs.items():
            failed_rdp = [l for l in ip_log_list 
                         if l.get("event_type") in ["failed_login", "auth_failure"]
                         and l.get("source_type") == "windows_rdp"]
            
            if len(failed_rdp) >= threshold:
                detections.append({
                    "source_ip": ip,
                    "description": f"RDP brute force: {len(failed_rdp)} failed attempts from {ip}",
                    "confidence": 0.85,
                })
        
        return detections
    
    def _check_malware_chain(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for malware execution chain."""
        detections = []
        suspicious_chains = [
            ("powershell", "cmd.exe"),
            ("wscript", "cscript"),
            ("mshta", "javascript"),
            ("regsvr32", "scrobj.dll"),
            ("certutil", "urlcache"),
        ]
        
        for log in logs:
            raw = log.get("raw_log", "")
            for proc1, proc2 in suspicious_chains:
                if proc1 in raw.lower() and proc2 in raw.lower():
                    detections.append({
                        "source_ip": log.get("source_ip"),
                        "description": f"Suspicious execution chain: {proc1} -> {proc2}",
                        "confidence": 0.8,
                    })
                    break
        
        return detections
    
    def _check_defender_tampering(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for Defender tampering."""
        detections = []
        tamper_indicators = [
            "windows defender", "disableantispyware", "disableantivirus",
            "exclusionpath", "add-mppreference", "remove-mppreference",
            "set-mppreference", "tamperprotection",
        ]
        
        for log in logs:
            raw = log.get("raw_log", "")
            for indicator in tamper_indicators:
                if indicator.lower() in raw.lower():
                    detections.append({
                        "source_ip": log.get("source_ip"),
                        "description": f"Windows Defender tampering detected: {indicator}",
                        "confidence": 0.85,
                    })
                    break
        
        return detections
    
    def _check_lateral_movement(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for lateral movement indicators."""
        detections = []
        lateral_indicators = [
            "psexec", "wmiexec", "smbexec", "mmcexec",
            "\\\\.*\\\$",  # Admin share access
            "net use", "net view",
            "schtasks", "at\\s",
            "wmic.*process.*call create",
        ]
        
        for log in logs:
            raw = log.get("raw_log", "")
            for indicator in lateral_indicators:
                if re.search(indicator, raw, re.IGNORECASE):
                    detections.append({
                        "source_ip": log.get("source_ip"),
                        "description": f"Lateral movement indicator: {indicator}",
                        "confidence": 0.8,
                    })
                    break
        
        return detections
    
    def _check_data_exfiltration(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for data exfiltration."""
        detections = []
        exfil_patterns = ["upload", "ftp", "scp ", "rsync", "mega.nz", "transfer.sh"]
        
        for log in logs:
            raw = log.get("raw_log", "")
            for pattern in exfil_patterns:
                if pattern.lower() in raw.lower():
                    detections.append({
                        "source_ip": log.get("source_ip"),
                        "description": f"Potential data exfiltration: {pattern}",
                        "confidence": 0.65,
                    })
                    break
        
        return detections
    
    def _check_port_scan(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for port scanning."""
        detections = []
        threshold = rule["threshold"]
        
        for ip, ip_log_list in ip_logs.items():
            connection_logs = [l for l in ip_log_list 
                             if l.get("event_type") in ["network_connection", "connection_event"]]
            
            if len(connection_logs) >= threshold:
                unique_ports = set()
                for l in connection_logs:
                    port = l.get("parsed_data", {}).get("port")
                    if port:
                        unique_ports.add(port)
                
                if len(unique_ports) >= 5:
                    detections.append({
                        "source_ip": ip,
                        "description": f"Port scanning detected: {len(unique_ports)} unique ports from {ip}",
                        "confidence": 0.8,
                    })
        
        return detections
    
    def _check_service_installation(self, logs, ip_logs, rule) -> List[Dict]:
        """Check for suspicious service installation."""
        detections = []
        
        for log in logs:
            if log.get("event_id") in ["4697", "7045"] or log.get("event_type") == "service_installed":
                parsed = log.get("parsed_data", {})
                service_name = ""
                if isinstance(parsed, dict):
                    service_name = parsed.get("ServiceName", parsed.get("service_name", "Unknown"))
                
                detections.append({
                    "source_ip": log.get("source_ip"),
                    "affected_system": log.get("hostname"),
                    "description": f"Service installed: {service_name}",
                    "confidence": 0.7,
                })
        
        return detections
    
    def _get_recommendation(self, category: str) -> str:
        """Get recommendation for a threat category."""
        recommendations = {
            "brute_force": "Block the source IP immediately. Review account lockout policies. Consider implementing multi-factor authentication.",
            "privilege_escalation": "Isolate the affected system. Review user permissions. Audit recent privilege changes.",
            "web_attack": "Block the source IP. Review WAF rules. Patch vulnerable applications. Monitor for successful exploitation.",
            "malicious_execution": "Isolate the affected system. Kill suspicious processes. Run full malware scan.",
            "credential_access": "Force password reset for affected accounts. Enable credential guard. Monitor for further credential access attempts.",
            "lateral_movement": "Isolate affected systems. Disable compromised accounts. Review network segmentation.",
            "malware": "Isolate the system. Run full antivirus scan. Analyze the malware sample. Review IOCs.",
            "defense_evasion": "Review security tool configurations. Restore tampered settings. Investigate root cause.",
            "exfiltration": "Block outbound connections. Review DLP policies. Investigate data scope.",
            "reconnaissance": "Monitor the source IP. Review firewall rules. Consider blocking if persistent.",
            "persistence": "Remove persistence mechanisms. Review startup items. Scan for backdoors.",
        }
        return recommendations.get(category, "Investigate the alert and take appropriate action based on findings.")
    
    def _calculate_risk_score(self, rule: Dict, detection: Dict) -> float:
        """Calculate risk score for a detection."""
        base_scores = {
            "low": 25,
            "medium": 50,
            "high": 75,
            "critical": 100,
        }
        
        base = base_scores.get(rule["severity"], 50)
        confidence = detection.get("confidence", 0.5)
        
        return min(100, base * (0.7 + confidence * 0.3))
