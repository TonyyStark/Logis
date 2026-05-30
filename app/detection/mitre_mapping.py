"""
MITRE ATT&CK framework mapping for threat detections.
"""
from typing import Dict, List, Optional


class MitreAttackMapper:
    """Maps security detections to MITRE ATT&CK framework."""
    
    # MITRE ATT&CK techniques mapping
    TECHNIQUES = {
        # Initial Access
        "T1190": {
            "name": "Exploit Public-Facing Application",
            "tactic": "Initial Access",
            "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system.",
            "applies_to": ["sql_injection", "xss", "path_traversal", "web_attack"],
        },
        "T1189": {
            "name": "Drive-by Compromise",
            "tactic": "Initial Access",
            "description": "Adversaries may gain access to a system through a user visiting a website.",
            "applies_to": ["xss", "drive_by"],
        },
        "T1133": {
            "name": "External Remote Services",
            "tactic": "Initial Access",
            "description": "Adversaries may leverage external-facing remote services to initially access a network.",
            "applies_to": ["rdp_brute_force", "external_remote"],
        },
        # Execution
        "T1059": {
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "description": "Adversaries may abuse command and script interpreters to execute commands.",
            "applies_to": ["powershell", "cmd", "bash"],
        },
        "T1059.001": {
            "name": "PowerShell",
            "tactic": "Execution",
            "description": "Adversaries may abuse PowerShell commands and scripts for execution.",
            "applies_to": ["suspicious_powershell", "encoded_powershell"],
        },
        "T1204.002": {
            "name": "Malicious File",
            "tactic": "Execution",
            "description": "Adversaries may rely on a user opening a malicious file.",
            "applies_to": ["malware_execution", "malicious_file"],
        },
        # Persistence
        "T1543.003": {
            "name": "Windows Service",
            "tactic": "Persistence",
            "description": "Adversaries may create or modify Windows services to repeatedly execute malicious payloads.",
            "applies_to": ["service_installation", "service_created"],
        },
        "T1136": {
            "name": "Create Account",
            "tactic": "Persistence",
            "description": "Adversaries may create an account to maintain access to victim systems.",
            "applies_to": ["user_created", "account_creation"],
        },
        # Privilege Escalation
        "T1548": {
            "name": "Abuse Elevation Control Mechanism",
            "tactic": "Privilege Escalation",
            "description": "Adversaries may circumvent mechanisms designed to control elevate privileges.",
            "applies_to": ["sudo_abuse", "uac_bypass"],
        },
        "T1055": {
            "name": "Process Injection",
            "tactic": "Privilege Escalation",
            "description": "Adversaries may inject code into processes to evade process-based defenses.",
            "applies_to": ["process_injection", "dll_injection"],
        },
        "T1078": {
            "name": "Valid Accounts",
            "tactic": "Privilege Escalation",
            "description": "Adversaries may obtain and abuse credentials of existing accounts.",
            "applies_to": ["credential_compromise", "pass_the_hash"],
        },
        # Defense Evasion
        "T1027": {
            "name": "Obfuscated Files or Information",
            "tactic": "Defense Evasion",
            "description": "Adversaries may attempt to make an executable or file difficult to discover or analyze.",
            "applies_to": ["encoded_command", "obfuscation"],
        },
        "T1562.001": {
            "name": "Disable or Modify Tools",
            "tactic": "Defense Evasion",
            "description": "Adversaries may modify and/or disable security tools to avoid possible detection.",
            "applies_to": ["defender_tampering", "disable_security"],
        },
        "T1070": {
            "name": "Indicator Removal on Host",
            "tactic": "Defense Evasion",
            "description": "Adversaries may delete or modify artifacts generated on a host system.",
            "applies_to": ["log_deletion", "clear_logs"],
        },
        # Credential Access
        "T1110": {
            "name": "Brute Force",
            "tactic": "Credential Access",
            "description": "Adversaries may use brute force techniques to gain access to accounts.",
            "applies_to": ["ssh_brute_force", "rdp_brute_force", "password_guessing"],
        },
        "T1003": {
            "name": "OS Credential Dumping",
            "tactic": "Credential Access",
            "description": "Adversaries may attempt to dump credentials to obtain account login and credential material.",
            "applies_to": ["credential_dumping", "lsass", "sam_dump"],
        },
        "T1556": {
            "name": "Modify Authentication Process",
            "tactic": "Credential Access",
            "description": "Adversaries may patch, modify, or otherwise manipulate the authentication process.",
            "applies_to": ["auth_modification", "credential_manipulation"],
        },
        # Discovery
        "T1046": {
            "name": "Network Service Scanning",
            "tactic": "Discovery",
            "description": "Adversaries may attempt to get a listing of services running on remote hosts.",
            "applies_to": ["port_scan", "service_scanning"],
        },
        "T1083": {
            "name": "File and Directory Discovery",
            "tactic": "Discovery",
            "description": "Adversaries may enumerate files and directories.",
            "applies_to": ["directory_enumeration", "file_discovery"],
        },
        "T1087": {
            "name": "Account Discovery",
            "tactic": "Discovery",
            "description": "Adversaries may attempt to get a listing of accounts on a system.",
            "applies_to": ["account_discovery", "user_enumeration"],
        },
        # Lateral Movement
        "T1021": {
            "name": "Remote Services",
            "tactic": "Lateral Movement",
            "description": "Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.",
            "applies_to": ["lateral_movement", "remote_access"],
        },
        "T1021.001": {
            "name": "Remote Desktop Protocol",
            "tactic": "Lateral Movement",
            "description": "Adversaries may use Valid Accounts to log into a computer using Remote Desktop Protocol.",
            "applies_to": ["rdp_lateral", "remote_desktop"],
        },
        "T1021.002": {
            "name": "SMB/Windows Admin Shares",
            "tactic": "Lateral Movement",
            "description": "Adversaries may use Valid Accounts to interact with a remote network share.",
            "applies_to": ["smb_lateral", "admin_share"],
        },
        # Exfiltration
        "T1041": {
            "name": "Exfiltration Over C2 Channel",
            "tactic": "Exfiltration",
            "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel.",
            "applies_to": ["data_exfiltration", "c2_communication"],
        },
        "T1048": {
            "name": "Exfiltration Over Alternative Protocol",
            "tactic": "Exfiltration",
            "description": "Adversaries may steal data by exfiltrating it over a different protocol.",
            "applies_to": ["dns_exfiltration", "icmp_exfiltration"],
        },
        # Impact
        "T1499": {
            "name": "Endpoint Denial of Service",
            "tactic": "Impact",
            "description": "Adversaries may perform endpoint denial of service.",
            "applies_to": ["dos", "resource_exhaustion"],
        },
    }
    
    TACTICS = {
        "Initial Access": "TA0001",
        "Execution": "TA0002",
        "Persistence": "TA0003",
        "Privilege Escalation": "TA0004",
        "Defense Evasion": "TA0005",
        "Credential Access": "TA0006",
        "Discovery": "TA0007",
        "Lateral Movement": "TA0008",
        "Collection": "TA0009",
        "Exfiltration": "TA0010",
        "Impact": "TA0040",
    }
    
    @classmethod
    def get_technique(cls, technique_id: str) -> Optional[Dict]:
        """Get technique details by ID."""
        return cls.TECHNIQUES.get(technique_id)
    
    @classmethod
    def get_tactic_id(cls, tactic_name: str) -> Optional[str]:
        """Get tactic ID by name."""
        return cls.TACTICS.get(tactic_name)
    
    @classmethod
    def map_detection(cls, category: str, event_type: str = None) -> List[Dict]:
        """Map a detection category to MITRE techniques."""
        matches = []
        
        for tech_id, tech in cls.TECHNIQUES.items():
            applies = tech.get("applies_to", [])
            if category.lower() in [a.lower() for a in applies]:
                matches.append({
                    "technique_id": tech_id,
                    "name": tech["name"],
                    "tactic": tech["tactic"],
                    "tactic_id": cls.TACTICS.get(tech["tactic"]),
                    "description": tech["description"],
                })
            elif event_type and event_type.lower() in [a.lower() for a in applies]:
                matches.append({
                    "technique_id": tech_id,
                    "name": tech["name"],
                    "tactic": tech["tactic"],
                    "tactic_id": cls.TACTICS.get(tech["tactic"]),
                    "description": tech["description"],
                })
        
        return matches
    
    @classmethod
    def get_all_techniques(cls) -> List[Dict]:
        """Get all techniques."""
        return [
            {
                "technique_id": tid,
                "name": t["name"],
                "tactic": t["tactic"],
                "tactic_id": cls.TACTICS.get(t["tactic"]),
            }
            for tid, t in cls.TECHNIQUES.items()
        ]
    
    @classmethod
    def get_all_tactics(cls) -> List[Dict]:
        """Get all tactics."""
        return [
            {"tactic_id": tid, "name": name}
            for name, tid in cls.TACTICS.items()
        ]
