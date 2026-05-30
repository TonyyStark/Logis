"""
Windows log parser for Security, System, PowerShell, Sysmon, and RDP logs.
"""
import re
import json
from datetime import datetime
from typing import Dict, Any, Optional


class WindowsLogParser:
    """Parser for Windows event logs."""
    
    # Windows Event ID mapping
    EVENT_IDS = {
        # Authentication
        "4624": {"type": "successful_login", "description": "An account was successfully logged on", "severity": "low"},
        "4625": {"type": "failed_login", "description": "An account failed to log on", "severity": "medium"},
        "4634": {"type": "account_logoff", "description": "An account was logged off", "severity": "low"},
        "4647": {"type": "user_initiated_logoff", "description": "User initiated logoff", "severity": "low"},
        "4648": {"type": "explicit_credential_use", "description": "A logon was attempted using explicit credentials", "severity": "medium"},
        "4771": {"type": "kerberos_preauth_failed", "description": "Kerberos pre-authentication failed", "severity": "medium"},
        "4776": {"type": "ntlm_auth_failed", "description": "The computer attempted to validate credentials", "severity": "medium"},
        
        # Privilege Escalation
        "4672": {"type": "special_privileges", "description": "Special privileges assigned to new logon", "severity": "medium"},
        "4673": {"type": "privileged_service_called", "description": "A privileged service was called", "severity": "medium"},
        "4674": {"type": "privileged_operation", "description": "An operation was attempted on a privileged object", "severity": "medium"},
        "4688": {"type": "process_creation", "description": "A new process has been created", "severity": "low"},
        "4692": {"type": "backup_attempt", "description": "Backup of data protection master key was attempted", "severity": "medium"},
        "4697": {"type": "service_installed", "description": "A service was installed in the system", "severity": "high"},
        
        # PowerShell
        "4103": {"type": "powershell_module", "description": "PowerShell module logging", "severity": "medium"},
        "4104": {"type": "powershell_scriptblock", "description": "PowerShell script block logging", "severity": "medium"},
        "4105": {"type": "powershell_command", "description": "PowerShell command start", "severity": "medium"},
        
        # Sysmon
        "1": {"type": "process_create", "description": "Process Create", "severity": "low"},
        "2": {"type": "file_change", "description": "A file creation time was changed", "severity": "medium"},
        "3": {"type": "network_connection", "description": "Network connection detected", "severity": "low"},
        "5": {"type": "process_terminated", "description": "Process terminated", "severity": "low"},
        "7": {"type": "image_loaded", "description": "Image loaded", "severity": "low"},
        "8": {"type": "create_remote_thread", "description": "CreateRemoteThread detected", "severity": "high"},
        "10": {"type": "process_access", "description": "ProcessAccess", "severity": "medium"},
        "11": {"type": "file_create", "description": "FileCreate", "severity": "low"},
        "12": {"type": "registry_add", "description": "RegistryEvent (Object create and delete)", "severity": "medium"},
        "13": {"type": "registry_set", "description": "RegistryEvent (Value Set)", "severity": "medium"},
        
        # RDP
        "1149": {"type": "rdp_authentication", "description": "User authentication succeeded", "severity": "low"},
        "21": {"type": "rdp_session_logon", "description": "Session logon succeeded", "severity": "low"},
        "22": {"type": "rdp_session_shell", "description": "Shell start notification received", "severity": "low"},
        "24": {"type": "rdp_session_disconnected", "description": "Remote Desktop Services: Session has been disconnected", "severity": "low"},
        "25": {"type": "rdp_reconnection", "description": "Remote Desktop Services: Session reconnection succeeded", "severity": "low"},
        
        # Account Management
        "4720": {"type": "user_created", "description": "A user account was created", "severity": "medium"},
        "4726": {"type": "user_deleted", "description": "A user account was deleted", "severity": "high"},
        "4732": {"type": "member_added", "description": "A member was added to a security-enabled local group", "severity": "high"},
        
        # Defender
        "1006": {"type": "defender_malware", "description": "Antimalware engine found malware", "severity": "critical"},
        "1007": {"type": "defender_action", "description": "Antimalware platform performed action", "severity": "high"},
        "1015": {"type": "defender_blocked", "description": "Windows Defender blocked malware", "severity": "critical"},
        "1116": {"type": "defender_detection", "description": "Windows Defender detected malware", "severity": "critical"},
        "1117": {"type": "defender_action_taken", "description": "Windows Defender took action", "severity": "high"},
        "1119": {"type": "defender_engine_failure", "description": "Antimalware engine failure", "severity": "critical"},
        
        # Other
        "7045": {"type": "service_installed", "description": "A service was installed in the system", "severity": "high"},
        "7036": {"type": "service_state", "description": "Service state changed", "severity": "low"},
    }
    
    def parse(self, raw_log: str, source_type: str = "windows_security") -> Dict[str, Any]:
        """Parse a Windows log entry."""
        # Try JSON format first (modern Windows logs)
        if raw_log.strip().startswith("{"):
            try:
                return self._parse_json_log(raw_log, source_type)
            except (json.JSONDecodeError, KeyError):
                pass
        
        # Try XML format
        if raw_log.strip().startswith("<"):
            return self._parse_xml_log(raw_log, source_type)
        
        # Try plain text format
        return self._parse_text_log(raw_log, source_type)
    
    def _parse_json_log(self, raw_log: str, source_type: str) -> Dict[str, Any]:
        """Parse JSON-formatted Windows log."""
        data = json.loads(raw_log)
        
        event_id = str(data.get("EventID", data.get("EventId", data.get("event_id", ""))))
        event_info = self.EVENT_IDS.get(event_id, {})
        
        result = {
            "timestamp": self._parse_timestamp(data.get("TimeCreated", data.get("timestamp", ""))),
            "source_ip": self._extract_ip_from_data(data),
            "username": self._extract_username_from_data(data),
            "hostname": data.get("Computer", data.get("hostname", None)),
            "process_name": self._extract_process_from_data(data),
            "event_id": event_id,
            "event_type": event_info.get("type", source_type),
            "severity": event_info.get("severity", "low"),
            "operating_system": "windows",
            "raw_log": raw_log,
            "parsed_data": data,
        }
        
        return result
    
    def _parse_xml_log(self, raw_log: str, source_type: str) -> Dict[str, Any]:
        """Parse XML-formatted Windows log."""
        try:
            from xml.etree import ElementTree as ET
            root = ET.fromstring(raw_log)
            
            # Extract EventID
            event_id = ""
            event_data = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventID")
            if event_data is not None:
                event_id = event_data.text or ""
            
            event_info = self.EVENT_IDS.get(event_id, {})
            
            # Extract timestamp
            time_created = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated")
            timestamp = self._parse_timestamp(time_created.get("SystemTime") if time_created is not None else "")
            
            # Extract computer name
            computer = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}Computer")
            hostname = computer.text if computer is not None else None
            
            # Extract data from EventData
            parsed_data = {}
            event_data_elem = root.find(".//{http://schemas.microsoft.com/win/2004/08/events/event}EventData")
            if event_data_elem is not None:
                for data in event_data_elem.findall("{http://schemas.microsoft.com/win/2004/08/events/event}Data"):
                    name = data.get("Name", "")
                    value = data.text or ""
                    if name:
                        parsed_data[name] = value
            
            return {
                "timestamp": timestamp,
                "source_ip": parsed_data.get("IpAddress", parsed_data.get("SourceAddr", None)),
                "username": parsed_data.get("TargetUserName", parsed_data.get("SubjectUserName", None)),
                "hostname": hostname,
                "process_name": parsed_data.get("NewProcessName", parsed_data.get("ProcessName", None)),
                "event_id": event_id,
                "event_type": event_info.get("type", source_type),
                "severity": event_info.get("severity", "low"),
                "operating_system": "windows",
                "raw_log": raw_log,
                "parsed_data": parsed_data,
            }
        except Exception:
            return self._parse_text_log(raw_log, source_type)
    
    def _parse_text_log(self, raw_log: str, source_type: str) -> Dict[str, Any]:
        """Parse plain text Windows log."""
        # Try to extract EventID
        event_id_match = re.search(r"EventID[=:]\s*(\d+)", raw_log, re.IGNORECASE)
        event_id = event_id_match.group(1) if event_id_match else ""
        
        event_info = self.EVENT_IDS.get(event_id, {})
        
        return {
            "timestamp": self._parse_timestamp(raw_log),
            "source_ip": self._extract_ip(raw_log),
            "username": self._extract_username(raw_log),
            "hostname": None,
            "process_name": None,
            "event_id": event_id,
            "event_type": event_info.get("type", source_type),
            "severity": event_info.get("severity", "low"),
            "operating_system": "windows",
            "raw_log": raw_log,
            "parsed_data": {},
        }
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse Windows timestamp."""
        if not timestamp_str:
            return datetime.utcnow()
        
        # ISO format
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%m/%d/%Y %I:%M:%S %p",
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        return datetime.utcnow()
    
    def _extract_ip_from_data(self, data: Dict) -> Optional[str]:
        """Extract IP from parsed data."""
        ip_fields = ["IpAddress", "SourceAddr", "ClientIP", "RemoteHost", "ip"]
        for field in ip_fields:
            if field in data and data[field] and data[field] not in ["-", "::1", "127.0.0.1"]:
                return data[field]
        
        # Search in nested data
        for key, value in data.items():
            if isinstance(value, str):
                match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", value)
                if match:
                    ip = match.group(1)
                    if ip not in ["0.0.0.0", "127.0.0.1", "::1"]:
                        return ip
        
        return None
    
    def _extract_username_from_data(self, data: Dict) -> Optional[str]:
        """Extract username from parsed data."""
        user_fields = ["TargetUserName", "SubjectUserName", "User", "username", "AccountName"]
        for field in user_fields:
            if field in data and data[field] and data[field] not in ["-", "SYSTEM", "ANONYMOUS LOGON", "NT AUTHORITY"]:
                return data[field]
        return None
    
    def _extract_process_from_data(self, data: Dict) -> Optional[str]:
        """Extract process name from parsed data."""
        process_fields = ["NewProcessName", "ProcessName", "Image", "Application"]
        for field in process_fields:
            if field in data and data[field]:
                return data[field].split("\\")[-1] if "\\" in data[field] else data[field]
        return None
    
    def _extract_ip(self, raw_log: str) -> Optional[str]:
        """Extract IP address from raw log."""
        match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", raw_log)
        return match.group(1) if match else None
    
    def _extract_username(self, raw_log: str) -> Optional[str]:
        """Extract username from raw log."""
        patterns = [
            r"User\s*[=:]\s*(\w+)",
            r"Account\s*[=:]\s*(\w+)",
            r"TargetUserName[=:](\w+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, raw_log, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
