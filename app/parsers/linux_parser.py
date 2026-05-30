"""
Linux log parser for auth, syslog, SSH, and sudo logs.
"""
import re
from datetime import datetime
from typing import Dict, Any, Optional


class LinuxLogParser:
    """Parser for Linux system logs."""
    
    # Regex patterns for different Linux log formats
    PATTERNS = {
        "auth": {
            "timestamp": r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
            "hostname": r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)",
            "service": r"\s(\w+)\[(\d+)\]:",
            "user": r"user[\s=]+(\w+)",
            "ip": r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
            "failed_password": r"Failed password for\s+(invalid user\s+)?(\w+)",
            "accepted_password": r"Accepted password for\s+(\w+)",
            "sudo_command": r"COMMAND=(.+)$",
            "authentication_failure": r"authentication failure",
        }
    }
    
    def parse(self, raw_log: str, source_type: str = "linux_auth") -> Dict[str, Any]:
        """Parse a Linux log entry."""
        result = {
            "timestamp": self._parse_timestamp(raw_log),
            "source_ip": self._extract_ip(raw_log),
            "username": self._extract_username(raw_log),
            "hostname": self._extract_hostname(raw_log),
            "process_name": self._extract_process(raw_log),
            "event_type": self._classify_event(raw_log, source_type),
            "severity": self._determine_severity(raw_log),
            "operating_system": "linux",
            "raw_log": raw_log,
            "parsed_data": {},
        }
        
        # Extract additional data based on event type
        if "Failed password" in raw_log:
            match = re.search(r"Failed password for\s+(invalid user\s+)?(\w+).*from\s+(\S+)\s+port\s+(\d+)", raw_log)
            if match:
                result["parsed_data"]["auth_status"] = "failed"
                result["parsed_data"]["target_user"] = match.group(2)
                result["parsed_data"]["source_ip"] = match.group(3)
                result["parsed_data"]["port"] = int(match.group(4))
                result["source_ip"] = match.group(3)
                result["username"] = match.group(2)
                result["event_type"] = "failed_login"
        
        elif "Accepted password" in raw_log or "Accepted publickey" in raw_log:
            match = re.search(r"Accepted\s+\w+\s+for\s+(\w+).*from\s+(\S+)\s+port\s+(\d+)", raw_log)
            if match:
                result["parsed_data"]["auth_status"] = "success"
                result["parsed_data"]["target_user"] = match.group(1)
                result["parsed_data"]["source_ip"] = match.group(2)
                result["parsed_data"]["port"] = int(match.group(3))
                result["source_ip"] = match.group(2)
                result["username"] = match.group(1)
                result["event_type"] = "successful_login"
        
        elif "sudo:" in raw_log:
            match = re.search(r"sudo:\s+(\w+)\s+.*COMMAND=(.+)$", raw_log)
            if match:
                result["parsed_data"]["sudo_user"] = match.group(1)
                result["parsed_data"]["command"] = match.group(2)
                result["username"] = match.group(1)
                result["event_type"] = "sudo_command"
                result["process_name"] = "sudo"
        
        elif "authentication failure" in raw_log:
            match = re.search(r"authentication failure.*user=(\w+)", raw_log)
            if match:
                result["parsed_data"]["auth_status"] = "failure"
                result["parsed_data"]["target_user"] = match.group(1)
                result["username"] = match.group(1)
                result["event_type"] = "auth_failure"
        
        elif "session opened" in raw_log or "session closed" in raw_log:
            match = re.search(r"session\s+(opened|closed)\s+for user\s+(\w+)", raw_log)
            if match:
                result["parsed_data"]["session_action"] = match.group(1)
                result["parsed_data"]["user"] = match.group(2)
                result["username"] = match.group(2)
                result["event_type"] = f"session_{match.group(1)}"
        
        elif "Invalid user" in raw_log:
            match = re.search(r"Invalid user\s+(\w+).*from\s+(\S+)", raw_log)
            if match:
                result["parsed_data"]["invalid_user"] = match.group(1)
                result["parsed_data"]["source_ip"] = match.group(2)
                result["username"] = match.group(1)
                result["source_ip"] = match.group(2)
                result["event_type"] = "invalid_user"
                result["severity"] = "medium"
        
        elif "Connection closed" in raw_log:
            match = re.search(r"Connection closed by\s+(\S+)", raw_log)
            if match:
                result["parsed_data"]["source_ip"] = match.group(1)
                result["source_ip"] = match.group(1)
                result["event_type"] = "connection_closed"
        
        elif "reverse mapping checking" in raw_log:
            result["event_type"] = "dns_spoofing_check"
            result["severity"] = "low"
        
        elif "POSSIBLE BREAK-IN ATTEMPT" in raw_log:
            result["event_type"] = "possible_breakin"
            result["severity"] = "critical"
        
        return result
    
    def _parse_timestamp(self, raw_log: str) -> Optional[datetime]:
        """Extract timestamp from log."""
        # Try standard syslog format: "Dec 10 08:15:30"
        match = re.match(r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", raw_log)
        if match:
            ts_str = match.group(1)
            current_year = datetime.now().year
            try:
                return datetime.strptime(f"{current_year} {ts_str}", "%Y %b %d %H:%M:%S")
            except ValueError:
                pass
        
        # Try ISO format
        match = re.search(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", raw_log)
        if match:
            try:
                return datetime.fromisoformat(match.group(1).replace(" ", "T"))
            except ValueError:
                pass
        
        return datetime.utcnow()
    
    def _extract_ip(self, raw_log: str) -> Optional[str]:
        """Extract IP address from log."""
        match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", raw_log)
        return match.group(1) if match else None
    
    def _extract_username(self, raw_log: str) -> Optional[str]:
        """Extract username from log."""
        # Try various patterns
        patterns = [
            r"user\s+(\w+)",
            r"for\s+(\w+)",
            r"USER=(\w+)",
            r"user=([^;\s]+)",
        ]
        for pattern in patterns:
            match = re.search(pattern, raw_log)
            if match:
                user = match.group(1).strip()
                if user not in ["unknown", "<", "invalid"]:
                    return user
        return None
    
    def _extract_hostname(self, raw_log: str) -> Optional[str]:
        """Extract hostname from log."""
        match = re.match(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)", raw_log)
        return match.group(1) if match else None
    
    def _extract_process(self, raw_log: str) -> Optional[str]:
        """Extract process name from log."""
        match = re.search(r"\s(\w+)\[\d+\]:", raw_log)
        return match.group(1) if match else None
    
    def _classify_event(self, raw_log: str, source_type: str) -> str:
        """Classify the event type."""
        if "Failed password" in raw_log:
            return "failed_login"
        elif "Accepted" in raw_log and "password" in raw_log:
            return "successful_login"
        elif "sudo:" in raw_log:
            return "sudo_command"
        elif "authentication failure" in raw_log:
            return "auth_failure"
        elif "session" in raw_log:
            return "session_event"
        elif "Invalid user" in raw_log:
            return "invalid_user"
        elif "Connection" in raw_log:
            return "connection_event"
        elif "POSSIBLE BREAK-IN ATTEMPT" in raw_log:
            return "possible_breakin"
        else:
            return source_type
    
    def _determine_severity(self, raw_log: str) -> str:
        """Determine severity based on log content."""
        critical_patterns = [
            "POSSIBLE BREAK-IN ATTEMPT",
            "emergency",
            "alert",
        ]
        high_patterns = [
            "Failed password",
            "authentication failure",
            "Invalid user",
            "error",
            "critical",
        ]
        medium_patterns = [
            "warning",
            "sudo:",
            "session opened",
        ]
        
        for pattern in critical_patterns:
            if pattern.lower() in raw_log.lower():
                return "critical"
        for pattern in high_patterns:
            if pattern.lower() in raw_log.lower():
                return "high"
        for pattern in medium_patterns:
            if pattern.lower() in raw_log.lower():
                return "medium"
        
        return "low"
