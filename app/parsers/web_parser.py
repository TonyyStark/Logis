"""
Web server log parser for Apache and Nginx logs.
"""
import re
import json
from datetime import datetime
from typing import Dict, Any, Optional
from urllib.parse import unquote


class WebLogParser:
    """Parser for Apache and Nginx access/error logs."""
    
    # Common log format regex
    COMBINED_LOG_PATTERN = re.compile(
        r'^(?P<ip>\S+)\s+'           # IP address
        r'\S+\s+'                      # ident
        r'\S+\s+'                      # auth user
        r'\[(?P<timestamp>[^\]]+)\]\s+'  # timestamp
        r'"(?P<method>\S+)\s+'         # HTTP method
        r'(?P<endpoint>\S+)\s+'        # Endpoint
        r'(?P<protocol>\S+)"\s+'      # Protocol
        r'(?P<status>\d{3})\s+'       # Status code
        r'(?P<bytes>\d+|-)\s+'        # Bytes sent
        r'"(?P<referer>[^"]*)"\s+'    # Referer
        r'"(?P<user_agent>[^"]*)"'     # User agent
    )
    
    # Common web attack patterns
    ATTACK_PATTERNS = {
        "sql_injection": [
            r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
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
            r"SLEEP\s*\(",
            r"BENCHMARK\s*\(",
        ],
        "xss": [
            r"<script[^>]*>[\s\S]*?</script>",
            r"javascript:",
            r"on\w+\s*=\s*['\"][^'\"]*[\"']",
            r"<iframe",
            r"<object",
            r"<embed",
            r"alert\s*\(",
            r"document\.cookie",
            r"document\.location",
            r"window\.location",
        ],
        "path_traversal": [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e%2f",
            r"%252e%252e%252f",
            r"\.%00/",
            r"\.\.\.\.",
            r"/etc/passwd",
            r"/etc/shadow",
            r"win\.ini",
            r"boot\.ini",
            r"../../",
            r"..\\..\\",
        ],
        "command_injection": [
            r";\s*\w+",
            r"\|\s*\w+",
            r"`\s*\w+",
            r"\$\(.*\)",
            r"\$\{.*\}",
            r"<\(.*\)",
            r">\(.*\)",
        ],
        "lfi": [
            r"file://",
            r"php://",
            r"data://",
            r"expect://",
            r"input://",
            r"filter://",
        ],
        "scanning": [
            r"\.env$",
            r"\.git/",
            r"\.svn/",
            r"\.hg/",
            r"\.DS_Store",
            r"phpmyadmin",
            r"wp-admin",
            r"wp-login",
            r"xmlrpc\.php",
            r"admin\.php",
            r"config\.xml",
            r"robots\.txt",
            r"sitemap\.xml",
            r"\?.*=.*SELECT",
            r"\?.*=.*UNION",
        ],
    }
    
    def parse(self, raw_log: str, source_type: str = "apache_access") -> Dict[str, Any]:
        """Parse a web server log entry."""
        # Try JSON format first
        if raw_log.strip().startswith("{"):
            try:
                return self._parse_json_log(raw_log, source_type)
            except (json.JSONDecodeError, KeyError):
                pass
        
        # Try combined log format
        match = self.COMBINED_LOG_PATTERN.match(raw_log)
        if match:
            return self._parse_combined_log(match, raw_log, source_type)
        
        # Try error log format
        if "[error]" in raw_log or "[warn]" in raw_log or "[notice]" in raw_log:
            return self._parse_error_log(raw_log, source_type)
        
        # Fallback generic parse
        return self._parse_generic(raw_log, source_type)
    
    def _parse_combined_log(self, match: re.Match, raw_log: str, source_type: str) -> Dict[str, Any]:
        """Parse combined log format entry."""
        data = match.groupdict()
        
        endpoint = unquote(data.get("endpoint", ""))
        user_agent = data.get("user_agent", "")
        status_code = int(data.get("status", 0))
        
        # Detect attacks
        attacks = self._detect_attacks(endpoint + " " + user_agent)
        
        severity = self._determine_severity(status_code, attacks)
        event_type = self._determine_event_type(status_code, attacks)
        
        return {
            "timestamp": self._parse_timestamp(data.get("timestamp", "")),
            "source_ip": data.get("ip"),
            "destination_ip": None,
            "username": None,
            "hostname": None,
            "process_name": None,
            "event_id": str(status_code) if status_code else None,
            "request_method": data.get("method"),
            "endpoint": endpoint,
            "status_code": status_code if status_code else None,
            "event_type": event_type,
            "severity": severity,
            "operating_system": None,
            "raw_log": raw_log,
            "parsed_data": {
                **data,
                "attacks_detected": attacks,
                "referer": data.get("referer", ""),
                "user_agent": user_agent,
                "bytes_sent": data.get("bytes", "-"),
            },
        }
    
    def _parse_error_log(self, raw_log: str, source_type: str) -> Dict[str, Any]:
        """Parse Apache/Nginx error log."""
        # Error log format: [timestamp] [severity] [client IP] message
        pattern = re.compile(
            r'\[(?P<timestamp>[^\]]+)\]\s+'
            r'\[(?P<severity>\w+)\]\s+'
            r'(?:\[pid\s+\d+:\w+\]\s+)?'
            r'(?:\[client\s+(?P<ip>\S+)\]\s+)?'
            r'(?P<message>.+)'
        )
        
        match = pattern.match(raw_log)
        if match:
            data = match.groupdict()
            return {
                "timestamp": self._parse_timestamp(data.get("timestamp", "")),
                "source_ip": data.get("ip"),
                "event_type": "web_error",
                "severity": data.get("severity", "error").lower(),
                "operating_system": None,
                "raw_log": raw_log,
                "parsed_data": {
                    "error_message": data.get("message", ""),
                    "error_severity": data.get("severity", ""),
                },
            }
        
        return self._parse_generic(raw_log, source_type)
    
    def _parse_json_log(self, raw_log: str, source_type: str) -> Dict[str, Any]:
        """Parse JSON-formatted web log."""
        data = json.loads(raw_log)
        
        endpoint = data.get("endpoint", data.get("path", data.get("request_uri", "")))
        user_agent = data.get("user_agent", data.get("http_user_agent", ""))
        
        attacks = self._detect_attacks(endpoint + " " + user_agent)
        status_code = data.get("status_code", data.get("status", 0))
        
        return {
            "timestamp": self._parse_timestamp(data.get("timestamp", data.get("time", ""))),
            "source_ip": data.get("source_ip", data.get("client_ip", data.get("remote_addr", None))),
            "request_method": data.get("method", data.get("request_method", None)),
            "endpoint": endpoint,
            "status_code": int(status_code) if status_code else None,
            "event_type": self._determine_event_type(status_code, attacks),
            "severity": self._determine_severity(status_code, attacks),
            "operating_system": None,
            "raw_log": raw_log,
            "parsed_data": {
                **data,
                "attacks_detected": attacks,
            },
        }
    
    def _parse_generic(self, raw_log: str, source_type: str) -> Dict[str, Any]:
        """Generic fallback parser."""
        # Extract IP
        ip_match = re.match(r"^(\S+)", raw_log)
        source_ip = ip_match.group(1) if ip_match else None
        
        # Extract timestamp
        ts_match = re.search(r"\[(?P<ts>[^\]]+)\]", raw_log)
        timestamp = self._parse_timestamp(ts_match.group("ts")) if ts_match else datetime.utcnow()
        
        # Try to find HTTP method and endpoint
        http_match = re.search(r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+(\S+)', raw_log)
        method = http_match.group(1) if http_match else None
        endpoint = http_match.group(2) if http_match else None
        
        # Try to find status code
        status_match = re.search(r'\s(\d{3})\s', raw_log)
        status_code = int(status_match.group(1)) if status_match else None
        
        attacks = self._detect_attacks(endpoint + " " + raw_log if endpoint else raw_log)
        
        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "request_method": method,
            "endpoint": endpoint,
            "status_code": status_code,
            "event_type": self._determine_event_type(status_code, attacks),
            "severity": self._determine_severity(status_code, attacks),
            "operating_system": None,
            "raw_log": raw_log,
            "parsed_data": {"attacks_detected": attacks},
        }
    
    def _detect_attacks(self, content: str) -> Dict[str, list]:
        """Detect web attacks in content."""
        if not content:
            return {}
        
        detected = {}
        decoded = unquote(content)
        
        for attack_type, patterns in self.ATTACK_PATTERNS.items():
            matches = []
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE) or re.search(pattern, decoded, re.IGNORECASE):
                    matches.append(pattern)
            if matches:
                detected[attack_type] = True
        
        return detected
    
    def _parse_timestamp(self, ts_str: str) -> datetime:
        """Parse web log timestamp."""
        if not ts_str:
            return datetime.utcnow()
        
        formats = [
            "%d/%b/%Y:%H:%M:%S %z",     # Apache: 10/Oct/2023:08:15:30 +0000
            "%d/%b/%Y:%H:%M:%S",         # Apache without timezone
            "%Y-%m-%dT%H:%M:%S.%fZ",     # ISO
            "%Y-%m-%dT%H:%M:%SZ",        # ISO without ms
            "%Y-%m-%d %H:%M:%S",         # Standard
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(ts_str, fmt)
            except ValueError:
                continue
        
        return datetime.utcnow()
    
    def _determine_severity(self, status_code, attacks: Dict) -> str:
        """Determine severity based on status code and attacks."""
        if attacks:
            if "sql_injection" in attacks or "command_injection" in attacks or "xss" in attacks:
                return "critical"
            return "high"
        
        if status_code:
            if status_code >= 500:
                return "high"
            elif status_code == 404:
                return "low"
            elif status_code == 403:
                return "medium"
            elif status_code == 401:
                return "medium"
        
        return "info"
    
    def _determine_event_type(self, status_code, attacks: Dict) -> str:
        """Determine event type."""
        if attacks:
            attack_types = list(attacks.keys())
            return f"web_attack_{attack_types[0]}"
        
        if status_code:
            if status_code >= 500:
                return "server_error"
            elif status_code == 404:
                return "not_found"
            elif status_code == 403:
                return "forbidden"
            elif status_code == 401:
                return "unauthorized"
            elif status_code >= 300:
                return "redirect"
            elif status_code == 200:
                return "successful_request"
        
        return "web_request"
