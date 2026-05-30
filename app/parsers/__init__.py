"""
Log parser engine for the CyberAI SOC Platform.
Supports Linux, Windows, and Web server logs.
"""
from app.parsers.linux_parser import LinuxLogParser
from app.parsers.windows_parser import WindowsLogParser
from app.parsers.web_parser import WebLogParser
from app.parsers.generic_parser import GenericLogParser

__all__ = ["LinuxLogParser", "WindowsLogParser", "WebLogParser", "GenericLogParser"]

# Log type detection patterns
LOG_TYPE_PATTERNS = {
    "linux_auth": [r"sshd\[", r"sudo:", r"authentication failure", r"Accepted password", r"Failed password"],
    "linux_syslog": [r"systemd\[", r"kernel:\[", r"cron\[", r"rsyslogd"],
    "linux_ssh": [r"sshd\[", r"ssh2", r"Accepted publickey", r"Connection from"],
    "linux_sudo": [r"sudo:", r"COMMAND=", r"USER=root"],
    "windows_security": [r"EventID=4624", r"EventID=4625", r"EventID=4634", r"EventID=4648"],
    "windows_powershell": [r"EventID=4103", r"EventID=4104", r"HostApplication="],
    "windows_sysmon": [r"EventID=1\b", r"Sysmon", r"Image:"],
    "windows_rdp": [r"TerminalServices", r"RDP", r"EventID=1149"],
    "apache_access": [r'\s(200|301|302|400|401|403|404|500|502|503)\s\d+\s"', r'"(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s'],
    "apache_error": [r"\[error\]", r"\[warn\]", r"Apache", r"mod_"],
    "nginx": [r'\s(200|301|302|400|401|403|404|499|500|502|503|504)\s\d+\s"', r'"(GET|POST)\s', r'nginx'],
    "json_log": [r'^\s*\{.*\}\s*$'],
}


def detect_log_type(raw_log: str) -> str:
    """Detect the type of log based on content patterns."""
    import re
    
    scores = {}
    for log_type, patterns in LOG_TYPE_PATTERNS.items():
        score = 0
        for pattern in patterns:
            if re.search(pattern, raw_log, re.IGNORECASE):
                score += 1
        if score > 0:
            scores[log_type] = score
    
    if not scores:
        # Try JSON detection
        try:
            import json
            json.loads(raw_log)
            return "json_log"
        except (json.JSONDecodeError, ValueError):
            pass
        return "generic"
    
    return max(scores, key=scores.get)


def get_parser(source_type: str):
    """Get the appropriate parser for a log type."""
    parsers = {
        "linux_auth": LinuxLogParser(),
        "linux_syslog": LinuxLogParser(),
        "linux_ssh": LinuxLogParser(),
        "linux_sudo": LinuxLogParser(),
        "windows_security": WindowsLogParser(),
        "windows_system": WindowsLogParser(),
        "windows_powershell": WindowsLogParser(),
        "windows_sysmon": WindowsLogParser(),
        "windows_defender": WindowsLogParser(),
        "windows_rdp": WindowsLogParser(),
        "apache_access": WebLogParser(),
        "apache_error": WebLogParser(),
        "nginx": WebLogParser(),
        "json_log": GenericLogParser(),
        "generic": GenericLogParser(),
    }
    return parsers.get(source_type, GenericLogParser())


def parse_log(raw_log: str, source_type: str = None) -> dict:
    """Parse a single log entry."""
    if not source_type or source_type == "auto":
        source_type = detect_log_type(raw_log)
    
    parser = get_parser(source_type)
    return parser.parse(raw_log, source_type)
