"""
Generic log parser for JSON logs and unknown formats.
"""

import re
import json
from datetime import datetime
from typing import Dict, Any, Optional


class GenericLogParser:
    """Generic parser for JSON logs and unknown formats."""

    def parse(self, raw_log: str, source_type: str = "generic") -> Dict[str, Any]:
        """Parse a generic log entry."""

        # SAFETY FIXES
        if raw_log is None:
            raw_log = ""

        if not isinstance(raw_log, str):
            raw_log = str(raw_log)

        raw_log = raw_log.strip()

        # Empty log fallback
        if not raw_log:
            return {
                "timestamp": datetime.utcnow(),
                "source_ip": None,
                "event_type": source_type,
                "severity": "low",
                "raw_log": "",
                "parsed_data": {},
            }

        # Try JSON format
        if raw_log.startswith("{") or raw_log.startswith("["):
            try:
                return self._parse_json(raw_log, source_type)
            except (json.JSONDecodeError, ValueError, TypeError):
                pass

        # Try syslog-like format
        if re.match(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", raw_log):
            return self._parse_syslog(raw_log, source_type)

        # Try timestamp-prefixed format
        ts_match = re.match(
            r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})",
            raw_log
        )

        if ts_match:
            return self._parse_timestamped(raw_log, source_type)

        # Ultimate fallback
        return self._parse_fallback(raw_log, source_type)

    def _parse_json(self, raw_log: str, source_type: str) -> Dict[str, Any]:
        """Parse JSON log."""

        data = json.loads(raw_log)

        # Convert lists to dict wrapper
        if isinstance(data, list):
            data = {"logs": data}

        # Flatten nested JSON
        flat_data = self._flatten_json(data)

        # Extract common fields
        timestamp = self._extract_timestamp(flat_data)

        source_ip = self._extract_field(
            flat_data,
            ["source_ip", "client_ip", "remote_addr", "ip", "src_ip", "host"]
        )

        username = self._extract_field(
            flat_data,
            ["username", "user", "user_name", "user_id", "actor"]
        )

        hostname = self._extract_field(
            flat_data,
            ["hostname", "host", "server", "machine", "computer"]
        )

        event_type = self._extract_field(
            flat_data,
            ["event_type", "event", "action", "type", "event_name", "operation"]
        )

        severity = self._extract_field(
            flat_data,
            ["severity", "level", "log_level", "priority", "importance"]
        )

        process_name = self._extract_field(
            flat_data,
            ["process", "process_name", "app", "application", "program"]
        )

        event_id = self._extract_field(
            flat_data,
            ["event_id", "eventId", "id", "code"]
        )

        status_code = self._extract_int_field(
            flat_data,
            ["status_code", "status", "response_code", "http_status"]
        )

        request_method = self._extract_field(
            flat_data,
            ["method", "http_method", "request_method", "verb"]
        )

        endpoint = self._extract_field(
            flat_data,
            ["endpoint", "path", "url", "uri", "request_uri", "route"]
        )

        severity = self._normalize_severity(severity)

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "username": username,
            "hostname": hostname,
            "process_name": process_name,
            "event_id": event_id,
            "request_method": request_method,
            "endpoint": endpoint,
            "status_code": status_code,
            "event_type": event_type or source_type,
            "severity": severity,
            "operating_system": self._extract_field(
                flat_data,
                ["os", "platform", "operating_system"]
            ),
            "raw_log": raw_log,
            "parsed_data": flat_data,
        }

    def _parse_syslog(self, raw_log: str, source_type: str) -> Dict[str, Any]:
        """Parse syslog-like format."""

        ts_match = re.match(
            r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
            raw_log
        )

        timestamp = (
            self._parse_syslog_timestamp(ts_match.group(1))
            if ts_match else datetime.utcnow()
        )

        host_match = re.match(
            r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)",
            raw_log
        )

        hostname = host_match.group(1) if host_match else None

        proc_match = re.search(r"\s(\w+)\[\d+\]:", raw_log)
        process_name = proc_match.group(1) if proc_match else None

        ip_match = re.search(
            r"(\d{1,3}(?:\.\d{1,3}){3})",
            raw_log
        )

        source_ip = ip_match.group(1) if ip_match else None

        return {
            "timestamp": timestamp,
            "source_ip": source_ip,
            "hostname": hostname,
            "process_name": process_name,
            "event_type": source_type,
            "severity": self._infer_severity(raw_log),
            "raw_log": raw_log,
            "parsed_data": {},
        }

    def _parse_timestamped(self, raw_log: str, source_type: str) -> Dict[str, Any]:
        """Parse timestamp-prefixed log."""

        ts_match = re.match(
            r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?)",
            raw_log
        )

        timestamp = (
            datetime.fromisoformat(
                ts_match.group(1).replace(" ", "T")
            )
            if ts_match else datetime.utcnow()
        )

        ip_match = re.search(
            r"(\d{1,3}(?:\.\d{1,3}){3})",
            raw_log
        )

        return {
            "timestamp": timestamp,
            "source_ip": ip_match.group(1) if ip_match else None,
            "event_type": source_type,
            "severity": self._infer_severity(raw_log),
            "raw_log": raw_log,
            "parsed_data": {},
        }

    def _parse_fallback(self, raw_log: str, source_type: str) -> Dict[str, Any]:
        """Ultimate fallback parser."""

        timestamp = datetime.utcnow()

        ip_match = re.search(
            r"(\d{1,3}(?:\.\d{1,3}){3})",
            raw_log
        )

        return {
            "timestamp": timestamp,
            "source_ip": ip_match.group(1) if ip_match else None,
            "event_type": source_type,
            "severity": self._infer_severity(raw_log),
            "raw_log": raw_log,
            "parsed_data": {"unparsed": True},
        }

    def _flatten_json(self, obj: Any, prefix: str = "") -> Dict[str, Any]:
        """Flatten nested JSON."""

        result = {}

        if isinstance(obj, dict):
            for key, value in obj.items():
                new_key = f"{prefix}.{key}" if prefix else key

                if isinstance(value, dict):
                    result.update(self._flatten_json(value, new_key))

                elif isinstance(value, list):
                    result[new_key] = str(value)

                else:
                    result[new_key] = value

        return result

    def _extract_field(self, data: Dict, keys: list) -> Optional[str]:
        """Extract a field from flattened data."""

        for key in keys:
            if key in data and data[key] is not None:
                value = str(data[key])

                if value and value.lower() not in ["null", "none", "", "-"]:
                    return value

        return None

    def _extract_int_field(self, data: Dict, keys: list) -> Optional[int]:
        """Extract integer field."""

        for key in keys:
            if key in data and data[key] is not None:
                try:
                    return int(data[key])
                except (ValueError, TypeError):
                    continue

        return None

    def _extract_timestamp(self, data: Dict) -> datetime:
        """Extract timestamp from data."""

        ts_keys = [
            "timestamp",
            "time",
            "datetime",
            "date",
            "@timestamp",
            "created_at",
            "event_time",
        ]

        for key in ts_keys:
            if key in data and data[key]:
                try:
                    ts_str = str(data[key])

                    return datetime.fromisoformat(
                        ts_str.replace("Z", "+00:00").replace(" ", "T")
                    )

                except Exception:
                    continue

        return datetime.utcnow()

    def _parse_syslog_timestamp(self, ts_str: str) -> datetime:
        """Parse syslog timestamp."""

        current_year = datetime.now().year

        try:
            return datetime.strptime(
                f"{current_year} {ts_str}",
                "%Y %b %d %H:%M:%S"
            )

        except Exception:
            return datetime.utcnow()

    def _normalize_severity(self, severity: Optional[str]) -> str:
        """Normalize severity."""

        if not severity:
            return "low"

        sev = severity.lower().strip()

        critical = ["critical", "fatal", "emergency", "alert"]
        high = ["high", "error", "failed", "warning"]
        medium = ["medium", "notice", "info"]

        if sev in critical:
            return "critical"

        elif sev in high:
            return "high"

        elif sev in medium:
            return "medium"

        return "low"

    def _infer_severity(self, raw_log: str) -> str:
        """Infer severity from log content."""

        log_lower = raw_log.lower()

        critical = ["critical", "fatal", "emergency", "malware"]
        high = ["error", "failed", "attack", "breach", "intrusion"]
        medium = ["warning", "suspicious", "anomaly"]

        for term in critical:
            if term in log_lower:
                return "critical"

        for term in high:
            if term in log_lower:
                return "high"

        for term in medium:
            if term in log_lower:
                return "medium"

        return "low"