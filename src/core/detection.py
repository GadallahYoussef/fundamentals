"""
Detection Engine Module
=======================
Detects security incidents from parsed log entries.
Implements detection rules for:
- Brute force attacks
- Suspicious login behavior
- Execution of unknown processes
- IOC (Indicator of Compromise) matches
"""

import json
import re
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Set, Callable
from pathlib import Path
from collections import defaultdict
from enum import Enum
import logging
import ipaddress

from .log_parser import ParsedLogEntry, LogType

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Severity(Enum):
    """Severity levels for detected incidents."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionType(Enum):
    """Types of detections."""
    BRUTE_FORCE = "brute_force"
    SUSPICIOUS_LOGIN = "suspicious_login"
    UNKNOWN_PROCESS = "unknown_process"
    IOC_MATCH = "ioc_match"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    ANOMALOUS_BEHAVIOR = "anomalous_behavior"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"


@dataclass
class Detection:
    """
    Represents a detected security incident.
    
    Attributes:
        detection_type: Type of detection
        alert: Human-readable alert description
        severity: Severity level of the detection
        iocs: List of associated IOCs
        log_entries: Related log entries
        timestamp: When the detection was made
        source_ips: Source IP addresses involved
        users: Users involved
        metadata: Additional detection-specific data
    """
    detection_type: DetectionType
    alert: str
    severity: Severity
    iocs: List[str] = field(default_factory=list)
    log_entries: List[ParsedLogEntry] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)
    source_ips: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_log_snippet(self, max_entries: int = 5) -> str:
        """
        Get a snippet of the relevant log entries.
        
        Args:
            max_entries: Maximum number of log entries to include
            
        Returns:
            Formatted string with log snippets
        """
        snippets = []
        for entry in self.log_entries[:max_entries]:
            snippets.append(f"[{entry.timestamp}] {entry.raw_log[:200]}")
        
        if len(self.log_entries) > max_entries:
            snippets.append(f"... and {len(self.log_entries) - max_entries} more entries")
        
        return "\n".join(snippets)
    
    def get_ioc_string(self) -> str:
        """Get IOCs as a formatted string."""
        return ", ".join(self.iocs) if self.iocs else "None"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert detection to dictionary."""
        return {
            'detection_type': self.detection_type.value,
            'alert': self.alert,
            'severity': self.severity.value,
            'iocs': self.iocs,
            'timestamp': self.timestamp.isoformat(),
            'source_ips': self.source_ips,
            'users': self.users,
            'log_snippet': self.get_log_snippet(),
            'metadata': self.metadata,
        }


@dataclass
class IOCDatabase:
    """
    Database of Indicators of Compromise (IOCs).
    
    Supports various IOC types:
    - IP addresses (single and CIDR ranges)
    - Domains
    - File hashes (MD5, SHA1, SHA256)
    - URLs
    - Email addresses
    - Process names
    - Usernames
    """
    
    ip_addresses: Set[str] = field(default_factory=set)
    ip_ranges: List[ipaddress.IPv4Network] = field(default_factory=list)
    domains: Set[str] = field(default_factory=set)
    hashes_md5: Set[str] = field(default_factory=set)
    hashes_sha1: Set[str] = field(default_factory=set)
    hashes_sha256: Set[str] = field(default_factory=set)
    urls: Set[str] = field(default_factory=set)
    emails: Set[str] = field(default_factory=set)
    process_names: Set[str] = field(default_factory=set)
    usernames: Set[str] = field(default_factory=set)
    custom_patterns: List[re.Pattern] = field(default_factory=list)
    
    @classmethod
    def load_from_file(cls, file_path: Path) -> 'IOCDatabase':
        """
        Load IOCs from a JSON file.
        
        Expected JSON format:
        {
            "ip_addresses": ["1.2.3.4", "5.6.7.8"],
            "ip_ranges": ["10.0.0.0/8"],
            "domains": ["malware.com"],
            "hashes": {
                "md5": ["abc123..."],
                "sha1": ["def456..."],
                "sha256": ["ghi789..."]
            },
            "urls": ["http://evil.com/malware"],
            "emails": ["attacker@evil.com"],
            "process_names": ["mimikatz.exe"],
            "usernames": ["admin", "root"],
            "patterns": [".*malware.*"]
        }
        
        Args:
            file_path: Path to the IOC JSON file
            
        Returns:
            IOCDatabase instance populated with IOCs
        """
        db = cls()
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Load IP addresses
            for ip in data.get('ip_addresses', []):
                db.ip_addresses.add(ip.lower().strip())
            
            # Load IP ranges
            for ip_range in data.get('ip_ranges', []):
                try:
                    db.ip_ranges.append(ipaddress.IPv4Network(ip_range, strict=False))
                except ValueError as e:
                    logger.warning(f"Invalid IP range '{ip_range}': {e}")
            
            # Load domains
            for domain in data.get('domains', []):
                db.domains.add(domain.lower().strip())
            
            # Load hashes
            hashes = data.get('hashes', {})
            for h in hashes.get('md5', []):
                db.hashes_md5.add(h.lower().strip())
            for h in hashes.get('sha1', []):
                db.hashes_sha1.add(h.lower().strip())
            for h in hashes.get('sha256', []):
                db.hashes_sha256.add(h.lower().strip())
            
            # Load URLs
            for url in data.get('urls', []):
                db.urls.add(url.lower().strip())
            
            # Load emails
            for email in data.get('emails', []):
                db.emails.add(email.lower().strip())
            
            # Load process names
            for proc in data.get('process_names', []):
                db.process_names.add(proc.lower().strip())
            
            # Load usernames
            for user in data.get('usernames', []):
                db.usernames.add(user.lower().strip())
            
            # Load custom patterns
            for pattern in data.get('patterns', []):
                try:
                    db.custom_patterns.append(re.compile(pattern, re.IGNORECASE))
                except re.error as e:
                    logger.warning(f"Invalid regex pattern '{pattern}': {e}")
            
            logger.info(f"Loaded IOC database from {file_path}: "
                       f"{len(db.ip_addresses)} IPs, {len(db.domains)} domains, "
                       f"{len(db.process_names)} process names")
            
        except FileNotFoundError:
            logger.warning(f"IOC file not found: {file_path}")
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in IOC file {file_path}: {e}")
        except Exception as e:
            logger.error(f"Error loading IOC file {file_path}: {e}")
        
        return db
    
    def check_ip(self, ip: str) -> bool:
        """Check if an IP address matches any IOC."""
        if not ip:
            return False
        
        ip_lower = ip.lower().strip()
        
        # Direct match
        if ip_lower in self.ip_addresses:
            return True
        
        # Range match
        try:
            ip_obj = ipaddress.IPv4Address(ip)
            for ip_range in self.ip_ranges:
                if ip_obj in ip_range:
                    return True
        except ValueError:
            pass
        
        return False
    
    def check_domain(self, domain: str) -> bool:
        """Check if a domain matches any IOC."""
        if not domain:
            return False
        return domain.lower().strip() in self.domains
    
    def check_hash(self, hash_value: str) -> bool:
        """Check if a hash matches any IOC."""
        if not hash_value:
            return False
        
        hash_lower = hash_value.lower().strip()
        
        # Determine hash type by length
        if len(hash_lower) == 32:  # MD5
            return hash_lower in self.hashes_md5
        elif len(hash_lower) == 40:  # SHA1
            return hash_lower in self.hashes_sha1
        elif len(hash_lower) == 64:  # SHA256
            return hash_lower in self.hashes_sha256
        
        # Check all
        return (hash_lower in self.hashes_md5 or 
                hash_lower in self.hashes_sha1 or 
                hash_lower in self.hashes_sha256)
    
    def check_process(self, process_name: str) -> bool:
        """Check if a process name matches any IOC."""
        if not process_name:
            return False
        return process_name.lower().strip() in self.process_names
    
    def check_username(self, username: str) -> bool:
        """Check if a username matches any IOC."""
        if not username:
            return False
        return username.lower().strip() in self.usernames
    
    def check_text(self, text: str) -> List[str]:
        """
        Check text against all IOCs and patterns.
        
        Args:
            text: Text to check
            
        Returns:
            List of matched IOCs
        """
        if not text:
            return []
        
        matches = []
        text_lower = text.lower()
        
        # Check IPs in text
        ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        for ip_match in ip_pattern.findall(text):
            if self.check_ip(ip_match):
                matches.append(f"IP: {ip_match}")
        
        # Check domains in text
        for domain in self.domains:
            if domain in text_lower:
                matches.append(f"Domain: {domain}")
        
        # Check process names in text
        for proc in self.process_names:
            if proc in text_lower:
                matches.append(f"Process: {proc}")
        
        # Check custom patterns
        for pattern in self.custom_patterns:
            if pattern.search(text):
                matches.append(f"Pattern: {pattern.pattern}")
        
        return matches


class BruteForceDetector:
    """
    Detects brute force attacks based on failed login patterns.
    
    Configurable thresholds:
    - Failed attempts threshold
    - Time window for counting failures
    - Different thresholds for SSH vs other services
    """
    
    def __init__(
        self,
        failed_threshold: int = 5,
        time_window_minutes: int = 10,
        distributed_threshold: int = 3,
        distributed_sources: int = 3
    ):
        """
        Initialize the brute force detector.
        
        Args:
            failed_threshold: Number of failures to trigger alert
            time_window_minutes: Time window for counting failures
            distributed_threshold: Failures per IP for distributed attack
            distributed_sources: Number of IPs for distributed attack
        """
        self.failed_threshold = failed_threshold
        self.time_window = timedelta(minutes=time_window_minutes)
        self.distributed_threshold = distributed_threshold
        self.distributed_sources = distributed_sources
    
    def detect(self, log_entries: List[ParsedLogEntry]) -> List[Detection]:
        """
        Detect brute force attacks in log entries.
        
        Args:
            log_entries: List of parsed log entries
            
        Returns:
            List of detected brute force attacks
        """
        detections = []
        
        # Group failures by target user and source IP
        failures_by_ip_user: Dict[tuple, List[ParsedLogEntry]] = defaultdict(list)
        failures_by_user: Dict[str, List[ParsedLogEntry]] = defaultdict(list)
        failures_by_ip: Dict[str, List[ParsedLogEntry]] = defaultdict(list)
        
        for entry in log_entries:
            if entry.event_type in ['failed_login', 'invalid_user', 'sudo_failure']:
                key = (entry.source_ip or 'unknown', entry.user or 'unknown')
                failures_by_ip_user[key].append(entry)
                
                if entry.user:
                    failures_by_user[entry.user].append(entry)
                if entry.source_ip:
                    failures_by_ip[entry.source_ip].append(entry)
        
        # Detect single-source brute force (same IP, same user)
        for (ip, user), entries in failures_by_ip_user.items():
            if ip == 'unknown':
                continue
            
            # Sort by timestamp and check for bursts
            entries_sorted = sorted(entries, key=lambda e: e.timestamp)
            
            for i, entry in enumerate(entries_sorted):
                # Count failures within time window
                window_entries = [
                    e for e in entries_sorted[i:]
                    if e.timestamp - entry.timestamp <= self.time_window
                ]
                
                if len(window_entries) >= self.failed_threshold:
                    detection = Detection(
                        detection_type=DetectionType.BRUTE_FORCE,
                        alert=f"Brute force attack detected: {len(window_entries)} failed login attempts "
                              f"for user '{user}' from IP {ip} within {self.time_window}",
                        severity=Severity.HIGH if len(window_entries) >= self.failed_threshold * 2 else Severity.MEDIUM,
                        iocs=[f"Source IP: {ip}"],
                        log_entries=window_entries,
                        timestamp=entry.timestamp,
                        source_ips=[ip],
                        users=[user] if user != 'unknown' else [],
                        metadata={
                            'failed_attempts': len(window_entries),
                            'time_window_minutes': self.time_window.total_seconds() / 60,
                            'attack_type': 'single_source',
                        }
                    )
                    detections.append(detection)
                    break  # Only one detection per IP/user combo
        
        # Detect distributed brute force (same user, multiple IPs)
        for user, entries in failures_by_user.items():
            if user == 'unknown':
                continue
            
            # Group by source IP
            ips_involved = defaultdict(list)
            for entry in entries:
                if entry.source_ip:
                    ips_involved[entry.source_ip].append(entry)
            
            # Check if multiple IPs are targeting the same user
            qualifying_ips = {
                ip: entries for ip, entries in ips_involved.items()
                if len(entries) >= self.distributed_threshold
            }
            
            if len(qualifying_ips) >= self.distributed_sources:
                all_entries = []
                for ip_entries in qualifying_ips.values():
                    all_entries.extend(ip_entries)
                
                detection = Detection(
                    detection_type=DetectionType.BRUTE_FORCE,
                    alert=f"Distributed brute force attack detected: {len(qualifying_ips)} different IPs "
                          f"targeting user '{user}' with {len(all_entries)} total failed attempts",
                    severity=Severity.CRITICAL,
                    iocs=[f"Source IP: {ip}" for ip in qualifying_ips.keys()],
                    log_entries=sorted(all_entries, key=lambda e: e.timestamp)[:20],
                    timestamp=min(e.timestamp for e in all_entries),
                    source_ips=list(qualifying_ips.keys()),
                    users=[user],
                    metadata={
                        'failed_attempts': len(all_entries),
                        'source_count': len(qualifying_ips),
                        'attack_type': 'distributed',
                    }
                )
                detections.append(detection)
        
        # Detect credential stuffing (same IP, many users)
        for ip, entries in failures_by_ip.items():
            users_targeted = set(e.user for e in entries if e.user)
            
            if len(users_targeted) >= 5:  # Many different users
                detection = Detection(
                    detection_type=DetectionType.BRUTE_FORCE,
                    alert=f"Credential stuffing detected: IP {ip} attempted login to "
                          f"{len(users_targeted)} different user accounts",
                    severity=Severity.HIGH,
                    iocs=[f"Source IP: {ip}"],
                    log_entries=entries[:20],
                    timestamp=min(e.timestamp for e in entries),
                    source_ips=[ip],
                    users=list(users_targeted),
                    metadata={
                        'failed_attempts': len(entries),
                        'users_targeted': len(users_targeted),
                        'attack_type': 'credential_stuffing',
                    }
                )
                detections.append(detection)
        
        return detections


class SuspiciousLoginDetector:
    """
    Detects suspicious login behavior.
    
    Detection criteria:
    - Logins at unusual hours
    - Logins from unusual locations/IPs
    - Logins using unusual methods
    - Rapid successive logins
    - Login after account creation
    """
    
    def __init__(
        self,
        unusual_hours: tuple = (0, 5),  # Midnight to 5 AM
        trusted_ips: Optional[Set[str]] = None,
        trusted_users: Optional[Set[str]] = None
    ):
        """
        Initialize the suspicious login detector.
        
        Args:
            unusual_hours: Tuple of (start_hour, end_hour) for unusual login times
            trusted_ips: Set of trusted IP addresses
            trusted_users: Set of trusted usernames
        """
        self.unusual_hours = unusual_hours
        self.trusted_ips = trusted_ips or set()
        self.trusted_users = trusted_users or {'root', 'admin', 'Administrator'}
    
    def detect(self, log_entries: List[ParsedLogEntry]) -> List[Detection]:
        """
        Detect suspicious login behavior.
        
        Args:
            log_entries: List of parsed log entries
            
        Returns:
            List of detected suspicious login incidents
        """
        detections = []
        
        # Track successful logins
        successful_logins: List[ParsedLogEntry] = []
        
        for entry in log_entries:
            if entry.event_type == 'successful_login':
                successful_logins.append(entry)
        
        # Check each successful login for suspicious patterns
        for entry in successful_logins:
            suspicious_reasons = []
            severity = Severity.LOW
            
            # Check for unusual hours
            if self.unusual_hours[0] <= entry.timestamp.hour <= self.unusual_hours[1]:
                suspicious_reasons.append(
                    f"Login at unusual hour ({entry.timestamp.strftime('%H:%M')})"
                )
                severity = Severity.MEDIUM
            
            # Check for root/admin login from non-trusted IP
            if entry.user and entry.user.lower() in {'root', 'administrator', 'admin'}:
                if entry.source_ip and entry.source_ip not in self.trusted_ips:
                    suspicious_reasons.append(
                        f"Privileged user '{entry.user}' login from external IP {entry.source_ip}"
                    )
                    severity = Severity.HIGH
            
            # Check for unusual authentication method
            auth_method = entry.metadata.get('auth_method', '').lower()
            if auth_method == 'password' and entry.user in self.trusted_users:
                suspicious_reasons.append(
                    f"Password authentication used instead of key-based for '{entry.user}'"
                )
            
            # Check for interactive login to service accounts
            logon_type = entry.metadata.get('LogonTypeName', '')
            if logon_type == 'Interactive' and entry.user:
                if entry.user.lower().endswith('$') or 'service' in entry.user.lower():
                    suspicious_reasons.append(
                        f"Interactive login to service account '{entry.user}'"
                    )
                    severity = Severity.HIGH
            
            if suspicious_reasons:
                detection = Detection(
                    detection_type=DetectionType.SUSPICIOUS_LOGIN,
                    alert=f"Suspicious login detected: {'; '.join(suspicious_reasons)}",
                    severity=severity,
                    iocs=[f"Source IP: {entry.source_ip}"] if entry.source_ip else [],
                    log_entries=[entry],
                    timestamp=entry.timestamp,
                    source_ips=[entry.source_ip] if entry.source_ip else [],
                    users=[entry.user] if entry.user else [],
                    metadata={
                        'reasons': suspicious_reasons,
                        'auth_method': auth_method,
                        'logon_type': logon_type,
                    }
                )
                detections.append(detection)
        
        # Detect rapid successive logins (potential lateral movement)
        logins_by_user: Dict[str, List[ParsedLogEntry]] = defaultdict(list)
        for entry in successful_logins:
            if entry.user:
                logins_by_user[entry.user].append(entry)
        
        for user, entries in logins_by_user.items():
            if len(entries) < 2:
                continue
            
            entries_sorted = sorted(entries, key=lambda e: e.timestamp)
            
            for i in range(len(entries_sorted) - 1):
                time_diff = entries_sorted[i + 1].timestamp - entries_sorted[i].timestamp
                
                # Different sources within short time
                if time_diff < timedelta(minutes=5):
                    ip1 = entries_sorted[i].source_ip
                    ip2 = entries_sorted[i + 1].source_ip
                    
                    if ip1 and ip2 and ip1 != ip2:
                        detection = Detection(
                            detection_type=DetectionType.SUSPICIOUS_LOGIN,
                            alert=f"Rapid successive logins for user '{user}' from different IPs: "
                                  f"{ip1} and {ip2} within {time_diff}",
                            severity=Severity.HIGH,
                            iocs=[f"Source IP: {ip1}", f"Source IP: {ip2}"],
                            log_entries=[entries_sorted[i], entries_sorted[i + 1]],
                            timestamp=entries_sorted[i].timestamp,
                            source_ips=[ip1, ip2],
                            users=[user],
                            metadata={
                                'time_difference_seconds': time_diff.total_seconds(),
                                'potential_lateral_movement': True,
                            }
                        )
                        detections.append(detection)
        
        return detections


class UnknownProcessDetector:
    """
    Detects execution of unknown or suspicious processes.
    
    Uses a whitelist approach combined with pattern matching
    to identify potentially malicious process executions.
    """
    
    # Common legitimate processes (can be customized)
    DEFAULT_WHITELIST = {
        'bash', 'sh', 'zsh', 'fish', 'csh', 'tcsh',
        'python', 'python3', 'python2', 'perl', 'ruby', 'node',
        'java', 'javac', 'dotnet',
        'ls', 'cat', 'grep', 'awk', 'sed', 'find', 'locate',
        'cp', 'mv', 'rm', 'mkdir', 'rmdir', 'touch',
        'vim', 'vi', 'nano', 'emacs',
        'git', 'svn', 'hg',
        'apt', 'apt-get', 'yum', 'dnf', 'pacman', 'brew',
        'systemctl', 'service', 'journalctl',
        'ssh', 'scp', 'rsync', 'sftp',
        'curl', 'wget', 'ping', 'traceroute', 'netstat', 'ss',
        'ps', 'top', 'htop', 'free', 'df', 'du',
        'cron', 'crontab', 'at',
        'sudo', 'su', 'passwd', 'useradd', 'usermod', 'userdel',
    }
    
    # Suspicious process patterns
    SUSPICIOUS_PATTERNS = [
        re.compile(r'nc\s+-.*-e', re.IGNORECASE),  # Netcat reverse shell
        re.compile(r'bash\s+-i', re.IGNORECASE),  # Interactive bash
        re.compile(r'/dev/tcp/', re.IGNORECASE),  # Bash network redirection
        re.compile(r'base64\s+-d', re.IGNORECASE),  # Base64 decode
        re.compile(r'curl.*\|\s*(?:ba)?sh', re.IGNORECASE),  # Curl pipe to shell
        re.compile(r'wget.*\|\s*(?:ba)?sh', re.IGNORECASE),  # Wget pipe to shell
        re.compile(r'python.*-c.*import', re.IGNORECASE),  # Python one-liner
        re.compile(r'perl.*-e.*socket', re.IGNORECASE),  # Perl socket
        re.compile(r'powershell.*-enc', re.IGNORECASE),  # Encoded PowerShell
        re.compile(r'powershell.*downloadstring', re.IGNORECASE),  # PowerShell download
        re.compile(r'certutil.*-urlcache', re.IGNORECASE),  # Certutil download
        re.compile(r'mshta\s+http', re.IGNORECASE),  # MSHTA remote
        re.compile(r'regsvr32.*\/s.*\/n.*\/u.*\/i:', re.IGNORECASE),  # Squiblydoo
        re.compile(r'wmic.*process.*call.*create', re.IGNORECASE),  # WMIC process creation
    ]
    
    # Known malicious process names
    MALICIOUS_PROCESSES = {
        'mimikatz', 'mimikatz.exe',
        'procdump', 'procdump.exe',
        'lazagne', 'lazagne.exe',
        'pwdump', 'pwdump.exe',
        'wce', 'wce.exe',
        'gsecdump', 'gsecdump.exe',
        'bloodhound', 'sharphound',
        'rubeus', 'rubeus.exe',
        'kerberoast',
        'empire', 'covenant',
        'cobalt', 'beacon',
    }
    
    def __init__(
        self,
        whitelist: Optional[Set[str]] = None,
        additional_suspicious: Optional[List[re.Pattern]] = None
    ):
        """
        Initialize the unknown process detector.
        
        Args:
            whitelist: Custom whitelist of allowed processes
            additional_suspicious: Additional suspicious patterns
        """
        self.whitelist = whitelist or self.DEFAULT_WHITELIST
        self.suspicious_patterns = self.SUSPICIOUS_PATTERNS.copy()
        if additional_suspicious:
            self.suspicious_patterns.extend(additional_suspicious)
    
    def detect(self, log_entries: List[ParsedLogEntry]) -> List[Detection]:
        """
        Detect unknown or suspicious process executions.
        
        Args:
            log_entries: List of parsed log entries
            
        Returns:
            List of detected suspicious process executions
        """
        detections = []
        
        for entry in log_entries:
            # Check sudo commands
            if entry.event_type == 'sudo_command':
                command = entry.metadata.get('command', '')
                self._check_command(entry, command, detections)
            
            # Check Windows process creation
            elif entry.event_type == 'process_creation':
                command = entry.metadata.get('CommandLine', '')
                process_name = entry.metadata.get('NewProcessName', '')
                self._check_command(entry, command, detections)
                self._check_process_name(entry, process_name, detections)
            
            # Check for command in message
            elif entry.metadata.get('pattern_matched') == 'sudo_command':
                command = entry.metadata.get('command', '')
                self._check_command(entry, command, detections)
        
        return detections
    
    def _check_command(
        self,
        entry: ParsedLogEntry,
        command: str,
        detections: List[Detection]
    ) -> None:
        """Check a command for suspicious patterns."""
        if not command:
            return
        
        command_lower = command.lower()
        
        # Check for malicious process names
        for malicious in self.MALICIOUS_PROCESSES:
            if malicious in command_lower:
                detection = Detection(
                    detection_type=DetectionType.UNKNOWN_PROCESS,
                    alert=f"Known malicious tool detected: '{malicious}' in command: {command[:100]}",
                    severity=Severity.CRITICAL,
                    iocs=[f"Malicious tool: {malicious}"],
                    log_entries=[entry],
                    timestamp=entry.timestamp,
                    source_ips=[entry.source_ip] if entry.source_ip else [],
                    users=[entry.user] if entry.user else [],
                    metadata={
                        'command': command,
                        'malicious_tool': malicious,
                    }
                )
                detections.append(detection)
                return
        
        # Check suspicious patterns
        for pattern in self.suspicious_patterns:
            if pattern.search(command):
                detection = Detection(
                    detection_type=DetectionType.UNKNOWN_PROCESS,
                    alert=f"Suspicious command pattern detected: {command[:100]}",
                    severity=Severity.HIGH,
                    iocs=[f"Pattern: {pattern.pattern}"],
                    log_entries=[entry],
                    timestamp=entry.timestamp,
                    source_ips=[entry.source_ip] if entry.source_ip else [],
                    users=[entry.user] if entry.user else [],
                    metadata={
                        'command': command,
                        'pattern_matched': pattern.pattern,
                    }
                )
                detections.append(detection)
                return
    
    def _check_process_name(
        self,
        entry: ParsedLogEntry,
        process_name: str,
        detections: List[Detection]
    ) -> None:
        """Check a process name against whitelist and blacklist."""
        if not process_name:
            return
        
        # Extract just the executable name
        exe_name = Path(process_name).name.lower()
        
        # Check blacklist
        if exe_name in self.MALICIOUS_PROCESSES:
            detection = Detection(
                detection_type=DetectionType.UNKNOWN_PROCESS,
                alert=f"Known malicious process executed: {process_name}",
                severity=Severity.CRITICAL,
                iocs=[f"Process: {exe_name}"],
                log_entries=[entry],
                timestamp=entry.timestamp,
                source_ips=[entry.source_ip] if entry.source_ip else [],
                users=[entry.user] if entry.user else [],
                metadata={
                    'process_name': process_name,
                }
            )
            detections.append(detection)


class IOCMatcher:
    """
    Matches log entries against an IOC database.
    """
    
    def __init__(self, ioc_database: IOCDatabase):
        """
        Initialize the IOC matcher.
        
        Args:
            ioc_database: IOCDatabase instance with loaded IOCs
        """
        self.ioc_db = ioc_database
    
    def detect(self, log_entries: List[ParsedLogEntry]) -> List[Detection]:
        """
        Check log entries for IOC matches.
        
        Args:
            log_entries: List of parsed log entries
            
        Returns:
            List of detected IOC matches
        """
        detections = []
        
        for entry in log_entries:
            matched_iocs = []
            
            # Check source IP
            if entry.source_ip and self.ioc_db.check_ip(entry.source_ip):
                matched_iocs.append(f"Malicious IP: {entry.source_ip}")
            
            # Check username
            if entry.user and self.ioc_db.check_username(entry.user):
                matched_iocs.append(f"Suspicious username: {entry.user}")
            
            # Check for IOCs in raw log and message
            text_matches = self.ioc_db.check_text(entry.raw_log)
            text_matches.extend(self.ioc_db.check_text(entry.message))
            matched_iocs.extend(set(text_matches))
            
            # Check metadata for additional IOCs
            for key, value in entry.metadata.items():
                if isinstance(value, str):
                    if self.ioc_db.check_ip(value):
                        matched_iocs.append(f"Malicious IP in {key}: {value}")
                    if self.ioc_db.check_process(value):
                        matched_iocs.append(f"Malicious process in {key}: {value}")
            
            if matched_iocs:
                # Deduplicate
                matched_iocs = list(set(matched_iocs))
                
                # Determine severity based on IOC type
                severity = Severity.MEDIUM
                if any('malicious ip' in ioc.lower() for ioc in matched_iocs):
                    severity = Severity.HIGH
                if any('process' in ioc.lower() for ioc in matched_iocs):
                    severity = Severity.CRITICAL
                
                detection = Detection(
                    detection_type=DetectionType.IOC_MATCH,
                    alert=f"IOC match detected: {', '.join(matched_iocs[:3])}",
                    severity=severity,
                    iocs=matched_iocs,
                    log_entries=[entry],
                    timestamp=entry.timestamp,
                    source_ips=[entry.source_ip] if entry.source_ip else [],
                    users=[entry.user] if entry.user else [],
                    metadata={
                        'matched_iocs': matched_iocs,
                        'event_type': entry.event_type,
                    }
                )
                detections.append(detection)
        
        return detections


class DetectionEngine:
    """
    Main detection engine that orchestrates all detection modules.
    
    Combines results from:
    - BruteForceDetector
    - SuspiciousLoginDetector
    - UnknownProcessDetector
    - IOCMatcher
    """
    
    def __init__(
        self,
        ioc_file: Optional[Path] = None,
        brute_force_threshold: int = 5,
        brute_force_window: int = 10,
    ):
        """
        Initialize the detection engine.
        
        Args:
            ioc_file: Path to IOC JSON file
            brute_force_threshold: Failed attempts threshold
            brute_force_window: Time window in minutes
        """
        self.brute_force_detector = BruteForceDetector(
            failed_threshold=brute_force_threshold,
            time_window_minutes=brute_force_window
        )
        self.suspicious_login_detector = SuspiciousLoginDetector()
        self.unknown_process_detector = UnknownProcessDetector()
        
        # Load IOC database if file provided
        if ioc_file:
            self.ioc_database = IOCDatabase.load_from_file(ioc_file)
            self.ioc_matcher = IOCMatcher(self.ioc_database)
        else:
            self.ioc_database = IOCDatabase()
            self.ioc_matcher = IOCMatcher(self.ioc_database)
    
    def load_iocs(self, ioc_file: Path) -> None:
        """
        Load IOCs from a file.
        
        Args:
            ioc_file: Path to IOC JSON file
        """
        self.ioc_database = IOCDatabase.load_from_file(ioc_file)
        self.ioc_matcher = IOCMatcher(self.ioc_database)
    
    def detect_all(self, log_entries: List[ParsedLogEntry]) -> List[Detection]:
        """
        Run all detection modules on log entries.
        
        Args:
            log_entries: List of parsed log entries
            
        Returns:
            List of all detected incidents
        """
        all_detections = []
        
        # Run each detector
        logger.info("Running brute force detection...")
        all_detections.extend(self.brute_force_detector.detect(log_entries))
        
        logger.info("Running suspicious login detection...")
        all_detections.extend(self.suspicious_login_detector.detect(log_entries))
        
        logger.info("Running unknown process detection...")
        all_detections.extend(self.unknown_process_detector.detect(log_entries))
        
        logger.info("Running IOC matching...")
        all_detections.extend(self.ioc_matcher.detect(log_entries))
        
        # Sort by timestamp (most recent first)
        all_detections.sort(key=lambda d: d.timestamp, reverse=True)
        
        logger.info(f"Detection complete: {len(all_detections)} incidents found")
        
        return all_detections
    
    def detect_brute_force(self, log_entries: List[ParsedLogEntry]) -> List[Detection]:
        """Run only brute force detection."""
        return self.brute_force_detector.detect(log_entries)
    
    def detect_suspicious_logins(self, log_entries: List[ParsedLogEntry]) -> List[Detection]:
        """Run only suspicious login detection."""
        return self.suspicious_login_detector.detect(log_entries)
    
    def detect_unknown_processes(self, log_entries: List[ParsedLogEntry]) -> List[Detection]:
        """Run only unknown process detection."""
        return self.unknown_process_detector.detect(log_entries)
    
    def detect_ioc_matches(self, log_entries: List[ParsedLogEntry]) -> List[Detection]:
        """Run only IOC matching."""
        return self.ioc_matcher.detect(log_entries)


def run_detection_pipeline(
    log_files: List[Path],
    ioc_file: Optional[Path] = None
) -> List[Detection]:
    """
    Convenience function to run the full detection pipeline.
    
    Args:
        log_files: List of log files to analyze
        ioc_file: Optional path to IOC file
        
    Returns:
        List of detected incidents
    """
    from .log_parser import UnifiedLogParser
    
    # Parse all logs
    parser = UnifiedLogParser()
    all_entries = []
    
    for log_file in log_files:
        entries = list(parser.parse_file(log_file))
        all_entries.extend(entries)
        logger.info(f"Parsed {len(entries)} entries from {log_file}")
    
    # Run detection
    engine = DetectionEngine(ioc_file=ioc_file)
    detections = engine.detect_all(all_entries)
    
    return detections
