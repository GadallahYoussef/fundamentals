"""
Test Log Parser Module
======================
PyTest tests for log parsing functionality.
"""

import pytest
from datetime import datetime
from pathlib import Path
import tempfile
import os
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.log_parser import (
    LinuxAuthLogParser,
    WindowsEventLogParser,
    IDSLogParser,
    UnifiedLogParser,
    ParsedLogEntry,
    LogType,
    parse_auth_log,
    parse_windows_log,
    parse_any_log
)


class TestLinuxAuthLogParser:
    """Tests for Linux auth.log parser."""
    
    @pytest.fixture
    def parser(self):
        """Create a parser instance."""
        return LinuxAuthLogParser(year=2024)
    
    def test_parse_ssh_failed_login(self, parser):
        """Test parsing failed SSH login."""
        line = "Dec 27 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22"
        
        entry = parser.parse_line(line)
        
        assert entry is not None
        assert entry.event_type == "failed_login"
        assert entry.user == "root"
        assert entry.source_ip == "192.168.1.100"
        assert entry.source == "server"
        assert entry.log_type == LogType.LINUX_AUTH
    
    def test_parse_ssh_successful_login(self, parser):
        """Test parsing successful SSH login."""
        line = "Dec 27 10:30:45 server sshd[1234]: Accepted publickey for admin from 10.0.0.1 port 54321"
        
        entry = parser.parse_line(line)
        
        assert entry is not None
        assert entry.event_type == "successful_login"
        assert entry.user == "admin"
        assert entry.source_ip == "10.0.0.1"
        assert entry.metadata.get('auth_method') == "publickey"
    
    def test_parse_invalid_user(self, parser):
        """Test parsing invalid user attempt."""
        line = "Dec 27 10:30:45 server sshd[1234]: Invalid user hacker from 192.168.1.100"
        
        entry = parser.parse_line(line)
        
        assert entry is not None
        assert entry.event_type == "invalid_user"
        assert entry.user == "hacker"
        assert entry.source_ip == "192.168.1.100"
    
    def test_parse_sudo_command(self, parser):
        """Test parsing sudo command."""
        line = "Dec 27 10:30:45 server sudo:   admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/bash"
        
        entry = parser.parse_line(line)
        
        assert entry is not None
        assert entry.event_type == "sudo_command"
        assert entry.user == "admin"
        assert entry.metadata.get('command') == "/bin/bash"
    
    def test_parse_session_opened(self, parser):
        """Test parsing session opened."""
        line = "Dec 27 10:30:45 server sshd[1234]: pam_unix(sshd:session): session opened for user admin"
        
        entry = parser.parse_line(line)
        
        assert entry is not None
        assert entry.event_type == "session_opened"
        assert entry.user == "admin"
    
    def test_parse_empty_line(self, parser):
        """Test parsing empty line returns None."""
        entry = parser.parse_line("")
        assert entry is None
    
    def test_parse_file(self, parser):
        """Test parsing a complete log file."""
        log_content = """Dec 27 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22
Dec 27 10:30:46 server sshd[1234]: Failed password for root from 192.168.1.100 port 22
Dec 27 10:30:47 server sshd[1234]: Accepted publickey for admin from 10.0.0.1 port 54321
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            temp_path = f.name
        
        try:
            entries = list(parser.parse_file(Path(temp_path)))
            
            assert len(entries) == 3
            assert entries[0].event_type == "failed_login"
            assert entries[2].event_type == "successful_login"
        finally:
            os.unlink(temp_path)
    
    def test_timestamp_parsing(self, parser):
        """Test timestamp parsing."""
        line = "Dec 27 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22"
        
        entry = parser.parse_line(line)
        
        assert entry.timestamp.month == 12
        assert entry.timestamp.day == 27
        assert entry.timestamp.hour == 10
        assert entry.timestamp.minute == 30
        assert entry.timestamp.second == 45


class TestWindowsEventLogParser:
    """Tests for Windows event log parser."""
    
    @pytest.fixture
    def parser(self):
        """Create a parser instance."""
        return WindowsEventLogParser()
    
    def test_parse_json_failed_login(self, parser):
        """Test parsing JSON format failed login."""
        log_line = '{"EventID": "4625", "TimeCreated": "2024-12-27T10:30:45", "Computer": "WORKSTATION1", "TargetUserName": "admin", "IpAddress": "192.168.1.100"}'
        
        entry = parser.parse_json_log(log_line)
        
        assert entry is not None
        assert entry.event_type == "failed_login"
        assert entry.user == "admin"
        assert entry.source_ip == "192.168.1.100"
        assert entry.source == "WORKSTATION1"
    
    def test_parse_json_successful_login(self, parser):
        """Test parsing JSON format successful login."""
        log_line = '{"EventID": "4624", "TimeCreated": "2024-12-27T10:30:45", "Computer": "WORKSTATION1", "TargetUserName": "user1", "IpAddress": "10.0.0.1"}'
        
        entry = parser.parse_json_log(log_line)
        
        assert entry is not None
        assert entry.event_type == "successful_login"
        assert entry.user == "user1"
    
    def test_parse_json_process_creation(self, parser):
        """Test parsing process creation event."""
        log_line = '{"EventID": "4688", "TimeCreated": "2024-12-27T10:30:45", "Computer": "SERVER1", "TargetUserName": "SYSTEM"}'
        
        entry = parser.parse_json_log(log_line)
        
        assert entry is not None
        assert entry.event_type == "process_creation"
    
    def test_parse_invalid_json(self, parser):
        """Test parsing invalid JSON returns None."""
        entry = parser.parse_json_log("not valid json")
        assert entry is None
    
    def test_event_id_mapping(self, parser):
        """Test that event IDs are properly mapped."""
        assert parser.EVENT_ID_MAP['4624'] == 'successful_login'
        assert parser.EVENT_ID_MAP['4625'] == 'failed_login'
        assert parser.EVENT_ID_MAP['4688'] == 'process_creation'
        assert parser.EVENT_ID_MAP['4672'] == 'special_privileges_assigned'
    
    def test_logon_types(self, parser):
        """Test logon type mapping."""
        assert parser.LOGON_TYPES['2'] == 'Interactive'
        assert parser.LOGON_TYPES['3'] == 'Network'
        assert parser.LOGON_TYPES['10'] == 'RemoteInteractive'


class TestIDSLogParser:
    """Tests for IDS log parser."""
    
    @pytest.fixture
    def parser(self):
        """Create a parser instance."""
        return IDSLogParser()
    
    def test_parse_suricata_eve(self, parser):
        """Test parsing Suricata EVE JSON format."""
        log_line = '{"timestamp": "2024-12-27T10:30:45", "event_type": "alert", "src_ip": "192.168.1.100", "dest_ip": "10.0.0.1", "alert": {"signature": "ET SCAN Potential SSH Scan", "signature_id": 2001219, "severity": 2, "category": "Attempted Information Leak"}}'
        
        entry = parser.parse_suricata_eve(log_line)
        
        assert entry is not None
        assert entry.event_type == "ids_alert"
        assert entry.source_ip == "192.168.1.100"
        assert entry.message == "ET SCAN Potential SSH Scan"
        assert entry.metadata.get('dst_ip') == "10.0.0.1"
    
    def test_parse_non_alert_event(self, parser):
        """Test that non-alert events return None."""
        log_line = '{"timestamp": "2024-12-27T10:30:45", "event_type": "flow", "src_ip": "192.168.1.100"}'
        
        entry = parser.parse_suricata_eve(log_line)
        assert entry is None


class TestUnifiedLogParser:
    """Tests for unified log parser."""
    
    @pytest.fixture
    def parser(self):
        """Create a parser instance."""
        return UnifiedLogParser()
    
    def test_detect_linux_auth_by_content(self, parser):
        """Test log type detection by content."""
        log_content = "Dec 27 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            temp_path = f.name
        
        try:
            log_type = parser.detect_log_type(Path(temp_path))
            assert log_type == LogType.LINUX_AUTH
        finally:
            os.unlink(temp_path)
    
    def test_detect_by_filename(self, parser):
        """Test log type detection by filename."""
        # Test auth log detection
        assert parser.detect_log_type(Path("/var/log/auth.log")) == LogType.LINUX_AUTH
        assert parser.detect_log_type(Path("/var/log/secure")) == LogType.LINUX_AUTH
        
        # Test Windows detection
        assert parser.detect_log_type(Path("Security.evtx")) == LogType.WINDOWS_SECURITY
        
        # Test IDS detection
        assert parser.detect_log_type(Path("suricata_eve.json")) == LogType.IDS_LOG
        assert parser.detect_log_type(Path("snort_alerts.log")) == LogType.IDS_LOG
    
    def test_parse_multiple_formats(self, parser):
        """Test parsing file with automatic detection."""
        log_content = """Dec 27 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22
Dec 27 10:30:46 server sshd[1234]: Failed password for admin from 192.168.1.101 port 22
"""
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='_auth.log', delete=False) as f:
            f.write(log_content)
            temp_path = f.name
        
        try:
            entries = list(parser.parse_file(Path(temp_path)))
            assert len(entries) >= 2
        finally:
            os.unlink(temp_path)


class TestConvenienceFunctions:
    """Tests for convenience functions."""
    
    def test_parse_auth_log(self):
        """Test parse_auth_log convenience function."""
        log_content = "Dec 27 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            temp_path = f.name
        
        try:
            entries = parse_auth_log(temp_path)
            assert len(entries) == 1
            assert entries[0].event_type == "failed_login"
        finally:
            os.unlink(temp_path)
    
    def test_parse_any_log(self):
        """Test parse_any_log convenience function."""
        log_content = "Dec 27 10:30:45 server sshd[1234]: Failed password for root from 192.168.1.100 port 22"
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
            f.write(log_content)
            temp_path = f.name
        
        try:
            entries = parse_any_log(temp_path)
            assert len(entries) >= 1
        finally:
            os.unlink(temp_path)


class TestParsedLogEntry:
    """Tests for ParsedLogEntry dataclass."""
    
    def test_create_entry(self):
        """Test creating a parsed log entry."""
        entry = ParsedLogEntry(
            timestamp=datetime.now(),
            source="server",
            event_type="failed_login",
            user="root",
            source_ip="192.168.1.100",
            message="Test message",
            raw_log="raw log line",
            log_type=LogType.LINUX_AUTH
        )
        
        assert entry.source == "server"
        assert entry.event_type == "failed_login"
        assert entry.user == "root"
        assert entry.source_ip == "192.168.1.100"
    
    def test_default_metadata(self):
        """Test default metadata is empty dict."""
        entry = ParsedLogEntry(
            timestamp=datetime.now(),
            source="server",
            event_type="test"
        )
        
        assert entry.metadata == {}
    
    def test_metadata_mutation(self):
        """Test metadata can be modified."""
        entry = ParsedLogEntry(
            timestamp=datetime.now(),
            source="server",
            event_type="test",
            metadata={'key': 'value'}
        )
        
        entry.metadata['new_key'] = 'new_value'
        assert entry.metadata['new_key'] == 'new_value'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
