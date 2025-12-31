"""
Log Parser Module
=================
Parses authentication logs from Linux (auth.log) and Windows event logs.
Extracts relevant security events for incident detection.
"""

import re
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Generator
from pathlib import Path
from enum import Enum
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LogType(Enum):
    """Enumeration of supported log types."""
    LINUX_AUTH = "linux_auth"
    WINDOWS_SECURITY = "windows_security"
    WINDOWS_SYSTEM = "windows_system"
    IDS_LOG = "ids_log"
    UNKNOWN = "unknown"


@dataclass
class ParsedLogEntry:
    """
    Represents a parsed log entry with normalized fields.
    
    Attributes:
        timestamp: When the event occurred
        source: Source of the log (hostname, service)
        event_type: Type of event (login, logout, failed_login, etc.)
        user: Username involved (if applicable)
        source_ip: Source IP address (if applicable)
        message: Raw or processed message content
        raw_log: Original log line
        metadata: Additional parsed fields
        log_type: Type of log this entry came from
    """
    timestamp: datetime
    source: str
    event_type: str
    user: Optional[str] = None
    source_ip: Optional[str] = None
    message: str = ""
    raw_log: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    log_type: LogType = LogType.UNKNOWN


class LinuxAuthLogParser:
    """
    Parser for Linux authentication logs (auth.log, secure).
    
    Handles common authentication events including:
    - SSH login attempts (successful and failed)
    - sudo commands
    - PAM authentication events
    - User session events
    """
    
    # Regex patterns for different log entry types
    PATTERNS = {
        'ssh_failed': re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
            r'Failed\s+(?P<auth_method>\S+)\s+for\s+'
            r'(?:invalid\s+user\s+)?(?P<user>\S+)\s+'
            r'from\s+(?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+'
            r'port\s+(?P<port>\d+)',
            re.IGNORECASE
        ),
        'ssh_success': re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
            r'Accepted\s+(?P<auth_method>\S+)\s+for\s+(?P<user>\S+)\s+'
            r'from\s+(?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+'
            r'port\s+(?P<port>\d+)',
            re.IGNORECASE
        ),
        'ssh_invalid_user': re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+sshd\[\d+\]:\s+'
            r'Invalid\s+user\s+(?P<user>\S+)\s+'
            r'from\s+(?P<source_ip>\d+\.\d+\.\d+\.\d+)',
            re.IGNORECASE
        ),
        'sudo_command': re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+sudo:\s+'
            r'(?P<user>\S+)\s+:\s+.*COMMAND=(?P<command>.+)$',
            re.IGNORECASE
        ),
        'sudo_failure': re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+sudo:\s+'
            r'(?P<user>\S+)\s+:\s+.*authentication\s+failure',
            re.IGNORECASE
        ),
        'session_opened': re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+(?P<service>\S+)\[\d+\]:\s+'
            r'pam_unix\(\S+:session\):\s+session\s+opened\s+for\s+user\s+(?P<user>\S+)',
            re.IGNORECASE
        ),
        'session_closed': re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+(?P<service>\S+)\[\d+\]:\s+'
            r'pam_unix\(\S+:session\):\s+session\s+closed\s+for\s+user\s+(?P<user>\S+)',
            re.IGNORECASE
        ),
        'generic': re.compile(
            r'(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
            r'(?P<hostname>\S+)\s+(?P<service>\S+)(?:\[\d+\])?:\s+(?P<message>.+)$',
            re.IGNORECASE
        ),
    }
    
    def __init__(self, year: Optional[int] = None):
        """
        Initialize the Linux auth log parser.
        
        Args:
            year: Year to use for timestamps (auth.log doesn't include year).
                  Defaults to current year.
        """
        self.year = year or datetime.now().year
    
    def _parse_timestamp(self, timestamp_str: str) -> datetime:
        """
        Parse Linux auth.log timestamp format.
        
        Args:
            timestamp_str: Timestamp string like "Dec 27 10:30:45"
            
        Returns:
            datetime object with the parsed timestamp
        """
        try:
            # Add year to the timestamp
            full_timestamp = f"{self.year} {timestamp_str}"
            return datetime.strptime(full_timestamp, "%Y %b %d %H:%M:%S")
        except ValueError as e:
            logger.warning(f"Failed to parse timestamp '{timestamp_str}': {e}")
            return datetime.now()
    
    def parse_line(self, line: str) -> Optional[ParsedLogEntry]:
        """
        Parse a single log line.
        
        Args:
            line: Raw log line to parse
            
        Returns:
            ParsedLogEntry if successfully parsed, None otherwise
        """
        line = line.strip()
        if not line:
            return None
        
        # Try each pattern in order of specificity
        for pattern_name, pattern in self.PATTERNS.items():
            match = pattern.match(line)
            if match:
                groups = match.groupdict()
                
                # Determine event type based on pattern
                event_type_map = {
                    'ssh_failed': 'failed_login',
                    'ssh_success': 'successful_login',
                    'ssh_invalid_user': 'invalid_user',
                    'sudo_command': 'sudo_command',
                    'sudo_failure': 'sudo_failure',
                    'session_opened': 'session_opened',
                    'session_closed': 'session_closed',
                    'generic': 'generic',
                }
                
                entry = ParsedLogEntry(
                    timestamp=self._parse_timestamp(groups.get('timestamp', '')),
                    source=groups.get('hostname', 'unknown'),
                    event_type=event_type_map.get(pattern_name, 'unknown'),
                    user=groups.get('user'),
                    source_ip=groups.get('source_ip'),
                    message=groups.get('message', line),
                    raw_log=line,
                    metadata={
                        'auth_method': groups.get('auth_method'),
                        'port': groups.get('port'),
                        'command': groups.get('command'),
                        'service': groups.get('service'),
                        'pattern_matched': pattern_name,
                    },
                    log_type=LogType.LINUX_AUTH
                )
                return entry
        
        return None
    
    def parse_file(self, file_path: Path) -> Generator[ParsedLogEntry, None, None]:
        """
        Parse an entire log file.
        
        Args:
            file_path: Path to the log file
            
        Yields:
            ParsedLogEntry for each successfully parsed line
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    entry = self.parse_line(line)
                    if entry:
                        entry.metadata['line_number'] = line_num
                        yield entry
        except FileNotFoundError:
            logger.error(f"Log file not found: {file_path}")
        except PermissionError:
            logger.error(f"Permission denied reading log file: {file_path}")
        except Exception as e:
            logger.error(f"Error parsing log file {file_path}: {e}")


class WindowsEventLogParser:
    """
    Parser for Windows Security Event Logs.
    
    Handles exported Windows event logs in XML format (EVTX exports).
    Focuses on security-relevant events:
    - Logon events (4624, 4625)
    - Account management (4720, 4722, 4723, 4724, 4725, 4726)
    - Privilege use (4672, 4673, 4674)
    - Process creation (4688)
    """
    
    # Important Windows Security Event IDs
    EVENT_ID_MAP = {
        '4624': 'successful_login',
        '4625': 'failed_login',
        '4634': 'logoff',
        '4647': 'user_initiated_logoff',
        '4648': 'explicit_credential_logon',
        '4672': 'special_privileges_assigned',
        '4673': 'privileged_service_called',
        '4674': 'operation_on_privileged_object',
        '4688': 'process_creation',
        '4689': 'process_termination',
        '4720': 'user_account_created',
        '4722': 'user_account_enabled',
        '4723': 'password_change_attempt',
        '4724': 'password_reset_attempt',
        '4725': 'user_account_disabled',
        '4726': 'user_account_deleted',
        '4732': 'member_added_to_security_group',
        '4733': 'member_removed_from_security_group',
        '4756': 'member_added_to_universal_group',
        '4768': 'kerberos_tgt_requested',
        '4769': 'kerberos_service_ticket_requested',
        '4771': 'kerberos_pre_auth_failed',
        '4776': 'credential_validation',
        '4778': 'session_reconnected',
        '4779': 'session_disconnected',
        '5140': 'network_share_accessed',
        '5145': 'network_share_object_checked',
    }
    
    # Windows Logon Types
    LOGON_TYPES = {
        '2': 'Interactive',
        '3': 'Network',
        '4': 'Batch',
        '5': 'Service',
        '7': 'Unlock',
        '8': 'NetworkCleartext',
        '9': 'NewCredentials',
        '10': 'RemoteInteractive',
        '11': 'CachedInteractive',
    }
    
    def __init__(self):
        """Initialize the Windows event log parser."""
        pass
    
    def _parse_xml_event(self, event_xml: str) -> Optional[ParsedLogEntry]:
        """
        Parse a single Windows event from XML.
        
        Args:
            event_xml: XML string representing the event
            
        Returns:
            ParsedLogEntry if successfully parsed, None otherwise
        """
        try:
            root = ET.fromstring(event_xml)
            
            # Handle namespace
            ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            # Try to parse with namespace first, then without
            try:
                system = root.find('ns:System', ns)
                event_data = root.find('ns:EventData', ns)
            except:
                system = root.find('System')
                event_data = root.find('EventData')
            
            if system is None:
                return None
            
            # Extract system information
            event_id_elem = system.find('ns:EventID', ns) if ns else system.find('EventID')
            if event_id_elem is None:
                event_id_elem = system.find('EventID')
            
            event_id = event_id_elem.text if event_id_elem is not None else 'unknown'
            
            time_created = system.find('ns:TimeCreated', ns) if ns else system.find('TimeCreated')
            if time_created is None:
                time_created = system.find('TimeCreated')
            
            timestamp_str = time_created.get('SystemTime', '') if time_created is not None else ''
            
            computer_elem = system.find('ns:Computer', ns) if ns else system.find('Computer')
            if computer_elem is None:
                computer_elem = system.find('Computer')
            
            computer = computer_elem.text if computer_elem is not None else 'unknown'
            
            # Parse timestamp
            try:
                if timestamp_str:
                    # Handle various timestamp formats
                    if '.' in timestamp_str:
                        timestamp_str = timestamp_str.split('.')[0]
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', ''))
                else:
                    timestamp = datetime.now()
            except ValueError:
                timestamp = datetime.now()
            
            # Extract event data fields
            metadata = {}
            user = None
            source_ip = None
            
            if event_data is not None:
                for data in event_data:
                    name = data.get('Name', '')
                    value = data.text or ''
                    metadata[name] = value
                    
                    # Extract common fields
                    if name in ['TargetUserName', 'SubjectUserName']:
                        user = value
                    elif name in ['IpAddress', 'SourceNetworkAddress']:
                        if value and value != '-':
                            source_ip = value
                    elif name == 'LogonType':
                        metadata['LogonTypeName'] = self.LOGON_TYPES.get(value, 'Unknown')
            
            # Determine event type
            event_type = self.EVENT_ID_MAP.get(event_id, f'event_{event_id}')
            
            # Build message
            message = f"Event {event_id}: {event_type}"
            if user:
                message += f" - User: {user}"
            if source_ip:
                message += f" - Source: {source_ip}"
            
            return ParsedLogEntry(
                timestamp=timestamp,
                source=computer,
                event_type=event_type,
                user=user,
                source_ip=source_ip,
                message=message,
                raw_log=event_xml[:500],  # Truncate for storage
                metadata=metadata,
                log_type=LogType.WINDOWS_SECURITY
            )
            
        except ET.ParseError as e:
            logger.warning(f"XML parse error: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error parsing Windows event: {e}")
            return None
    
    def parse_json_log(self, log_line: str) -> Optional[ParsedLogEntry]:
        """
        Parse a Windows event log exported as JSON.
        
        Args:
            log_line: JSON string representing the event
            
        Returns:
            ParsedLogEntry if successfully parsed, None otherwise
        """
        try:
            event = json.loads(log_line)
            
            # Handle different JSON formats
            event_id = str(event.get('EventID', event.get('event_id', 'unknown')))
            timestamp_str = event.get('TimeCreated', event.get('timestamp', ''))
            computer = event.get('Computer', event.get('hostname', 'unknown'))
            
            # Parse timestamp
            try:
                if timestamp_str:
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', ''))
                else:
                    timestamp = datetime.now()
            except ValueError:
                timestamp = datetime.now()
            
            # Extract user and IP
            user = event.get('TargetUserName', event.get('SubjectUserName', event.get('user')))
            source_ip = event.get('IpAddress', event.get('source_ip'))
            
            event_type = self.EVENT_ID_MAP.get(event_id, f'event_{event_id}')
            
            return ParsedLogEntry(
                timestamp=timestamp,
                source=computer,
                event_type=event_type,
                user=user,
                source_ip=source_ip,
                message=f"Event {event_id}: {event_type}",
                raw_log=log_line[:500],
                metadata=event,
                log_type=LogType.WINDOWS_SECURITY
            )
            
        except json.JSONDecodeError:
            return None
        except Exception as e:
            logger.warning(f"Error parsing JSON event: {e}")
            return None
    
    def parse_file(self, file_path: Path) -> Generator[ParsedLogEntry, None, None]:
        """
        Parse a Windows event log file.
        
        Supports both XML and JSON export formats.
        
        Args:
            file_path: Path to the log file
            
        Yields:
            ParsedLogEntry for each successfully parsed event
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Try to determine format
            content_stripped = content.strip()
            
            if content_stripped.startswith('<'):
                # XML format - could be single events or wrapped in Events tag
                if '<Events>' in content:
                    # Multiple events wrapped
                    try:
                        root = ET.fromstring(content)
                        for event in root.findall('.//Event'):
                            event_xml = ET.tostring(event, encoding='unicode')
                            entry = self._parse_xml_event(event_xml)
                            if entry:
                                yield entry
                    except ET.ParseError:
                        # Try line by line
                        for line in content.split('</Event>'):
                            if '<Event' in line:
                                event_xml = line + '</Event>'
                                entry = self._parse_xml_event(event_xml)
                                if entry:
                                    yield entry
                else:
                    # Single event or line-by-line events
                    entry = self._parse_xml_event(content)
                    if entry:
                        yield entry
            
            elif content_stripped.startswith('{') or content_stripped.startswith('['):
                # JSON format
                if content_stripped.startswith('['):
                    # Array of events
                    events = json.loads(content)
                    for event in events:
                        entry = self.parse_json_log(json.dumps(event))
                        if entry:
                            yield entry
                else:
                    # Single event or newline-delimited JSON
                    for line in content.split('\n'):
                        line = line.strip()
                        if line.startswith('{'):
                            entry = self.parse_json_log(line)
                            if entry:
                                yield entry
            
            else:
                # Try line by line for unknown format
                for line in content.split('\n'):
                    line = line.strip()
                    if line:
                        entry = self.parse_json_log(line)
                        if entry:
                            yield entry
                            
        except FileNotFoundError:
            logger.error(f"Log file not found: {file_path}")
        except Exception as e:
            logger.error(f"Error parsing log file {file_path}: {e}")


class IDSLogParser:
    """
    Parser for IDS/IPS logs (Snort, Suricata-style).
    
    Handles common IDS alert formats including:
    - Snort fast alert format
    - Suricata EVE JSON format
    - Generic CSV IDS exports
    """
    
    # Snort fast alert pattern
    SNORT_PATTERN = re.compile(
        r'(?P<timestamp>\d{2}/\d{2}(?:/\d{2,4})?-\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+'
        r'\[\*\*\]\s*\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*'
        r'(?P<message>[^\[]*)\s*\[\*\*\]\s*'
        r'(?:\[Classification:\s*(?P<classification>[^\]]*)\])?\s*'
        r'(?:\[Priority:\s*(?P<priority>\d+)\])?\s*'
        r'\{(?P<protocol>\w+)\}\s*'
        r'(?P<src_ip>\d+\.\d+\.\d+\.\d+)(?::(?P<src_port>\d+))?\s*->\s*'
        r'(?P<dst_ip>\d+\.\d+\.\d+\.\d+)(?::(?P<dst_port>\d+))?',
        re.IGNORECASE
    )
    
    def __init__(self):
        """Initialize the IDS log parser."""
        pass
    
    def parse_snort_line(self, line: str) -> Optional[ParsedLogEntry]:
        """
        Parse a Snort fast alert format line.
        
        Args:
            line: Raw log line to parse
            
        Returns:
            ParsedLogEntry if successfully parsed, None otherwise
        """
        match = self.SNORT_PATTERN.match(line.strip())
        if not match:
            return None
        
        groups = match.groupdict()
        
        # Parse timestamp
        timestamp_str = groups.get('timestamp', '')
        try:
            # Handle various Snort timestamp formats
            if '/' in timestamp_str:
                parts = timestamp_str.split('-')
                date_part = parts[0]
                time_part = parts[1] if len(parts) > 1 else '00:00:00'
                
                if len(date_part.split('/')[0]) == 2:
                    # MM/DD or MM/DD/YY format
                    date_parts = date_part.split('/')
                    if len(date_parts) == 2:
                        date_part = f"{datetime.now().year}/{date_part}"
                    timestamp = datetime.strptime(f"{date_part}-{time_part.split('.')[0]}", 
                                                  "%Y/%m/%d-%H:%M:%S")
                else:
                    timestamp = datetime.strptime(f"{date_part}-{time_part.split('.')[0]}", 
                                                  "%m/%d/%y-%H:%M:%S")
            else:
                timestamp = datetime.now()
        except ValueError:
            timestamp = datetime.now()
        
        return ParsedLogEntry(
            timestamp=timestamp,
            source='snort',
            event_type='ids_alert',
            user=None,
            source_ip=groups.get('src_ip'),
            message=groups.get('message', '').strip(),
            raw_log=line,
            metadata={
                'gid': groups.get('gid'),
                'sid': groups.get('sid'),
                'rev': groups.get('rev'),
                'classification': groups.get('classification'),
                'priority': groups.get('priority'),
                'protocol': groups.get('protocol'),
                'src_port': groups.get('src_port'),
                'dst_ip': groups.get('dst_ip'),
                'dst_port': groups.get('dst_port'),
            },
            log_type=LogType.IDS_LOG
        )
    
    def parse_suricata_eve(self, line: str) -> Optional[ParsedLogEntry]:
        """
        Parse a Suricata EVE JSON format line.
        
        Args:
            line: JSON log line to parse
            
        Returns:
            ParsedLogEntry if successfully parsed, None otherwise
        """
        try:
            event = json.loads(line)
            
            # Only process alert events
            if event.get('event_type') != 'alert':
                return None
            
            alert = event.get('alert', {})
            
            timestamp_str = event.get('timestamp', '')
            try:
                timestamp = datetime.fromisoformat(timestamp_str.replace('Z', ''))
            except ValueError:
                timestamp = datetime.now()
            
            return ParsedLogEntry(
                timestamp=timestamp,
                source='suricata',
                event_type='ids_alert',
                user=None,
                source_ip=event.get('src_ip'),
                message=alert.get('signature', 'Unknown alert'),
                raw_log=line[:500],
                metadata={
                    'signature_id': alert.get('signature_id'),
                    'severity': alert.get('severity'),
                    'category': alert.get('category'),
                    'src_port': event.get('src_port'),
                    'dst_ip': event.get('dest_ip'),
                    'dst_port': event.get('dest_port'),
                    'protocol': event.get('proto'),
                },
                log_type=LogType.IDS_LOG
            )
            
        except json.JSONDecodeError:
            return None
        except Exception as e:
            logger.warning(f"Error parsing Suricata event: {e}")
            return None
    
    def parse_file(self, file_path: Path) -> Generator[ParsedLogEntry, None, None]:
        """
        Parse an IDS log file.
        
        Args:
            file_path: Path to the log file
            
        Yields:
            ParsedLogEntry for each successfully parsed alert
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Try Suricata EVE JSON first
                    entry = self.parse_suricata_eve(line)
                    if entry:
                        entry.metadata['line_number'] = line_num
                        yield entry
                        continue
                    
                    # Try Snort format
                    entry = self.parse_snort_line(line)
                    if entry:
                        entry.metadata['line_number'] = line_num
                        yield entry
                        
        except FileNotFoundError:
            logger.error(f"Log file not found: {file_path}")
        except Exception as e:
            logger.error(f"Error parsing IDS log file {file_path}: {e}")


class UnifiedLogParser:
    """
    Unified log parser that can handle multiple log formats.
    
    Automatically detects log format and uses appropriate parser.
    """
    
    def __init__(self):
        """Initialize the unified log parser with all sub-parsers."""
        self.linux_parser = LinuxAuthLogParser()
        self.windows_parser = WindowsEventLogParser()
        self.ids_parser = IDSLogParser()
    
    def detect_log_type(self, file_path: Path) -> LogType:
        """
        Detect the type of log file.
        
        Args:
            file_path: Path to the log file
            
        Returns:
            Detected LogType
        """
        filename = file_path.name.lower()
        
        # Check by filename
        if 'auth' in filename or 'secure' in filename:
            return LogType.LINUX_AUTH
        elif 'security' in filename or 'evtx' in filename:
            return LogType.WINDOWS_SECURITY
        elif 'ids' in filename or 'snort' in filename or 'suricata' in filename or 'eve' in filename:
            return LogType.IDS_LOG
        
        # Check by content
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_lines = f.read(1000)
            
            if '<Event' in first_lines or '<Events' in first_lines:
                return LogType.WINDOWS_SECURITY
            elif 'sshd' in first_lines or 'pam_unix' in first_lines:
                return LogType.LINUX_AUTH
            elif '"event_type"' in first_lines or '[**]' in first_lines:
                return LogType.IDS_LOG
            elif 'EventID' in first_lines:
                return LogType.WINDOWS_SECURITY
                
        except Exception:
            pass
        
        return LogType.UNKNOWN
    
    def parse_file(self, file_path: Path) -> Generator[ParsedLogEntry, None, None]:
        """
        Parse a log file using the appropriate parser.
        
        Args:
            file_path: Path to the log file
            
        Yields:
            ParsedLogEntry for each successfully parsed entry
        """
        file_path = Path(file_path)
        log_type = self.detect_log_type(file_path)
        
        logger.info(f"Detected log type: {log_type.value} for {file_path}")
        
        if log_type == LogType.LINUX_AUTH:
            yield from self.linux_parser.parse_file(file_path)
        elif log_type == LogType.WINDOWS_SECURITY:
            yield from self.windows_parser.parse_file(file_path)
        elif log_type == LogType.IDS_LOG:
            yield from self.ids_parser.parse_file(file_path)
        else:
            # Try each parser
            logger.warning(f"Unknown log type for {file_path}, trying all parsers")
            for entry in self.linux_parser.parse_file(file_path):
                yield entry
    
    def parse_multiple_files(self, file_paths: List[Path]) -> Generator[ParsedLogEntry, None, None]:
        """
        Parse multiple log files.
        
        Args:
            file_paths: List of paths to log files
            
        Yields:
            ParsedLogEntry for each successfully parsed entry from all files
        """
        for file_path in file_paths:
            yield from self.parse_file(file_path)


# Convenience functions
def parse_auth_log(file_path: str) -> List[ParsedLogEntry]:
    """
    Parse a Linux auth.log file.
    
    Args:
        file_path: Path to the auth.log file
        
    Returns:
        List of parsed log entries
    """
    parser = LinuxAuthLogParser()
    return list(parser.parse_file(Path(file_path)))


def parse_windows_log(file_path: str) -> List[ParsedLogEntry]:
    """
    Parse a Windows security event log file.
    
    Args:
        file_path: Path to the Windows log file
        
    Returns:
        List of parsed log entries
    """
    parser = WindowsEventLogParser()
    return list(parser.parse_file(Path(file_path)))


def parse_ids_log(file_path: str) -> List[ParsedLogEntry]:
    """
    Parse an IDS log file.
    
    Args:
        file_path: Path to the IDS log file
        
    Returns:
        List of parsed log entries
    """
    parser = IDSLogParser()
    return list(parser.parse_file(Path(file_path)))


def parse_any_log(file_path: str) -> List[ParsedLogEntry]:
    """
    Parse any supported log file with automatic format detection.
    
    Args:
        file_path: Path to the log file
        
    Returns:
        List of parsed log entries
    """
    parser = UnifiedLogParser()
    return list(parser.parse_file(Path(file_path)))
