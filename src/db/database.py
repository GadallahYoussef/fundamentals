"""
Database Module
===============
SQLite database operations for storing and managing security incidents.
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any, Tuple
from dataclasses import dataclass, asdict
from contextlib import contextmanager
import logging
import threading

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# Default database path
DEFAULT_DB_PATH = Path(__file__).parent.parent.parent / "data" / "incidents.db"


@dataclass
class Incident:
    """
    Represents a security incident stored in the database.
    
    Attributes:
        id: Unique identifier (auto-generated)
        alert: Human-readable alert description
        ioc: Indicators of Compromise (JSON string or comma-separated)
        log_snippet: Relevant log entries snippet
        ai_summary: AI-generated analysis summary (nullable)
        severity: Severity level (low, medium, high, critical)
        status: Incident status (new, investigating, resolved, false_positive)
        timestamp: When the incident was detected
        detection_type: Type of detection that triggered this incident
        source_ips: Source IP addresses involved
        users: Users involved
        metadata: Additional incident metadata (JSON)
    """
    id: Optional[int] = None
    alert: str = ""
    ioc: str = ""
    log_snippet: str = ""
    ai_summary: Optional[str] = None
    severity: str = "medium"
    status: str = "new"
    timestamp: Optional[datetime] = None
    detection_type: str = ""
    source_ips: str = ""
    users: str = ""
    metadata: str = "{}"
    
    def __post_init__(self):
        """Initialize default timestamp if not provided."""
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    @classmethod
    def from_row(cls, row: Tuple) -> 'Incident':
        """
        Create an Incident from a database row.
        
        Args:
            row: Database row tuple
            
        Returns:
            Incident instance
        """
        return cls(
            id=row[0],
            alert=row[1],
            ioc=row[2],
            log_snippet=row[3],
            ai_summary=row[4],
            severity=row[5],
            status=row[6],
            timestamp=datetime.fromisoformat(row[7]) if row[7] else datetime.now(),
            detection_type=row[8] if len(row) > 8 else "",
            source_ips=row[9] if len(row) > 9 else "",
            users=row[10] if len(row) > 10 else "",
            metadata=row[11] if len(row) > 11 else "{}"
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert incident to dictionary."""
        return {
            'id': self.id,
            'alert': self.alert,
            'ioc': self.ioc,
            'log_snippet': self.log_snippet,
            'ai_summary': self.ai_summary,
            'severity': self.severity,
            'status': self.status,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'detection_type': self.detection_type,
            'source_ips': self.source_ips,
            'users': self.users,
            'metadata': json.loads(self.metadata) if isinstance(self.metadata, str) else self.metadata
        }
    
    def get_metadata_dict(self) -> Dict[str, Any]:
        """Parse and return metadata as dictionary."""
        if isinstance(self.metadata, dict):
            return self.metadata
        try:
            return json.loads(self.metadata)
        except (json.JSONDecodeError, TypeError):
            return {}


class IncidentDatabase:
    """
    SQLite database manager for security incidents.
    
    Thread-safe implementation with connection pooling.
    """
    
    # SQL statements
    CREATE_TABLE_SQL = """
    CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert TEXT NOT NULL,
        ioc TEXT,
        log_snippet TEXT,
        ai_summary TEXT,
        severity TEXT DEFAULT 'medium',
        status TEXT DEFAULT 'new',
        timestamp TEXT NOT NULL,
        detection_type TEXT,
        source_ips TEXT,
        users TEXT,
        metadata TEXT DEFAULT '{}'
    )
    """
    
    CREATE_INDEXES_SQL = [
        "CREATE INDEX IF NOT EXISTS idx_severity ON incidents(severity)",
        "CREATE INDEX IF NOT EXISTS idx_status ON incidents(status)",
        "CREATE INDEX IF NOT EXISTS idx_timestamp ON incidents(timestamp)",
        "CREATE INDEX IF NOT EXISTS idx_detection_type ON incidents(detection_type)"
    ]
    
    INSERT_SQL = """
    INSERT INTO incidents 
        (alert, ioc, log_snippet, ai_summary, severity, status, timestamp, 
         detection_type, source_ips, users, metadata)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """
    
    SELECT_ALL_SQL = """
    SELECT id, alert, ioc, log_snippet, ai_summary, severity, status, 
           timestamp, detection_type, source_ips, users, metadata
    FROM incidents
    ORDER BY timestamp DESC
    """
    
    SELECT_BY_ID_SQL = """
    SELECT id, alert, ioc, log_snippet, ai_summary, severity, status, 
           timestamp, detection_type, source_ips, users, metadata
    FROM incidents
    WHERE id = ?
    """
    
    UPDATE_AI_SUMMARY_SQL = """
    UPDATE incidents 
    SET ai_summary = ?
    WHERE id = ?
    """
    
    UPDATE_STATUS_SQL = """
    UPDATE incidents 
    SET status = ?
    WHERE id = ?
    """
    
    DELETE_SQL = """
    DELETE FROM incidents WHERE id = ?
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize the database connection.
        
        Args:
            db_path: Path to the SQLite database file.
                     If None, uses default path in data directory.
        """
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path = Path(self.db_path)
        
        # Ensure parent directory exists
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Thread-local storage for connections
        self._local = threading.local()
        
        # Initialize database schema
        self._init_db()
        
        logger.info(f"Initialized incident database at {self.db_path}")
    
    def _get_connection(self) -> sqlite3.Connection:
        """
        Get a thread-local database connection.
        
        Returns:
            SQLite connection for current thread
        """
        if not hasattr(self._local, 'connection') or self._local.connection is None:
            self._local.connection = sqlite3.connect(
                str(self.db_path),
                detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES,
                check_same_thread=False
            )
            self._local.connection.row_factory = sqlite3.Row
        return self._local.connection
    
    @contextmanager
    def _get_cursor(self):
        """
        Context manager for database cursors with automatic commit/rollback.
        
        Yields:
            Database cursor
        """
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            cursor.close()
    
    def _init_db(self) -> None:
        """Initialize the database schema."""
        with self._get_cursor() as cursor:
            # Create main table
            cursor.execute(self.CREATE_TABLE_SQL)
            
            # Create indexes
            for index_sql in self.CREATE_INDEXES_SQL:
                cursor.execute(index_sql)
        
        logger.debug("Database schema initialized")
    
    def add_incident(self, incident: Incident) -> int:
        """
        Add a new incident to the database.
        
        Args:
            incident: Incident to add
            
        Returns:
            ID of the inserted incident
        """
        with self._get_cursor() as cursor:
            cursor.execute(
                self.INSERT_SQL,
                (
                    incident.alert,
                    incident.ioc,
                    incident.log_snippet,
                    incident.ai_summary,
                    incident.severity,
                    incident.status,
                    incident.timestamp.isoformat() if incident.timestamp else datetime.now().isoformat(),
                    incident.detection_type,
                    incident.source_ips,
                    incident.users,
                    incident.metadata if isinstance(incident.metadata, str) else json.dumps(incident.metadata)
                )
            )
            incident_id = cursor.lastrowid
        
        logger.info(f"Added incident {incident_id}: {incident.alert[:50]}...")
        return incident_id
    
    def add_incidents_bulk(self, incidents: List[Incident]) -> List[int]:
        """
        Add multiple incidents in a single transaction.
        
        Args:
            incidents: List of incidents to add
            
        Returns:
            List of inserted incident IDs
        """
        ids = []
        with self._get_cursor() as cursor:
            for incident in incidents:
                cursor.execute(
                    self.INSERT_SQL,
                    (
                        incident.alert,
                        incident.ioc,
                        incident.log_snippet,
                        incident.ai_summary,
                        incident.severity,
                        incident.status,
                        incident.timestamp.isoformat() if incident.timestamp else datetime.now().isoformat(),
                        incident.detection_type,
                        incident.source_ips,
                        incident.users,
                        incident.metadata if isinstance(incident.metadata, str) else json.dumps(incident.metadata)
                    )
                )
                ids.append(cursor.lastrowid)
        
        logger.info(f"Added {len(ids)} incidents in bulk")
        return ids
    
    def get_incident(self, incident_id: int) -> Optional[Incident]:
        """
        Get a specific incident by ID.
        
        Args:
            incident_id: ID of the incident to retrieve
            
        Returns:
            Incident if found, None otherwise
        """
        with self._get_cursor() as cursor:
            cursor.execute(self.SELECT_BY_ID_SQL, (incident_id,))
            row = cursor.fetchone()
            
            if row:
                return Incident.from_row(tuple(row))
        
        return None
    
    def get_all_incidents(self) -> List[Incident]:
        """
        Get all incidents from the database.
        
        Returns:
            List of all incidents, ordered by timestamp (newest first)
        """
        with self._get_cursor() as cursor:
            cursor.execute(self.SELECT_ALL_SQL)
            rows = cursor.fetchall()
            
            return [Incident.from_row(tuple(row)) for row in rows]
    
    def get_incidents_by_status(self, status: str) -> List[Incident]:
        """
        Get incidents filtered by status.
        
        Args:
            status: Status to filter by (new, investigating, resolved, false_positive)
            
        Returns:
            List of matching incidents
        """
        sql = self.SELECT_ALL_SQL.replace(
            "ORDER BY", 
            f"WHERE status = ? ORDER BY"
        )
        
        with self._get_cursor() as cursor:
            cursor.execute(sql, (status,))
            rows = cursor.fetchall()
            
            return [Incident.from_row(tuple(row)) for row in rows]
    
    def get_incidents_by_severity(self, severity: str) -> List[Incident]:
        """
        Get incidents filtered by severity.
        
        Args:
            severity: Severity to filter by (low, medium, high, critical)
            
        Returns:
            List of matching incidents
        """
        sql = self.SELECT_ALL_SQL.replace(
            "ORDER BY",
            f"WHERE severity = ? ORDER BY"
        )
        
        with self._get_cursor() as cursor:
            cursor.execute(sql, (severity,))
            rows = cursor.fetchall()
            
            return [Incident.from_row(tuple(row)) for row in rows]
    
    def get_incidents_by_detection_type(self, detection_type: str) -> List[Incident]:
        """
        Get incidents filtered by detection type.
        
        Args:
            detection_type: Detection type to filter by
            
        Returns:
            List of matching incidents
        """
        sql = self.SELECT_ALL_SQL.replace(
            "ORDER BY",
            f"WHERE detection_type = ? ORDER BY"
        )
        
        with self._get_cursor() as cursor:
            cursor.execute(sql, (detection_type,))
            rows = cursor.fetchall()
            
            return [Incident.from_row(tuple(row)) for row in rows]
    
    def get_incidents_without_ai_summary(self) -> List[Incident]:
        """
        Get incidents that have not been analyzed by AI.
        
        Returns:
            List of incidents without AI summary
        """
        sql = self.SELECT_ALL_SQL.replace(
            "ORDER BY",
            "WHERE ai_summary IS NULL OR ai_summary = '' ORDER BY"
        )
        
        with self._get_cursor() as cursor:
            cursor.execute(sql)
            rows = cursor.fetchall()
            
            return [Incident.from_row(tuple(row)) for row in rows]
    
    def get_incidents_by_date_range(
        self,
        start_date: datetime,
        end_date: datetime
    ) -> List[Incident]:
        """
        Get incidents within a date range.
        
        Args:
            start_date: Start of date range
            end_date: End of date range
            
        Returns:
            List of incidents within the range
        """
        sql = self.SELECT_ALL_SQL.replace(
            "ORDER BY",
            "WHERE timestamp BETWEEN ? AND ? ORDER BY"
        )
        
        with self._get_cursor() as cursor:
            cursor.execute(sql, (start_date.isoformat(), end_date.isoformat()))
            rows = cursor.fetchall()
            
            return [Incident.from_row(tuple(row)) for row in rows]
    
    def search_incidents(self, search_term: str) -> List[Incident]:
        """
        Search incidents by alert text, IOC, or log snippet.
        
        Args:
            search_term: Term to search for
            
        Returns:
            List of matching incidents
        """
        sql = """
        SELECT id, alert, ioc, log_snippet, ai_summary, severity, status, 
               timestamp, detection_type, source_ips, users, metadata
        FROM incidents
        WHERE alert LIKE ? OR ioc LIKE ? OR log_snippet LIKE ? OR source_ips LIKE ?
        ORDER BY timestamp DESC
        """
        
        search_pattern = f"%{search_term}%"
        
        with self._get_cursor() as cursor:
            cursor.execute(sql, (search_pattern, search_pattern, search_pattern, search_pattern))
            rows = cursor.fetchall()
            
            return [Incident.from_row(tuple(row)) for row in rows]
    
    def update_ai_summary(self, incident_id: int, ai_summary: str) -> bool:
        """
        Update the AI summary for an incident.
        
        Args:
            incident_id: ID of the incident to update
            ai_summary: New AI summary
            
        Returns:
            True if updated successfully, False otherwise
        """
        with self._get_cursor() as cursor:
            cursor.execute(self.UPDATE_AI_SUMMARY_SQL, (ai_summary, incident_id))
            success = cursor.rowcount > 0
        
        if success:
            logger.info(f"Updated AI summary for incident {incident_id}")
        else:
            logger.warning(f"No incident found with ID {incident_id}")
        
        return success
    
    def update_status(self, incident_id: int, status: str) -> bool:
        """
        Update the status of an incident.
        
        Args:
            incident_id: ID of the incident to update
            status: New status (new, investigating, resolved, false_positive)
            
        Returns:
            True if updated successfully, False otherwise
        """
        valid_statuses = {'new', 'investigating', 'resolved', 'false_positive'}
        if status not in valid_statuses:
            logger.error(f"Invalid status: {status}. Must be one of {valid_statuses}")
            return False
        
        with self._get_cursor() as cursor:
            cursor.execute(self.UPDATE_STATUS_SQL, (status, incident_id))
            success = cursor.rowcount > 0
        
        if success:
            logger.info(f"Updated status for incident {incident_id} to {status}")
        else:
            logger.warning(f"No incident found with ID {incident_id}")
        
        return success
    
    def update_incident(self, incident: Incident) -> bool:
        """
        Update all fields of an incident.
        
        Args:
            incident: Incident with updated fields (must have valid id)
            
        Returns:
            True if updated successfully, False otherwise
        """
        if incident.id is None:
            logger.error("Cannot update incident without ID")
            return False
        
        sql = """
        UPDATE incidents SET
            alert = ?,
            ioc = ?,
            log_snippet = ?,
            ai_summary = ?,
            severity = ?,
            status = ?,
            timestamp = ?,
            detection_type = ?,
            source_ips = ?,
            users = ?,
            metadata = ?
        WHERE id = ?
        """
        
        with self._get_cursor() as cursor:
            cursor.execute(
                sql,
                (
                    incident.alert,
                    incident.ioc,
                    incident.log_snippet,
                    incident.ai_summary,
                    incident.severity,
                    incident.status,
                    incident.timestamp.isoformat() if incident.timestamp else datetime.now().isoformat(),
                    incident.detection_type,
                    incident.source_ips,
                    incident.users,
                    incident.metadata if isinstance(incident.metadata, str) else json.dumps(incident.metadata),
                    incident.id
                )
            )
            success = cursor.rowcount > 0
        
        if success:
            logger.info(f"Updated incident {incident.id}")
        
        return success
    
    def delete_incident(self, incident_id: int) -> bool:
        """
        Delete an incident from the database.
        
        Args:
            incident_id: ID of the incident to delete
            
        Returns:
            True if deleted successfully, False otherwise
        """
        with self._get_cursor() as cursor:
            cursor.execute(self.DELETE_SQL, (incident_id,))
            success = cursor.rowcount > 0
        
        if success:
            logger.info(f"Deleted incident {incident_id}")
        else:
            logger.warning(f"No incident found with ID {incident_id}")
        
        return success
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about incidents in the database.
        
        Returns:
            Dictionary with various statistics
        """
        stats = {}
        
        with self._get_cursor() as cursor:
            # Total count
            cursor.execute("SELECT COUNT(*) FROM incidents")
            stats['total'] = cursor.fetchone()[0]
            
            # Count by severity
            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM incidents 
                GROUP BY severity
            """)
            stats['by_severity'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Count by status
            cursor.execute("""
                SELECT status, COUNT(*) as count 
                FROM incidents 
                GROUP BY status
            """)
            stats['by_status'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Count by detection type
            cursor.execute("""
                SELECT detection_type, COUNT(*) as count 
                FROM incidents 
                GROUP BY detection_type
            """)
            stats['by_detection_type'] = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Count without AI analysis
            cursor.execute("""
                SELECT COUNT(*) FROM incidents 
                WHERE ai_summary IS NULL OR ai_summary = ''
            """)
            stats['pending_ai_analysis'] = cursor.fetchone()[0]
            
            # Recent incidents (last 24 hours)
            yesterday = (datetime.now() - __import__('datetime').timedelta(days=1)).isoformat()
            cursor.execute("""
                SELECT COUNT(*) FROM incidents 
                WHERE timestamp > ?
            """, (yesterday,))
            stats['last_24h'] = cursor.fetchone()[0]
        
        return stats
    
    def close(self) -> None:
        """Close the database connection for the current thread."""
        if hasattr(self._local, 'connection') and self._local.connection:
            self._local.connection.close()
            self._local.connection = None
            logger.debug("Database connection closed")


def detection_to_incident(detection) -> Incident:
    """
    Convert a Detection object to an Incident for database storage.
    
    Args:
        detection: Detection object from detection engine
        
    Returns:
        Incident ready for database storage
    """
    return Incident(
        alert=detection.alert,
        ioc=detection.get_ioc_string(),
        log_snippet=detection.get_log_snippet(),
        ai_summary=None,
        severity=detection.severity.value,
        status="new",
        timestamp=detection.timestamp,
        detection_type=detection.detection_type.value,
        source_ips=", ".join(detection.source_ips),
        users=", ".join(detection.users),
        metadata=json.dumps(detection.metadata)
    )


# Singleton instance for global access
_db_instance: Optional[IncidentDatabase] = None


def get_database(db_path: Optional[Path] = None) -> IncidentDatabase:
    """
    Get or create the global database instance.
    
    Args:
        db_path: Optional path to database file
        
    Returns:
        IncidentDatabase instance
    """
    global _db_instance
    
    if _db_instance is None or db_path is not None:
        _db_instance = IncidentDatabase(db_path)
    
    return _db_instance
