"""
Test Database Module
====================
PyTest tests for database operations.
"""

import pytest
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import os
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.db.database import (
    IncidentDatabase,
    Incident,
    detection_to_incident,
    get_database
)
from src.core.detection import Detection, DetectionType, Severity


class TestIncident:
    """Tests for Incident dataclass."""
    
    def test_create_incident(self):
        """Test creating an incident."""
        incident = Incident(
            alert="Test alert",
            ioc="IP: 192.168.1.100",
            log_snippet="Test log",
            severity="high",
            status="new"
        )
        
        assert incident.alert == "Test alert"
        assert incident.severity == "high"
        assert incident.status == "new"
        assert incident.id is None
    
    def test_default_timestamp(self):
        """Test default timestamp is set."""
        incident = Incident(alert="Test")
        assert incident.timestamp is not None
        assert isinstance(incident.timestamp, datetime)
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        incident = Incident(
            id=1,
            alert="Test alert",
            ioc="IP: 192.168.1.100",
            severity="high",
            status="new"
        )
        
        d = incident.to_dict()
        
        assert d['id'] == 1
        assert d['alert'] == "Test alert"
        assert d['severity'] == "high"
        assert d['status'] == "new"
    
    def test_from_row(self):
        """Test creating from database row."""
        row = (
            1,  # id
            "Test alert",  # alert
            "IP: 192.168.1.100",  # ioc
            "Log snippet",  # log_snippet
            "AI summary",  # ai_summary
            "high",  # severity
            "new",  # status
            "2024-12-27T10:30:00",  # timestamp
            "brute_force",  # detection_type
            "192.168.1.100",  # source_ips
            "root",  # users
            "{}"  # metadata
        )
        
        incident = Incident.from_row(row)
        
        assert incident.id == 1
        assert incident.alert == "Test alert"
        assert incident.severity == "high"
        assert incident.detection_type == "brute_force"
    
    def test_get_metadata_dict(self):
        """Test parsing metadata as dictionary."""
        incident = Incident(
            alert="Test",
            metadata='{"key": "value"}'
        )
        
        meta = incident.get_metadata_dict()
        
        assert meta['key'] == 'value'
    
    def test_get_metadata_dict_empty(self):
        """Test empty metadata returns empty dict."""
        incident = Incident(alert="Test", metadata='{}')
        
        meta = incident.get_metadata_dict()
        
        assert meta == {}


class TestIncidentDatabase:
    """Tests for IncidentDatabase class."""
    
    @pytest.fixture
    def db(self):
        """Create a temporary database."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            temp_path = f.name
        
        database = IncidentDatabase(Path(temp_path))
        
        yield database
        
        database.close()
        try:
            os.unlink(temp_path)
        except:
            pass
    
    def test_database_creation(self, db):
        """Test database is created correctly."""
        assert db.db_path.exists()
    
    def test_add_incident(self, db):
        """Test adding an incident."""
        incident = Incident(
            alert="Test alert",
            ioc="IP: 192.168.1.100",
            log_snippet="Test log",
            severity="high",
            status="new",
            detection_type="brute_force"
        )
        
        incident_id = db.add_incident(incident)
        
        assert incident_id is not None
        assert incident_id > 0
    
    def test_get_incident(self, db):
        """Test retrieving an incident by ID."""
        incident = Incident(
            alert="Test alert",
            severity="high",
            status="new"
        )
        
        incident_id = db.add_incident(incident)
        retrieved = db.get_incident(incident_id)
        
        assert retrieved is not None
        assert retrieved.id == incident_id
        assert retrieved.alert == "Test alert"
    
    def test_get_nonexistent_incident(self, db):
        """Test retrieving non-existent incident returns None."""
        retrieved = db.get_incident(99999)
        assert retrieved is None
    
    def test_get_all_incidents(self, db):
        """Test retrieving all incidents."""
        # Add multiple incidents
        for i in range(5):
            incident = Incident(
                alert=f"Alert {i}",
                severity="medium",
                status="new"
            )
            db.add_incident(incident)
        
        all_incidents = db.get_all_incidents()
        
        assert len(all_incidents) == 5
    
    def test_get_incidents_by_severity(self, db):
        """Test filtering by severity."""
        db.add_incident(Incident(alert="High 1", severity="high", status="new"))
        db.add_incident(Incident(alert="High 2", severity="high", status="new"))
        db.add_incident(Incident(alert="Low 1", severity="low", status="new"))
        
        high_incidents = db.get_incidents_by_severity("high")
        
        assert len(high_incidents) == 2
        assert all(i.severity == "high" for i in high_incidents)
    
    def test_get_incidents_by_status(self, db):
        """Test filtering by status."""
        db.add_incident(Incident(alert="New 1", severity="high", status="new"))
        db.add_incident(Incident(alert="New 2", severity="high", status="new"))
        db.add_incident(Incident(alert="Resolved", severity="high", status="resolved"))
        
        new_incidents = db.get_incidents_by_status("new")
        
        assert len(new_incidents) == 2
        assert all(i.status == "new" for i in new_incidents)
    
    def test_get_incidents_without_ai_summary(self, db):
        """Test getting incidents without AI analysis."""
        db.add_incident(Incident(alert="No AI", severity="high", status="new", ai_summary=None))
        db.add_incident(Incident(alert="Has AI", severity="high", status="new", ai_summary="Analysis done"))
        
        pending = db.get_incidents_without_ai_summary()
        
        assert len(pending) == 1
        assert pending[0].alert == "No AI"
    
    def test_update_ai_summary(self, db):
        """Test updating AI summary."""
        incident_id = db.add_incident(Incident(
            alert="Test",
            severity="high",
            status="new"
        ))
        
        success = db.update_ai_summary(incident_id, "New AI summary")
        
        assert success is True
        
        updated = db.get_incident(incident_id)
        assert updated.ai_summary == "New AI summary"
    
    def test_update_status(self, db):
        """Test updating incident status."""
        incident_id = db.add_incident(Incident(
            alert="Test",
            severity="high",
            status="new"
        ))
        
        success = db.update_status(incident_id, "investigating")
        
        assert success is True
        
        updated = db.get_incident(incident_id)
        assert updated.status == "investigating"
    
    def test_update_status_invalid(self, db):
        """Test updating with invalid status fails."""
        incident_id = db.add_incident(Incident(
            alert="Test",
            severity="high",
            status="new"
        ))
        
        success = db.update_status(incident_id, "invalid_status")
        
        assert success is False
    
    def test_delete_incident(self, db):
        """Test deleting an incident."""
        incident_id = db.add_incident(Incident(
            alert="Test",
            severity="high",
            status="new"
        ))
        
        success = db.delete_incident(incident_id)
        
        assert success is True
        assert db.get_incident(incident_id) is None
    
    def test_search_incidents(self, db):
        """Test searching incidents."""
        db.add_incident(Incident(alert="Brute force attack from 192.168.1.100", severity="high", status="new"))
        db.add_incident(Incident(alert="Different alert", severity="low", status="new"))
        
        results = db.search_incidents("192.168")
        
        assert len(results) == 1
        assert "192.168" in results[0].alert
    
    def test_add_incidents_bulk(self, db):
        """Test bulk adding incidents."""
        incidents = [
            Incident(alert=f"Alert {i}", severity="medium", status="new")
            for i in range(10)
        ]
        
        ids = db.add_incidents_bulk(incidents)
        
        assert len(ids) == 10
        assert all(isinstance(id, int) for id in ids)
    
    def test_get_statistics(self, db):
        """Test getting statistics."""
        db.add_incident(Incident(alert="High 1", severity="high", status="new"))
        db.add_incident(Incident(alert="Critical 1", severity="critical", status="new"))
        db.add_incident(Incident(alert="Low 1", severity="low", status="resolved"))
        
        stats = db.get_statistics()
        
        assert stats['total'] == 3
        assert stats['by_severity'].get('high', 0) == 1
        assert stats['by_severity'].get('critical', 0) == 1
        assert stats['by_status'].get('new', 0) == 2
        assert stats['by_status'].get('resolved', 0) == 1
    
    def test_get_incidents_by_date_range(self, db):
        """Test filtering by date range."""
        now = datetime.now()
        yesterday = now - timedelta(days=1)
        two_days_ago = now - timedelta(days=2)
        
        db.add_incident(Incident(alert="Today", severity="high", status="new", timestamp=now))
        db.add_incident(Incident(alert="Yesterday", severity="high", status="new", timestamp=yesterday))
        
        # Search for today only
        results = db.get_incidents_by_date_range(
            yesterday + timedelta(hours=12),
            now + timedelta(hours=1)
        )
        
        assert len(results) == 1
        assert results[0].alert == "Today"
    
    def test_update_incident_full(self, db):
        """Test full incident update."""
        incident = Incident(
            alert="Original alert",
            severity="low",
            status="new"
        )
        incident_id = db.add_incident(incident)
        
        # Update incident
        updated_incident = Incident(
            id=incident_id,
            alert="Updated alert",
            severity="high",
            status="investigating",
            ioc="New IOC"
        )
        
        success = db.update_incident(updated_incident)
        
        assert success is True
        
        retrieved = db.get_incident(incident_id)
        assert retrieved.alert == "Updated alert"
        assert retrieved.severity == "high"
        assert retrieved.status == "investigating"


class TestDetectionToIncident:
    """Tests for detection to incident conversion."""
    
    def test_convert_detection(self):
        """Test converting detection to incident."""
        detection = Detection(
            detection_type=DetectionType.BRUTE_FORCE,
            alert="Brute force detected",
            severity=Severity.HIGH,
            iocs=["IP: 192.168.1.100"],
            source_ips=["192.168.1.100"],
            users=["root"],
            metadata={"key": "value"}
        )
        
        incident = detection_to_incident(detection)
        
        assert incident.alert == "Brute force detected"
        assert incident.severity == "high"
        assert incident.status == "new"
        assert incident.detection_type == "brute_force"
        assert "192.168.1.100" in incident.source_ips
        assert "root" in incident.users


class TestGetDatabase:
    """Tests for get_database singleton function."""
    
    def test_get_database_creates_instance(self):
        """Test that get_database creates a database."""
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            temp_path = f.name
        
        try:
            db = get_database(Path(temp_path))
            assert db is not None
            assert isinstance(db, IncidentDatabase)
        finally:
            try:
                os.unlink(temp_path)
            except:
                pass


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
