#!/usr/bin/env python3
"""
Test script to populate the database with sample incidents
Run this to generate test data for the dashboard
"""

from src.core.log_parser import UnifiedLogParser
from src.core.detection import DetectionEngine
from src.db.database import IncidentDatabase, detection_to_incident
import os

def populate_database():
    """Parse sample logs, detect threats, and populate the database"""
    
    print("🚀 Starting database population...")
    
    # Initialize components
    parser = UnifiedLogParser()
    engine = DetectionEngine(ioc_file="logs/iocs.json")
    db = IncidentDatabase("data/incidents.db")
    
    # Sample log files to process
    log_files = [
        "logs/sample_auth.log",
        "logs/sample_windows_security.json",
        "logs/sample_ids.json"
    ]
    
    total_incidents = 0
    
    for log_file in log_files:
        if not os.path.exists(log_file):
            print(f"⚠️  File not found: {log_file}")
            continue
            
        print(f"\n📄 Processing: {log_file}")
        
        try:
            # Parse logs
            events = list(parser.parse_file(log_file))
            print(f"   Parsed {len(events)} events")
            
            # Detect threats
            detections = list(engine.detect_all(events))
            print(f"   Found {len(detections)} detections")
            
            # Save to database
            for detection in detections:
                incident = detection_to_incident(detection)
                incident_id = db.add_incident(incident)
                total_incidents += 1
                
                # Print summary
                severity_emoji = {
                    "critical": "🔴",
                    "high": "🟠",
                    "medium": "🟡",
                    "low": "🟢"
                }.get(incident.severity, "⚪")
                
                print(f"   {severity_emoji} [{incident.severity.upper()}] {incident.alert[:60]}...")
                
        except Exception as e:
            print(f"   ❌ Error processing {log_file}: {e}")
            continue
    
    print(f"\n✅ Database populated successfully!")
    print(f"📊 Total incidents created: {total_incidents}")
    
    # Show statistics
    stats = db.get_statistics()
    print(f"\n📈 Database Statistics:")
    print(f"   Total: {stats['total']}")
    print(f"   Critical: {stats['by_severity'].get('critical', 0)}")
    print(f"   High: {stats['by_severity'].get('high', 0)}")
    print(f"   Medium: {stats['by_severity'].get('medium', 0)}")
    print(f"   Low: {stats['by_severity'].get('low', 0)}")
    
    print(f"\n🌐 Open the dashboard: http://localhost:8501")
    print(f"   Run: python -m streamlit run src/dashboard/app.py")

if __name__ == "__main__":
    populate_database()
