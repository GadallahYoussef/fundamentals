"""
Test AI Analyzer Module
=======================
PyTest tests for AI-powered incident analysis.
Uses mocked responses to test without loading the actual model.
"""

import pytest
from datetime import datetime
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.ai.analyzer import (
    AIAnalyzer,
    AIAnalysisResult,
    MockAIAnalyzer,
    IncidentClassification,
    analyze_incident,
    get_analyzer
)


class TestAIAnalysisResult:
    """Tests for AIAnalysisResult dataclass."""
    
    def test_create_result(self):
        """Test creating an analysis result."""
        result = AIAnalysisResult(
            summary="Test summary",
            classification="credential_access",
            severity="high",
            confidence=85,
            response_steps=["Step 1", "Step 2"]
        )
        
        assert result.summary == "Test summary"
        assert result.classification == "credential_access"
        assert result.severity == "high"
        assert result.confidence == 85
        assert len(result.response_steps) == 2
    
    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = AIAnalysisResult(
            summary="Test summary",
            classification="credential_access",
            severity="high",
            confidence=85,
            response_steps=["Step 1"]
        )
        
        d = result.to_dict()
        
        assert d['summary'] == "Test summary"
        assert d['classification'] == "credential_access"
        assert d['severity'] == "high"
        assert d['confidence'] == 85
    
    def test_to_formatted_string(self):
        """Test formatted string output."""
        result = AIAnalysisResult(
            summary="Test summary",
            classification="credential_access",
            severity="high",
            confidence=85,
            response_steps=["Step 1", "Step 2"],
            ioc_analysis="IOC found",
            risk_assessment="High risk"
        )
        
        formatted = result.to_formatted_string()
        
        assert "AI INCIDENT ANALYSIS REPORT" in formatted
        assert "Test summary" in formatted
        assert "credential_access" in formatted
        assert "HIGH" in formatted
        assert "Step 1" in formatted
        assert "Step 2" in formatted
    
    def test_default_values(self):
        """Test default values."""
        result = AIAnalysisResult()
        
        assert result.summary == ""
        assert result.classification == "unknown"
        assert result.severity == "medium"
        assert result.confidence == 0
        assert result.response_steps == []


class TestMockAIAnalyzer:
    """Tests for mock AI analyzer."""
    
    @pytest.fixture
    def analyzer(self):
        """Create a mock analyzer."""
        return MockAIAnalyzer()
    
    def test_load_model_succeeds(self, analyzer):
        """Test that mock load always succeeds."""
        assert analyzer.load_model() is True
        assert analyzer._model_loaded is True
    
    def test_analyze_brute_force(self, analyzer):
        """Test analysis of brute force incident."""
        result = analyzer.analyze_incident(
            alert_description="Multiple failed login attempts detected for root user",
            ioc_details="Source IP: 192.168.1.100",
            log_snippet="Failed password for root from 192.168.1.100"
        )
        
        assert result.classification == "credential_access"
        assert result.severity in ["medium", "high"]
        assert "brute" in result.summary.lower()
        assert len(result.response_steps) > 0
    
    def test_analyze_mimikatz(self, analyzer):
        """Test analysis of credential theft tool detection."""
        result = analyzer.analyze_incident(
            alert_description="Mimikatz tool detected on workstation",
            ioc_details="Process: mimikatz.exe",
            log_snippet="Process mimikatz.exe started"
        )
        
        assert result.classification == "credential_access"
        assert result.severity == "critical"
        assert "credential" in result.summary.lower() or "compromise" in result.summary.lower()
    
    def test_analyze_lateral_movement(self, analyzer):
        """Test analysis of lateral movement detection."""
        result = analyzer.analyze_incident(
            alert_description="Potential lateral movement detected across multiple IPs",
            ioc_details="Source IPs: 192.168.1.100, 192.168.1.101",
            log_snippet="Login from multiple IPs within short timeframe"
        )
        
        assert result.classification == "lateral_movement"
        assert result.severity == "high"
    
    def test_analyze_suspicious_login(self, analyzer):
        """Test analysis of suspicious login."""
        result = analyzer.analyze_incident(
            alert_description="Suspicious login detected at unusual hour",
            ioc_details="Source IP: 10.0.0.1",
            log_snippet="Login at 3:00 AM"
        )
        
        assert result.classification in ["initial_access", "unknown"]
    
    def test_analyze_unknown_incident(self, analyzer):
        """Test analysis of unknown/generic incident."""
        result = analyzer.analyze_incident(
            alert_description="Generic security alert",
            ioc_details="None",
            log_snippet="Some log entry"
        )
        
        assert result.classification == "unknown"
        assert result.severity == "medium"
        assert len(result.response_steps) > 0
    
    def test_ioc_analysis_with_ip(self, analyzer):
        """Test IOC analysis includes IP information."""
        result = analyzer.analyze_incident(
            alert_description="Test alert",
            ioc_details="Source IP: 192.168.1.100",
            log_snippet="Test log"
        )
        
        assert "IP" in result.ioc_analysis or "ip" in result.ioc_analysis.lower()
    
    def test_ioc_analysis_empty(self, analyzer):
        """Test IOC analysis with no IOCs."""
        result = analyzer.analyze_incident(
            alert_description="Test alert",
            ioc_details="",
            log_snippet="Test log"
        )
        
        assert "no" in result.ioc_analysis.lower() or result.ioc_analysis != ""
    
    def test_confidence_score(self, analyzer):
        """Test that confidence score is reasonable."""
        result = analyzer.analyze_incident(
            alert_description="Brute force attack",
            ioc_details="IP: 192.168.1.100",
            log_snippet="Failed login"
        )
        
        assert 0 <= result.confidence <= 100
    
    def test_response_steps_not_empty(self, analyzer):
        """Test that response steps are provided."""
        result = analyzer.analyze_incident(
            alert_description="Any alert",
            ioc_details="Any IOC",
            log_snippet="Any log"
        )
        
        assert len(result.response_steps) > 0
        assert all(isinstance(step, str) for step in result.response_steps)


class TestAIAnalyzer:
    """Tests for main AI analyzer (without loading model)."""
    
    def test_init_without_loading(self):
        """Test initialization without loading model."""
        analyzer = AIAnalyzer(load_model=False)
        
        assert analyzer._model_loaded is False
        assert analyzer.model is None
        assert analyzer.tokenizer is None
    
    def test_model_name_default(self):
        """Test default model name."""
        analyzer = AIAnalyzer(load_model=False)
        assert analyzer.model_name == "fdtn-ai/Foundation-Sec-8B"
    
    def test_build_prompt(self):
        """Test prompt building."""
        analyzer = AIAnalyzer(load_model=False)
        
        prompt = analyzer._build_prompt(
            alert_description="Test alert",
            ioc_details="Test IOC",
            log_snippet="Test log"
        )
        
        assert "Test alert" in prompt
        assert "Test IOC" in prompt
        assert "Test log" in prompt
        assert "MITRE ATT&CK" in prompt
    
    def test_parse_response_with_summary(self):
        """Test response parsing."""
        analyzer = AIAnalyzer(load_model=False)
        
        response = """
        Summary: This is a test summary
        Classification: credential_access
        Severity: high
        IOC Analysis: Malicious IP detected
        Risk Assessment: High risk to organization
        Response Steps:
        1. Block the IP
        2. Reset passwords
        """
        
        result = analyzer._parse_response(response)
        
        assert "test summary" in result.summary.lower()
        assert result.classification == "credential_access"
        assert result.severity == "high"
    
    def test_analyze_incident_without_model(self):
        """Test analysis returns error when model not loaded."""
        analyzer = AIAnalyzer(load_model=False)
        
        # Mock that load_model fails
        analyzer.load_model = lambda: False
        
        result = analyzer.analyze_incident(
            alert_description="Test",
            ioc_details="Test",
            log_snippet="Test"
        )
        
        assert "unavailable" in result.summary.lower() or "failed" in result.summary.lower()


class TestAnalyzeIncidentFunction:
    """Tests for the module-level analyze_incident function."""
    
    def test_analyze_with_mock_analyzer(self):
        """Test analyze_incident with mock analyzer."""
        mock_analyzer = MockAIAnalyzer()
        
        result = analyze_incident(
            alert_description="Brute force attack detected",
            ioc_details="IP: 192.168.1.100",
            log_snippet="Failed login attempts",
            analyzer=mock_analyzer
        )
        
        assert isinstance(result, AIAnalysisResult)
        assert result.summary != ""


class TestGetAnalyzer:
    """Tests for get_analyzer function."""
    
    def test_get_mock_analyzer(self):
        """Test getting mock analyzer."""
        analyzer = get_analyzer(use_mock=True)
        assert isinstance(analyzer, MockAIAnalyzer)
    
    def test_get_real_analyzer(self):
        """Test getting real analyzer (without loading)."""
        analyzer = get_analyzer(use_mock=False)
        assert isinstance(analyzer, AIAnalyzer)
        assert not analyzer._model_loaded


class TestIncidentClassification:
    """Tests for IncidentClassification enum."""
    
    def test_classification_values(self):
        """Test classification enum values exist."""
        assert IncidentClassification.RECONNAISSANCE.value == "reconnaissance"
        assert IncidentClassification.INITIAL_ACCESS.value == "initial_access"
        assert IncidentClassification.CREDENTIAL_ACCESS.value == "credential_access"
        assert IncidentClassification.LATERAL_MOVEMENT.value == "lateral_movement"
        assert IncidentClassification.UNKNOWN.value == "unknown"
    
    def test_all_mitre_categories(self):
        """Test that major MITRE categories are covered."""
        categories = [c.value for c in IncidentClassification]
        
        expected = [
            "reconnaissance",
            "initial_access",
            "execution",
            "persistence",
            "privilege_escalation",
            "defense_evasion",
            "credential_access",
            "discovery",
            "lateral_movement",
            "collection",
            "exfiltration",
            "command_and_control",
            "impact"
        ]
        
        for exp in expected:
            assert exp in categories


class TestAnalysisIntegration:
    """Integration tests for analysis workflow."""
    
    def test_full_analysis_workflow(self):
        """Test complete analysis workflow with mock."""
        # Create mock analyzer
        analyzer = MockAIAnalyzer()
        
        # Simulate incident data
        incidents = [
            {
                "alert": "Brute force attack detected",
                "ioc": "IP: 192.168.1.100",
                "log_snippet": "Multiple failed logins"
            },
            {
                "alert": "Mimikatz detected",
                "ioc": "Process: mimikatz.exe",
                "log_snippet": "Process creation event"
            }
        ]
        
        # Analyze each incident
        results = []
        for incident in incidents:
            result = analyzer.analyze_incident(
                alert_description=incident["alert"],
                ioc_details=incident["ioc"],
                log_snippet=incident["log_snippet"]
            )
            results.append(result)
        
        # Verify all incidents were analyzed
        assert len(results) == 2
        assert all(isinstance(r, AIAnalysisResult) for r in results)
        
        # Verify results are different based on incident type
        assert results[0].classification != results[1].classification or \
               results[0].severity != results[1].severity


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
