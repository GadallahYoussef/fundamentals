"""
AI Analysis Module
==================
AI-powered incident analysis using Hugging Face Foundation-Sec-8B model.

This module provides:
- Integration with the fdtn-ai/Foundation-Sec-8B model
- Structured incident analysis with security context
- Classification, severity assessment, and response recommendations
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from enum import Enum
import re

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Model configuration
MODEL_NAME = "fdtn-ai/Foundation-Sec-8B"
DEFAULT_MAX_LENGTH = 2048
DEFAULT_TEMPERATURE = 0.7


class IncidentClassification(Enum):
    """Classification categories for security incidents."""
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"
    UNKNOWN = "unknown"


@dataclass
class AIAnalysisResult:
    """
    Structured result from AI incident analysis.
    
    Attributes:
        summary: Human-readable summary of the incident
        classification: MITRE ATT&CK-style classification
        severity: Assessed severity (low, medium, high, critical)
        confidence: Confidence score of the analysis (0-100)
        response_steps: List of recommended incident response steps
        ioc_analysis: Analysis of provided IOCs
        risk_assessment: Overall risk assessment
        additional_context: Any additional relevant context
        raw_response: Raw model output for debugging
    """
    summary: str = ""
    classification: str = "unknown"
    severity: str = "medium"
    confidence: int = 0
    response_steps: List[str] = field(default_factory=list)
    ioc_analysis: str = ""
    risk_assessment: str = ""
    additional_context: str = ""
    raw_response: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'summary': self.summary,
            'classification': self.classification,
            'severity': self.severity,
            'confidence': self.confidence,
            'response_steps': self.response_steps,
            'ioc_analysis': self.ioc_analysis,
            'risk_assessment': self.risk_assessment,
            'additional_context': self.additional_context,
        }
    
    def to_formatted_string(self) -> str:
        """Convert result to formatted string for display."""
        lines = [
            "=" * 60,
            "AI INCIDENT ANALYSIS REPORT",
            "=" * 60,
            "",
            f"📋 SUMMARY:",
            f"   {self.summary}",
            "",
            f"🏷️  CLASSIFICATION: {self.classification}",
            f"⚠️  SEVERITY: {self.severity.upper()}",
            f"📊 CONFIDENCE: {self.confidence}%",
            "",
            "🔍 IOC ANALYSIS:",
            f"   {self.ioc_analysis}",
            "",
            "⚡ RISK ASSESSMENT:",
            f"   {self.risk_assessment}",
            "",
            "📝 RECOMMENDED RESPONSE STEPS:",
        ]
        
        for i, step in enumerate(self.response_steps, 1):
            lines.append(f"   {i}. {step}")
        
        if self.additional_context:
            lines.extend([
                "",
                "ℹ️  ADDITIONAL CONTEXT:",
                f"   {self.additional_context}",
            ])
        
        lines.append("")
        lines.append("=" * 60)
        
        return "\n".join(lines)


class AIAnalyzer:
    """
    AI-powered security incident analyzer.
    
    Uses the Foundation-Sec-8B model for cybersecurity-focused analysis.
    """
    
    def __init__(
        self,
        model_name: str = MODEL_NAME,
        device: str = "auto",
        max_length: int = DEFAULT_MAX_LENGTH,
        temperature: float = DEFAULT_TEMPERATURE,
        load_model: bool = True
    ):
        """
        Initialize the AI analyzer.
        
        Args:
            model_name: Hugging Face model name/path
            device: Device to use ('auto', 'cpu', 'cuda', 'cuda:0', etc.)
            max_length: Maximum generation length
            temperature: Sampling temperature
            load_model: Whether to load the model immediately
        """
        self.model_name = model_name
        self.device = device
        self.max_length = max_length
        self.temperature = temperature
        
        self.model = None
        self.tokenizer = None
        self.pipeline = None
        self._model_loaded = False
        
        if load_model:
            self.load_model()
    
    def load_model(self) -> bool:
        """
        Load the AI model and tokenizer.
        
        Returns:
            True if loaded successfully, False otherwise
        """
        if self._model_loaded:
            logger.info("Model already loaded")
            return True
        
        try:
            logger.info(f"Loading model: {self.model_name}")
            logger.info("This may take several minutes on first run...")
            
            from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline
            import torch
            
            # Determine device
            if self.device == "auto":
                if torch.cuda.is_available():
                    device = "cuda"
                    logger.info(f"Using GPU: {torch.cuda.get_device_name(0)}")
                else:
                    device = "cpu"
                    logger.info("Using CPU (GPU not available)")
            else:
                device = self.device
            
            # Load tokenizer
            logger.info("Loading tokenizer...")
            self.tokenizer = AutoTokenizer.from_pretrained(
                self.model_name,
                trust_remote_code=True
            )
            
            # Set padding token if not set
            if self.tokenizer.pad_token is None:
                self.tokenizer.pad_token = self.tokenizer.eos_token
            
            # Load model with appropriate settings
            logger.info("Loading model weights...")
            
            # Determine dtype based on device
            if device == "cuda":
                dtype = torch.float16  # Use half precision for GPU
            else:
                dtype = torch.float32
            
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_name,
                torch_dtype=dtype,
                device_map=device if device == "cuda" else None,
                trust_remote_code=True,
                low_cpu_mem_usage=True
            )
            
            if device == "cpu":
                self.model = self.model.to(device)
            
            # Create pipeline
            self.pipeline = pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                device=0 if device == "cuda" else -1,
                max_length=self.max_length,
                temperature=self.temperature,
                do_sample=True,
                top_p=0.9,
                repetition_penalty=1.1,
                pad_token_id=self.tokenizer.eos_token_id
            )
            
            self._model_loaded = True
            logger.info("Model loaded successfully!")
            
            return True
            
        except ImportError as e:
            logger.error(f"Missing required packages. Please install: pip install transformers torch")
            logger.error(f"Import error: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            logger.error("Make sure you have enough memory and the model is accessible")
            return False
    
    def _build_prompt(
        self,
        alert_description: str,
        ioc_details: str,
        log_snippet: str
    ) -> str:
        """
        Build the analysis prompt for the model.
        
        Args:
            alert_description: Description of the alert/incident
            ioc_details: Indicators of Compromise details
            log_snippet: Relevant log entries
            
        Returns:
            Formatted prompt string
        """
        prompt = f"""You are a cybersecurity incident response analyst. Analyze the following security incident and provide a structured response.

## INCIDENT DETAILS

### Alert Description:
{alert_description}

### Indicators of Compromise (IOCs):
{ioc_details if ioc_details else "None provided"}

### Relevant Log Entries:
```
{log_snippet if log_snippet else "No log entries available"}
```

## ANALYSIS REQUEST

Please analyze this security incident and provide:

1. **Summary**: A concise human-readable summary of what occurred (2-3 sentences)

2. **Classification**: Classify this incident using MITRE ATT&CK framework categories:
   - reconnaissance, initial_access, execution, persistence, privilege_escalation
   - defense_evasion, credential_access, discovery, lateral_movement
   - collection, exfiltration, command_and_control, impact, or unknown

3. **Severity**: Assess the severity level (low, medium, high, or critical)

4. **IOC Analysis**: Brief analysis of the provided IOCs and their significance

5. **Risk Assessment**: Overall risk to the organization

6. **Response Steps**: List 3-5 specific incident response steps to take

Provide your analysis in a clear, structured format:

### Analysis:
"""
        return prompt
    
    def _parse_response(self, response_text: str) -> AIAnalysisResult:
        """
        Parse the model's response into structured format.
        
        Args:
            response_text: Raw model output
            
        Returns:
            Structured AIAnalysisResult
        """
        result = AIAnalysisResult(raw_response=response_text)
        
        try:
            # Extract summary
            summary_match = re.search(
                r'(?:Summary|SUMMARY)[:\s]*\n*([^\n#*]+(?:\n[^\n#*]+)*)',
                response_text,
                re.IGNORECASE
            )
            if summary_match:
                result.summary = summary_match.group(1).strip()
            
            # Extract classification
            class_match = re.search(
                r'(?:Classification|CLASSIFICATION)[:\s]*\n*(\w+)',
                response_text,
                re.IGNORECASE
            )
            if class_match:
                classification = class_match.group(1).lower().strip()
                # Validate against known classifications
                valid_classifications = [c.value for c in IncidentClassification]
                if classification in valid_classifications:
                    result.classification = classification
                else:
                    result.classification = "unknown"
            
            # Extract severity
            severity_match = re.search(
                r'(?:Severity|SEVERITY)[:\s]*\n*(low|medium|high|critical)',
                response_text,
                re.IGNORECASE
            )
            if severity_match:
                result.severity = severity_match.group(1).lower()
            
            # Extract IOC analysis
            ioc_match = re.search(
                r'(?:IOC Analysis|IOC ANALYSIS)[:\s]*\n*([^\n#]+(?:\n[^\n#]+)*)',
                response_text,
                re.IGNORECASE
            )
            if ioc_match:
                result.ioc_analysis = ioc_match.group(1).strip()
            
            # Extract risk assessment
            risk_match = re.search(
                r'(?:Risk Assessment|RISK ASSESSMENT)[:\s]*\n*([^\n#]+(?:\n[^\n#]+)*)',
                response_text,
                re.IGNORECASE
            )
            if risk_match:
                result.risk_assessment = risk_match.group(1).strip()
            
            # Extract response steps
            steps_section = re.search(
                r'(?:Response Steps|RESPONSE STEPS|Recommended.*Steps)[:\s]*\n*((?:\d+\.|[-*])[^\n]+(?:\n(?:\d+\.|[-*])[^\n]+)*)',
                response_text,
                re.IGNORECASE
            )
            if steps_section:
                steps_text = steps_section.group(1)
                steps = re.findall(r'(?:\d+\.|[-*])\s*([^\n]+)', steps_text)
                result.response_steps = [step.strip() for step in steps if step.strip()]
            
            # Calculate confidence based on completeness
            confidence = 0
            if result.summary:
                confidence += 25
            if result.classification != "unknown":
                confidence += 25
            if result.response_steps:
                confidence += 25
            if result.ioc_analysis or result.risk_assessment:
                confidence += 25
            result.confidence = confidence
            
            # If we couldn't parse well, use the raw response as summary
            if not result.summary and response_text:
                # Take first meaningful paragraph
                paragraphs = response_text.split('\n\n')
                for para in paragraphs:
                    clean_para = para.strip()
                    if clean_para and len(clean_para) > 50 and not clean_para.startswith('#'):
                        result.summary = clean_para[:500]
                        break
            
        except Exception as e:
            logger.warning(f"Error parsing response: {e}")
            result.summary = response_text[:500] if response_text else "Analysis failed"
        
        return result
    
    def analyze_incident(
        self,
        alert_description: str,
        ioc_details: str,
        log_snippet: str
    ) -> AIAnalysisResult:
        """
        Analyze a security incident using AI.
        
        This is the main function that takes incident details and returns
        a structured analysis including summary, classification, severity,
        and recommended response steps.
        
        Args:
            alert_description: Human-readable description of the alert
            ioc_details: Comma-separated or formatted IOC details
            log_snippet: Relevant log entries as a string
            
        Returns:
            AIAnalysisResult with structured analysis
        """
        if not self._model_loaded:
            logger.warning("Model not loaded. Attempting to load...")
            if not self.load_model():
                return AIAnalysisResult(
                    summary="AI analysis unavailable - model failed to load",
                    classification="unknown",
                    severity="medium",
                    response_steps=["Manual analysis required - AI model not available"]
                )
        
        try:
            # Build prompt
            prompt = self._build_prompt(alert_description, ioc_details, log_snippet)
            
            logger.info("Generating AI analysis...")
            
            # Generate response
            outputs = self.pipeline(
                prompt,
                max_new_tokens=1024,
                num_return_sequences=1,
                return_full_text=False
            )
            
            response_text = outputs[0]['generated_text']
            
            # Parse and structure the response
            result = self._parse_response(response_text)
            
            logger.info(f"Analysis complete. Classification: {result.classification}, Severity: {result.severity}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error during analysis: {e}")
            return AIAnalysisResult(
                summary=f"Analysis error: {str(e)}",
                classification="unknown",
                severity="medium",
                response_steps=["Manual analysis required due to AI error"],
                raw_response=str(e)
            )
    
    def analyze_incident_batch(
        self,
        incidents: List[Dict[str, str]]
    ) -> List[AIAnalysisResult]:
        """
        Analyze multiple incidents.
        
        Args:
            incidents: List of dicts with 'alert', 'ioc', 'log_snippet' keys
            
        Returns:
            List of AIAnalysisResult objects
        """
        results = []
        
        for i, incident in enumerate(incidents):
            logger.info(f"Analyzing incident {i+1}/{len(incidents)}...")
            result = self.analyze_incident(
                alert_description=incident.get('alert', ''),
                ioc_details=incident.get('ioc', ''),
                log_snippet=incident.get('log_snippet', '')
            )
            results.append(result)
        
        return results


# Module-level convenience function
def analyze_incident(
    alert_description: str,
    ioc_details: str,
    log_snippet: str,
    analyzer: Optional[AIAnalyzer] = None
) -> AIAnalysisResult:
    """
    Analyze a security incident using AI.
    
    This is the main entry point for incident analysis. It takes three string
    inputs describing the incident and returns a structured analysis.
    
    Args:
        alert_description: Human-readable description of the security alert
        ioc_details: Details about Indicators of Compromise (IPs, domains, hashes, etc.)
        log_snippet: Relevant log entries that triggered or relate to the alert
        analyzer: Optional AIAnalyzer instance (creates new one if not provided)
        
    Returns:
        AIAnalysisResult containing:
        - summary: Human-readable summary of the analysis
        - classification: MITRE ATT&CK-style classification
        - severity: Assessed severity level (low, medium, high, critical)
        - confidence: Confidence score (0-100)
        - response_steps: List of recommended incident response actions
        - ioc_analysis: Analysis of the provided IOCs
        - risk_assessment: Overall risk assessment
        
    Example:
        >>> result = analyze_incident(
        ...     alert_description="Multiple failed SSH login attempts detected",
        ...     ioc_details="Source IP: 192.168.1.100",
        ...     log_snippet="Dec 27 10:30:45 server sshd[1234]: Failed password for root..."
        ... )
        >>> print(result.summary)
        >>> print(result.severity)
        >>> for step in result.response_steps:
        ...     print(f"- {step}")
    """
    if analyzer is None:
        analyzer = AIAnalyzer(load_model=True)
    
    return analyzer.analyze_incident(alert_description, ioc_details, log_snippet)


# Lightweight mock analyzer for testing without GPU
class MockAIAnalyzer:
    """
    Mock AI analyzer for testing without loading the actual model.
    
    Provides realistic-looking responses without requiring GPU or
    downloading the large model.
    """
    
    def __init__(self):
        """Initialize mock analyzer."""
        self._model_loaded = True
    
    def load_model(self) -> bool:
        """Mock load - always succeeds."""
        return True
    
    def analyze_incident(
        self,
        alert_description: str,
        ioc_details: str,
        log_snippet: str
    ) -> AIAnalysisResult:
        """
        Generate a mock analysis based on keyword matching.
        
        Args:
            alert_description: Alert description
            ioc_details: IOC details
            log_snippet: Log snippet
            
        Returns:
            Mock AIAnalysisResult
        """
        # Determine classification and severity based on keywords
        text = f"{alert_description} {ioc_details} {log_snippet}".lower()
        
        # Classification logic
        if "brute force" in text or "failed login" in text or "failed password" in text:
            classification = "credential_access"
            severity = "high" if "root" in text or "admin" in text else "medium"
            summary = "Brute force attack detected targeting user authentication."
            steps = [
                "Block the source IP address at the firewall",
                "Review all recent authentication attempts from this IP",
                "Check if any successful logins occurred from this source",
                "Implement account lockout policies if not already in place",
                "Consider implementing fail2ban or similar intrusion prevention"
            ]
        elif "mimikatz" in text or "credential" in text or "password dump" in text:
            classification = "credential_access"
            severity = "critical"
            summary = "Credential theft tool detected, indicating potential compromise."
            steps = [
                "Isolate affected systems immediately",
                "Force password reset for all potentially affected accounts",
                "Review and revoke any suspicious sessions",
                "Scan for lateral movement indicators",
                "Engage incident response team for full investigation"
            ]
        elif "lateral" in text or "multiple ip" in text:
            classification = "lateral_movement"
            severity = "high"
            summary = "Potential lateral movement detected across network."
            steps = [
                "Map all systems accessed by the suspicious account",
                "Review network traffic between affected systems",
                "Check for unauthorized service accounts or scheduled tasks",
                "Implement network segmentation if possible"
            ]
        elif "suspicious" in text and "login" in text:
            classification = "initial_access"
            severity = "medium"
            summary = "Suspicious login activity detected requiring investigation."
            steps = [
                "Verify the login with the user if possible",
                "Review the source IP reputation",
                "Check for any follow-up suspicious activity",
                "Document findings in incident tracking system"
            ]
        elif "process" in text or "execution" in text or "command" in text:
            classification = "execution"
            severity = "high" if "powershell" in text or "curl" in text else "medium"
            summary = "Suspicious process execution detected that may indicate malicious activity."
            steps = [
                "Capture process details and command line arguments",
                "Check parent process chain",
                "Review file system changes during execution",
                "Collect memory dump if process is still running"
            ]
        else:
            classification = "unknown"
            severity = "medium"
            summary = "Security incident detected requiring further analysis."
            steps = [
                "Collect additional context and logs",
                "Determine scope of potential impact",
                "Document all findings",
                "Escalate to senior analyst if needed"
            ]
        
        # Build IOC analysis
        ioc_analysis = "IOC analysis: "
        if ioc_details:
            if "ip" in ioc_details.lower():
                ioc_analysis += "Source IP identified - recommend blocking and reputation check. "
            if any(x in ioc_details.lower() for x in ['domain', 'url', 'http']):
                ioc_analysis += "Potentially malicious domain/URL detected. "
            if any(x in ioc_details.lower() for x in ['hash', 'md5', 'sha']):
                ioc_analysis += "File hash identified - check against threat intelligence. "
        else:
            ioc_analysis += "No specific IOCs provided."
        
        return AIAnalysisResult(
            summary=summary,
            classification=classification,
            severity=severity,
            confidence=85,
            response_steps=steps,
            ioc_analysis=ioc_analysis,
            risk_assessment=f"Risk level assessed as {severity} based on attack type and potential impact.",
            additional_context="This analysis was generated by the mock analyzer for testing purposes.",
            raw_response="[Mock response]"
        )


def get_analyzer(use_mock: bool = False) -> AIAnalyzer:
    """
    Get an AI analyzer instance.
    
    Args:
        use_mock: If True, returns a mock analyzer for testing
        
    Returns:
        AIAnalyzer or MockAIAnalyzer instance
    """
    if use_mock:
        return MockAIAnalyzer()
    return AIAnalyzer(load_model=False)  # Don't load until needed
