"""
AI Analyzer Microservice for SecureOps Platform
Mock AI analysis service for incident classification and recommendations
"""

from flask import Flask, request, jsonify
import json
from datetime import datetime

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze_incident():
    """
    Analyze an incident and return AI-powered insights
    """
    try:
        data = request.json
        incident = data.get('incident', {})
        
        # Mock AI analysis (in production, this would use ML models)
        analysis = {
            'incident_id': incident.get('id'),
            'timestamp': datetime.utcnow().isoformat(),
            'summary': f"Automated analysis of {incident.get('detection_type', 'security')} incident",
            'severity_assessment': incident.get('severity', 'medium'),
            'attack_classification': classify_attack(incident),
            'recommended_actions': get_recommendations(incident),
            'mitre_attack': get_mitre_mapping(incident),
            'confidence': 0.85,
            'threat_score': calculate_threat_score(incident),
            'affected_systems': identify_affected_systems(incident),
            'indicators': extract_indicators(incident)
        }
        
        return jsonify(analysis), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def classify_attack(incident):
    """Classify the type of attack based on incident data"""
    detection_type = incident.get('detection_type', '')
    
    classifications = {
        'brute_force': 'Brute Force Attack',
        'suspicious_hours': 'Off-Hours Access',
        'privileged_access': 'Privileged Account Compromise',
        'user_enumeration': 'User Enumeration',
        'sql_injection': 'SQL Injection Attack',
        'data_exfiltration': 'Data Exfiltration',
        'malware': 'Malware Detection',
        'reconnaissance': 'Network Reconnaissance'
    }
    
    return classifications.get(detection_type, 'Unknown Attack Type')

def get_recommendations(incident):
    """Get recommended actions based on incident type"""
    detection_type = incident.get('detection_type', '')
    
    recommendations = {
        'brute_force': [
            'Block source IP address immediately',
            'Enforce account lockout policy',
            'Enable multi-factor authentication',
            'Review password policies'
        ],
        'suspicious_hours': [
            'Verify user identity',
            'Check for compromised credentials',
            'Review access logs',
            'Implement time-based access controls'
        ],
        'privileged_access': [
            'Immediately reset privileged account credentials',
            'Audit all recent privileged operations',
            'Enable privileged access management (PAM)',
            'Investigate potential lateral movement'
        ],
        'sql_injection': [
            'Apply input validation and sanitization',
            'Use parameterized queries',
            'Conduct code review',
            'Deploy web application firewall (WAF)'
        ],
        'default': [
            'Investigate source IP address',
            'Review related log entries',
            'Check for similar patterns',
            'Update security rules if needed'
        ]
    }
    
    return recommendations.get(detection_type, recommendations['default'])

def get_mitre_mapping(incident):
    """Map incident to MITRE ATT&CK framework"""
    detection_type = incident.get('detection_type', '')
    
    mitre_mappings = {
        'brute_force': {
            'tactics': ['Credential Access'],
            'techniques': ['T1110 - Brute Force', 'T1110.001 - Password Guessing']
        },
        'privileged_access': {
            'tactics': ['Privilege Escalation', 'Credential Access'],
            'techniques': ['T1078 - Valid Accounts', 'T1078.003 - Local Accounts']
        },
        'sql_injection': {
            'tactics': ['Initial Access', 'Execution'],
            'techniques': ['T1190 - Exploit Public-Facing Application']
        },
        'data_exfiltration': {
            'tactics': ['Exfiltration'],
            'techniques': ['T1041 - Exfiltration Over C2 Channel']
        }
    }
    
    return mitre_mappings.get(detection_type, {
        'tactics': ['Initial Access'],
        'techniques': ['T1078 - Valid Accounts']
    })

def calculate_threat_score(incident):
    """Calculate numerical threat score (0-10)"""
    severity_scores = {
        'critical': 10,
        'high': 7,
        'medium': 5,
        'low': 3
    }
    
    base_score = severity_scores.get(incident.get('severity', 'medium'), 5)
    
    # Adjust based on detection type
    if incident.get('detection_type') == 'brute_force':
        base_score += 1
    elif incident.get('detection_type') == 'privileged_access':
        base_score += 2
    
    return min(base_score, 10)

def identify_affected_systems(incident):
    """Identify systems potentially affected by the incident"""
    systems = []
    
    if incident.get('asset_name'):
        systems.append(incident['asset_name'])
    
    if incident.get('source_ips'):
        systems.extend(incident['source_ips'].split(','))
    
    return systems[:5]  # Limit to 5 systems

def extract_indicators(incident):
    """Extract indicators of compromise (IOCs)"""
    indicators = {
        'ips': [],
        'users': [],
        'processes': []
    }
    
    if incident.get('source_ips'):
        indicators['ips'] = incident['source_ips'].split(',')
    
    if incident.get('users'):
        indicators['users'] = incident['users'].split(',')
    
    return indicators

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'AI Analyzer',
        'timestamp': datetime.utcnow().isoformat()
    }), 200

if __name__ == '__main__':
    print("🤖 Starting AI Analyzer Microservice...")
    print("📡 Listening on http://localhost:5001")
    app.run(host='0.0.0.0', port=5001, debug=True)
