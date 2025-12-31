/**
 * Seed Database with Sample Data
 */

const database = require('../config/database');
const { calculateRiskScore, calculateRiskLevel } = require('./riskCalculator');

async function seed() {
    try {
        await database.connect();
        await database.initialize();
        
        console.log('Seeding database with sample data...');
        
        // Sample Assets
        const assets = [
            { name: 'Web Server (Production)', category: 'Hardware', description: 'Main production web server hosting customer-facing applications', criticality: 5, value: 50000, owner: 'IT Operations' },
            { name: 'Database Server', category: 'Hardware', description: 'Primary database server containing customer and financial data', criticality: 5, value: 100000, owner: 'Database Admin' },
            { name: 'Customer CRM System', category: 'Software', description: 'Customer relationship management application', criticality: 4, value: 30000, owner: 'Sales Team' },
            { name: 'Employee Workstations', category: 'Hardware', description: 'Desktop and laptop computers used by employees', criticality: 3, value: 2000, owner: 'IT Support' },
            { name: 'Customer Database', category: 'Data', description: 'Database containing sensitive customer information', criticality: 5, value: 500000, owner: 'Data Protection Officer' },
            { name: 'Financial Records', category: 'Data', description: 'Company financial records and accounting data', criticality: 5, value: 1000000, owner: 'CFO' },
            { name: 'Email Server', category: 'Software', description: 'Corporate email system', criticality: 4, value: 20000, owner: 'IT Operations' },
            { name: 'VPN Gateway', category: 'Hardware', description: 'Virtual private network for remote access', criticality: 4, value: 15000, owner: 'Network Admin' },
            { name: 'Security Personnel', category: 'Personnel', description: 'IT security team members', criticality: 4, value: 0, owner: 'CISO' },
            { name: 'Data Center Facility', category: 'Facilities', description: 'Physical data center location', criticality: 5, value: 2000000, owner: 'Facilities Manager' },
            { name: 'Backup Server', category: 'Hardware', description: 'Backup and disaster recovery server', criticality: 4, value: 40000, owner: 'IT Operations' },
            { name: 'Firewall', category: 'Hardware', description: 'Network security firewall', criticality: 5, value: 25000, owner: 'Network Security' }
        ];
        
        const assetIds = [];
        for (const asset of assets) {
            const result = await database.run(
                'INSERT INTO assets (name, category, description, criticality, value, owner) VALUES (?, ?, ?, ?, ?, ?)',
                [asset.name, asset.category, asset.description, asset.criticality, asset.value, asset.owner]
            );
            assetIds.push(result.id);
        }
        console.log(`✓ Inserted ${assetIds.length} assets`);
        
        // Sample Threats
        const threats = [
            { name: 'SQL Injection', category: 'Application Attack', description: 'Injection of malicious SQL code into application inputs' },
            { name: 'Brute Force Attack', category: 'Authentication Attack', description: 'Automated password guessing attempts' },
            { name: 'DDoS Attack', category: 'Network Attack', description: 'Distributed denial of service attack' },
            { name: 'Ransomware', category: 'Malware', description: 'Malicious software that encrypts data and demands ransom' },
            { name: 'Phishing', category: 'Social Engineering', description: 'Fraudulent emails attempting to steal credentials' },
            { name: 'Insider Threat', category: 'Human Factor', description: 'Malicious or negligent employee actions' },
            { name: 'Zero-Day Exploit', category: 'Vulnerability Exploit', description: 'Attack exploiting unknown software vulnerabilities' },
            { name: 'Data Breach', category: 'Data Theft', description: 'Unauthorized access to sensitive data' },
            { name: 'Man-in-the-Middle', category: 'Network Attack', description: 'Interception of network communications' },
            { name: 'Credential Stuffing', category: 'Authentication Attack', description: 'Using stolen credentials from other breaches' },
            { name: 'Physical Intrusion', category: 'Physical Security', description: 'Unauthorized physical access to facilities' },
            { name: 'Supply Chain Attack', category: 'Third-Party Risk', description: 'Compromise through trusted vendors or suppliers' }
        ];
        
        const threatIds = [];
        for (const threat of threats) {
            const result = await database.run(
                'INSERT INTO threats (name, category, description) VALUES (?, ?, ?)',
                [threat.name, threat.category, threat.description]
            );
            threatIds.push(result.id);
        }
        console.log(`✓ Inserted ${threatIds.length} threats`);
        
        // Sample Vulnerabilities
        const vulnerabilities = [
            { name: 'Outdated Software', category: 'Software', description: 'Running software with known security vulnerabilities', severity: 'High' },
            { name: 'Weak Passwords', category: 'Authentication', description: 'Use of easily guessable passwords', severity: 'High' },
            { name: 'Missing Security Patches', category: 'Software', description: 'Critical security updates not applied', severity: 'Critical' },
            { name: 'Unencrypted Data Storage', category: 'Data Protection', description: 'Sensitive data stored without encryption', severity: 'Critical' },
            { name: 'Open Network Ports', category: 'Network', description: 'Unnecessary network ports left open', severity: 'Medium' },
            { name: 'Lack of MFA', category: 'Authentication', description: 'Multi-factor authentication not implemented', severity: 'High' },
            { name: 'Insufficient Access Controls', category: 'Access Control', description: 'Overly permissive user access rights', severity: 'High' },
            { name: 'No Backup Strategy', category: 'Business Continuity', description: 'Inadequate or missing backup procedures', severity: 'High' },
            { name: 'Poor Physical Security', category: 'Physical', description: 'Inadequate physical access controls', severity: 'Medium' },
            { name: 'Unmonitored Systems', category: 'Monitoring', description: 'Lack of security monitoring and logging', severity: 'Medium' },
            { name: 'SQL Injection Vulnerability', category: 'Application', description: 'Web application vulnerable to SQL injection', severity: 'Critical' },
            { name: 'Cross-Site Scripting (XSS)', category: 'Application', description: 'Web application vulnerable to XSS attacks', severity: 'High' }
        ];
        
        const vulnIds = [];
        for (const vuln of vulnerabilities) {
            const result = await database.run(
                'INSERT INTO vulnerabilities (name, category, description, severity) VALUES (?, ?, ?, ?)',
                [vuln.name, vuln.category, vuln.description, vuln.severity]
            );
            vulnIds.push(result.id);
        }
        console.log(`✓ Inserted ${vulnIds.length} vulnerabilities`);
        
        // Sample Risks (connecting assets, threats, and vulnerabilities)
        const risks = [
            { asset_id: assetIds[0], threat_id: threatIds[0], vulnerability_id: vulnIds[10], likelihood: 4, impact: 5, description: 'Web server vulnerable to SQL injection attacks' },
            { asset_id: assetIds[1], threat_id: threatIds[7], vulnerability_id: vulnIds[3], likelihood: 3, impact: 5, description: 'Database server stores sensitive data without encryption' },
            { asset_id: assetIds[4], threat_id: threatIds[7], vulnerability_id: vulnIds[6], likelihood: 4, impact: 5, description: 'Customer database has insufficient access controls' },
            { asset_id: assetIds[0], threat_id: threatIds[2], vulnerability_id: vulnIds[4], likelihood: 3, impact: 4, description: 'Web server exposed to DDoS attacks due to open ports' },
            { asset_id: assetIds[3], threat_id: threatIds[4], vulnerability_id: vulnIds[1], description: 'Employee workstations vulnerable to phishing due to weak passwords', likelihood: 5, impact: 3 },
            { asset_id: assetIds[6], threat_id: threatIds[1], vulnerability_id: vulnIds[5], likelihood: 4, impact: 4, description: 'Email server lacks MFA for authentication' },
            { asset_id: assetIds[1], threat_id: threatIds[3], vulnerability_id: vulnIds[7], likelihood: 2, impact: 5, description: 'Database server at risk from ransomware due to inadequate backups' },
            { asset_id: assetIds[7], threat_id: threatIds[9], vulnerability_id: vulnIds[1], likelihood: 3, impact: 4, description: 'VPN gateway vulnerable to credential stuffing attacks' },
            { asset_id: assetIds[2], threat_id: threatIds[6], vulnerability_id: vulnIds[0], likelihood: 3, impact: 4, description: 'CRM system running outdated software with known vulnerabilities' },
            { asset_id: assetIds[9], threat_id: threatIds[10], vulnerability_id: vulnIds[8], likelihood: 2, impact: 5, description: 'Data center has poor physical security controls' },
            { asset_id: assetIds[0], threat_id: threatIds[8], vulnerability_id: vulnIds[4], likelihood: 2, impact: 4, description: 'Web server communications vulnerable to MITM attacks' },
            { asset_id: assetIds[5], threat_id: threatIds[5], vulnerability_id: vulnIds[6], likelihood: 2, impact: 5, description: 'Financial records at risk from insider threats' },
            { asset_id: assetIds[11], threat_id: threatIds[6], vulnerability_id: vulnIds[2], likelihood: 3, impact: 5, description: 'Firewall missing critical security patches' },
            { asset_id: assetIds[3], threat_id: threatIds[3], vulnerability_id: vulnIds[0], likelihood: 4, impact: 3, description: 'Workstations at risk from ransomware due to outdated software' },
            { asset_id: assetIds[8], threat_id: threatIds[5], vulnerability_id: vulnIds[6], likelihood: 3, impact: 4, description: 'Security personnel access rights not properly managed' }
        ];
        
        const riskIds = [];
        for (const risk of risks) {
            const riskScore = calculateRiskScore(risk.likelihood, risk.impact);
            const riskLevel = calculateRiskLevel(riskScore);
            
            const result = await database.run(
                'INSERT INTO risks (asset_id, threat_id, vulnerability_id, likelihood, impact, risk_score, risk_level, description, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [risk.asset_id, risk.threat_id, risk.vulnerability_id, risk.likelihood, risk.impact, riskScore, riskLevel, risk.description, 'Active']
            );
            riskIds.push(result.id);
        }
        console.log(`✓ Inserted ${riskIds.length} risks`);
        
        // Sample Treatments
        const treatments = [
            { risk_id: riskIds[0], treatment_type: 'Mitigate', description: 'Implement input validation and parameterized queries', owner: 'Development Team', status: 'In Progress', due_date: '2024-02-15', notes: 'Code review scheduled' },
            { risk_id: riskIds[1], treatment_type: 'Mitigate', description: 'Enable database encryption at rest', owner: 'Database Admin', status: 'Planned', due_date: '2024-02-28', notes: 'Requires maintenance window' },
            { risk_id: riskIds[2], treatment_type: 'Mitigate', description: 'Implement role-based access control (RBAC)', owner: 'Security Team', status: 'In Progress', due_date: '2024-01-31', notes: 'Phase 1 of 3 complete' },
            { risk_id: riskIds[3], treatment_type: 'Mitigate', description: 'Deploy DDoS protection service', owner: 'Network Team', status: 'Planned', due_date: '2024-03-15', notes: 'Vendor evaluation in progress' },
            { risk_id: riskIds[4], treatment_type: 'Mitigate', description: 'Conduct security awareness training', owner: 'HR Department', status: 'Completed', due_date: '2024-01-15', notes: '95% completion rate' },
            { risk_id: riskIds[5], treatment_type: 'Mitigate', description: 'Enable MFA for all email accounts', owner: 'IT Operations', status: 'In Progress', due_date: '2024-02-01', notes: '60% rollout complete' },
            { risk_id: riskIds[6], treatment_type: 'Mitigate', description: 'Implement automated backup solution', owner: 'IT Operations', status: 'Planned', due_date: '2024-02-20', notes: 'Budget approved' },
            { risk_id: riskIds[7], treatment_type: 'Accept', description: 'Accept risk with increased monitoring', owner: 'CISO', status: 'Completed', due_date: '2024-01-10', notes: 'Risk within tolerance' },
            { risk_id: riskIds[8], treatment_type: 'Mitigate', description: 'Update CRM system to latest version', owner: 'IT Operations', status: 'Planned', due_date: '2024-03-01', notes: 'Testing in progress' },
            { risk_id: riskIds[9], treatment_type: 'Mitigate', description: 'Install badge access system and cameras', owner: 'Facilities Manager', status: 'In Progress', due_date: '2024-02-28', notes: 'Installation 50% complete' }
        ];
        
        for (const treatment of treatments) {
            await database.run(
                'INSERT INTO treatments (risk_id, treatment_type, description, owner, status, due_date, notes) VALUES (?, ?, ?, ?, ?, ?, ?)',
                [treatment.risk_id, treatment.treatment_type, treatment.description, treatment.owner, treatment.status, treatment.due_date, treatment.notes]
            );
        }
        console.log(`✓ Inserted ${treatments.length} treatments`);
        
        // Sample Incidents
        const incidents = [
            { alert: 'Brute force attack detected from 192.168.1.100', severity: 'high', status: 'investigating', detection_type: 'brute_force', source_ips: '192.168.1.100', users: 'root,admin,user', log_snippet: 'Failed password attempts', asset_id: assetIds[0], timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString() },
            { alert: 'Suspicious login during off-hours', severity: 'medium', status: 'new', detection_type: 'suspicious_hours', source_ips: '10.0.0.50', users: 'jsmith', log_snippet: 'Login at 02:30 AM', asset_id: assetIds[6], timestamp: new Date(Date.now() - 5 * 60 * 60 * 1000).toISOString() },
            { alert: 'Multiple failed login attempts for admin account', severity: 'high', status: 'resolved', detection_type: 'privileged_access', source_ips: '203.0.113.42', users: 'administrator', log_snippet: '15 failed attempts', asset_id: assetIds[1], timestamp: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString() },
            { alert: 'Possible user enumeration attack detected', severity: 'medium', status: 'investigating', detection_type: 'user_enumeration', source_ips: '198.51.100.23', users: 'user1,user2,user3,user4,user5', log_snippet: 'Multiple username attempts', asset_id: assetIds[7], timestamp: new Date(Date.now() - 12 * 60 * 60 * 1000).toISOString() },
            { alert: 'SQL injection attempt detected', severity: 'critical', status: 'resolved', detection_type: 'sql_injection', source_ips: '172.16.0.99', users: 'anonymous', log_snippet: "' OR '1'='1' --", asset_id: assetIds[0], risk_id: riskIds[0], timestamp: new Date(Date.now() - 48 * 60 * 60 * 1000).toISOString() },
            { alert: 'Unusual data access pattern detected', severity: 'high', status: 'investigating', detection_type: 'data_exfiltration', source_ips: '10.0.1.25', users: 'dbuser', log_snippet: 'Large data query executed', asset_id: assetIds[1], timestamp: new Date(Date.now() - 6 * 60 * 60 * 1000).toISOString() },
            { alert: 'Failed VPN authentication attempts', severity: 'medium', status: 'new', detection_type: 'brute_force', source_ips: '203.0.113.89', users: 'vpnuser', log_snippet: '8 failed attempts', asset_id: assetIds[7], timestamp: new Date(Date.now() - 3 * 60 * 60 * 1000).toISOString() },
            { alert: 'Port scan detected', severity: 'medium', status: 'resolved', detection_type: 'reconnaissance', source_ips: '198.51.100.50', users: 'N/A', log_snippet: 'Scanning ports 1-1000', asset_id: assetIds[11], timestamp: new Date(Date.now() - 36 * 60 * 60 * 1000).toISOString() },
            { alert: 'Malware signature detected in email', severity: 'high', status: 'resolved', detection_type: 'malware', source_ips: 'external', users: 'employee@company.com', log_snippet: 'Trojan.Generic.12345', asset_id: assetIds[6], timestamp: new Date(Date.now() - 18 * 60 * 60 * 1000).toISOString() },
            { alert: 'Unauthorized access attempt to data center', severity: 'critical', status: 'investigating', detection_type: 'physical_security', source_ips: 'N/A', users: 'unknown', log_snippet: 'Badge access denied', asset_id: assetIds[9], timestamp: new Date(Date.now() - 8 * 60 * 60 * 1000).toISOString() }
        ];
        
        for (const incident of incidents) {
            await database.run(
                'INSERT INTO incidents (alert, severity, status, detection_type, source_ips, users, log_snippet, asset_id, risk_id, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                [incident.alert, incident.severity, incident.status, incident.detection_type, incident.source_ips, incident.users, incident.log_snippet, incident.asset_id, incident.risk_id || null, incident.timestamp]
            );
        }
        console.log(`✓ Inserted ${incidents.length} incidents`);
        
        // Sample IOCs
        const iocs = [
            { value: '192.168.1.100', type: 'ip', threat_type: 'brute_force', description: 'Known attacker IP', confidence: 0.9 },
            { value: '203.0.113.42', type: 'ip', threat_type: 'brute_force', description: 'Repeated failed login attempts', confidence: 0.85 },
            { value: 'malware.example.com', type: 'domain', threat_type: 'c2_server', description: 'Command and control server', confidence: 0.95 },
            { value: '44d88612fea8a8f36de82e1278abb02f', type: 'hash', threat_type: 'malware', description: 'Known malware hash', confidence: 0.99 },
            { value: 'suspicious.exe', type: 'process', threat_type: 'malware', description: 'Suspicious process name', confidence: 0.7 }
        ];
        
        for (const ioc of iocs) {
            await database.run(
                'INSERT INTO iocs (value, type, threat_type, description, confidence) VALUES (?, ?, ?, ?, ?)',
                [ioc.value, ioc.type, ioc.threat_type, ioc.description, ioc.confidence]
            );
        }
        console.log(`✓ Inserted ${iocs.length} IOCs`);
        
        console.log('\n✅ Database seeding completed successfully!');
        
        await database.close();
    } catch (error) {
        console.error('Error seeding database:', error);
        process.exit(1);
    }
}

// Run seed if called directly
if (require.main === module) {
    seed();
}

module.exports = seed;
