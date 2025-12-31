-- SecureOps Platform Database Schema

-- Assets table (from RMTool)
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL CHECK(category IN ('Hardware', 'Software', 'Data', 'Personnel', 'Facilities')),
    description TEXT,
    criticality INTEGER NOT NULL CHECK(criticality >= 1 AND criticality <= 5),
    value REAL,
    owner TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Threats table
CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Vulnerabilities table
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    description TEXT,
    severity TEXT CHECK(severity IN ('Critical', 'High', 'Medium', 'Low')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Risks table
CREATE TABLE IF NOT EXISTS risks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id INTEGER NOT NULL,
    threat_id INTEGER NOT NULL,
    vulnerability_id INTEGER NOT NULL,
    likelihood INTEGER NOT NULL CHECK(likelihood >= 1 AND likelihood <= 5),
    impact INTEGER NOT NULL CHECK(impact >= 1 AND impact <= 5),
    risk_score INTEGER NOT NULL,
    risk_level TEXT NOT NULL CHECK(risk_level IN ('Critical', 'High', 'Medium', 'Low')),
    description TEXT,
    status TEXT DEFAULT 'Active' CHECK(status IN ('Active', 'Mitigated', 'Accepted', 'Closed')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE,
    FOREIGN KEY (threat_id) REFERENCES threats(id) ON DELETE CASCADE,
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id) ON DELETE CASCADE
);

-- Treatments table
CREATE TABLE IF NOT EXISTS treatments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    risk_id INTEGER NOT NULL,
    treatment_type TEXT NOT NULL CHECK(treatment_type IN ('Mitigate', 'Accept', 'Transfer', 'Avoid')),
    description TEXT NOT NULL,
    owner TEXT,
    status TEXT DEFAULT 'Planned' CHECK(status IN ('Planned', 'In Progress', 'Completed', 'Cancelled')),
    due_date DATE,
    notes TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (risk_id) REFERENCES risks(id) ON DELETE CASCADE
);

-- Incidents table (from Fundamentals)
CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('critical', 'high', 'medium', 'low')),
    status TEXT DEFAULT 'new' CHECK(status IN ('new', 'investigating', 'resolved', 'false_positive')),
    detection_type TEXT,
    source_ips TEXT,
    users TEXT,
    log_snippet TEXT,
    ai_summary TEXT,
    asset_id INTEGER,
    risk_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE SET NULL,
    FOREIGN KEY (risk_id) REFERENCES risks(id) ON DELETE SET NULL
);

-- IOCs (Indicators of Compromise) table
CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('ip', 'domain', 'hash', 'process', 'email', 'url')),
    threat_type TEXT,
    description TEXT,
    confidence REAL CHECK(confidence >= 0 AND confidence <= 1),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Linking tables
CREATE TABLE IF NOT EXISTS incident_assets (
    incident_id INTEGER NOT NULL,
    asset_id INTEGER NOT NULL,
    PRIMARY KEY (incident_id, asset_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY (asset_id) REFERENCES assets(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS incident_risks (
    incident_id INTEGER NOT NULL,
    risk_id INTEGER NOT NULL,
    PRIMARY KEY (incident_id, risk_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY (risk_id) REFERENCES risks(id) ON DELETE CASCADE
);

-- Create indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_risks_asset ON risks(asset_id);
CREATE INDEX IF NOT EXISTS idx_risks_threat ON risks(threat_id);
CREATE INDEX IF NOT EXISTS idx_risks_vulnerability ON risks(vulnerability_id);
CREATE INDEX IF NOT EXISTS idx_risks_level ON risks(risk_level);
CREATE INDEX IF NOT EXISTS idx_treatments_risk ON treatments(risk_id);
CREATE INDEX IF NOT EXISTS idx_treatments_status ON treatments(status);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_asset ON incidents(asset_id);
CREATE INDEX IF NOT EXISTS idx_incidents_risk ON incidents(risk_id);
CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
