/**
 * Incident Controller
 * Handles CRUD operations for incidents
 */

const database = require('../config/database');

async function getAllIncidents(req, res) {
    try {
        const incidents = await database.all(`
            SELECT 
                i.*,
                a.name as asset_name,
                r.description as risk_description,
                r.risk_level
            FROM incidents i
            LEFT JOIN assets a ON i.asset_id = a.id
            LEFT JOIN risks r ON i.risk_id = r.id
            ORDER BY i.timestamp DESC
        `);
        res.json(incidents);
    } catch (error) {
        console.error('Error fetching incidents:', error);
        res.status(500).json({ error: 'Failed to fetch incidents' });
    }
}

async function getIncidentById(req, res) {
    try {
        const { id } = req.params;
        const incident = await database.get(`
            SELECT 
                i.*,
                a.name as asset_name,
                a.criticality as asset_criticality,
                r.description as risk_description,
                r.risk_level
            FROM incidents i
            LEFT JOIN assets a ON i.asset_id = a.id
            LEFT JOIN risks r ON i.risk_id = r.id
            WHERE i.id = ?
        `, [id]);
        
        if (!incident) {
            return res.status(404).json({ error: 'Incident not found' });
        }
        
        res.json(incident);
    } catch (error) {
        console.error('Error fetching incident:', error);
        res.status(500).json({ error: 'Failed to fetch incident' });
    }
}

async function createIncident(req, res) {
    try {
        const { alert, severity, status, detection_type, source_ips, users, log_snippet, ai_summary, asset_id, risk_id, timestamp } = req.body;
        
        if (!alert || !severity) {
            return res.status(400).json({ error: 'Alert and severity are required' });
        }
        
        const validSeverities = ['critical', 'high', 'medium', 'low'];
        if (!validSeverities.includes(severity)) {
            return res.status(400).json({ error: 'Invalid severity level' });
        }
        
        const result = await database.run(
            `INSERT INTO incidents (alert, severity, status, detection_type, source_ips, users, log_snippet, ai_summary, asset_id, risk_id, timestamp) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [alert, severity, status || 'new', detection_type || null, source_ips || null, users || null, 
             log_snippet || null, ai_summary || null, asset_id || null, risk_id || null, timestamp || new Date().toISOString()]
        );
        
        const newIncident = await database.get(`
            SELECT 
                i.*,
                a.name as asset_name
            FROM incidents i
            LEFT JOIN assets a ON i.asset_id = a.id
            WHERE i.id = ?
        `, [result.id]);
        
        res.status(201).json(newIncident);
    } catch (error) {
        console.error('Error creating incident:', error);
        res.status(500).json({ error: 'Failed to create incident' });
    }
}

async function updateIncident(req, res) {
    try {
        const { id } = req.params;
        const { alert, severity, status, detection_type, source_ips, users, log_snippet, ai_summary, asset_id, risk_id } = req.body;
        
        const existing = await database.get('SELECT * FROM incidents WHERE id = ?', [id]);
        if (!existing) {
            return res.status(404).json({ error: 'Incident not found' });
        }
        
        const validSeverities = ['critical', 'high', 'medium', 'low'];
        if (severity && !validSeverities.includes(severity)) {
            return res.status(400).json({ error: 'Invalid severity level' });
        }
        
        const validStatuses = ['new', 'investigating', 'resolved', 'false_positive'];
        if (status && !validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        await database.run(
            `UPDATE incidents SET 
                alert = COALESCE(?, alert),
                severity = COALESCE(?, severity),
                status = COALESCE(?, status),
                detection_type = COALESCE(?, detection_type),
                source_ips = COALESCE(?, source_ips),
                users = COALESCE(?, users),
                log_snippet = COALESCE(?, log_snippet),
                ai_summary = COALESCE(?, ai_summary),
                asset_id = COALESCE(?, asset_id),
                risk_id = COALESCE(?, risk_id),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?`,
            [alert, severity, status, detection_type, source_ips, users, log_snippet, ai_summary, asset_id, risk_id, id]
        );
        
        const updated = await database.get(`
            SELECT 
                i.*,
                a.name as asset_name
            FROM incidents i
            LEFT JOIN assets a ON i.asset_id = a.id
            WHERE i.id = ?
        `, [id]);
        
        res.json(updated);
    } catch (error) {
        console.error('Error updating incident:', error);
        res.status(500).json({ error: 'Failed to update incident' });
    }
}

async function deleteIncident(req, res) {
    try {
        const { id } = req.params;
        
        const existing = await database.get('SELECT * FROM incidents WHERE id = ?', [id]);
        if (!existing) {
            return res.status(404).json({ error: 'Incident not found' });
        }
        
        await database.run('DELETE FROM incidents WHERE id = ?', [id]);
        res.json({ message: 'Incident deleted successfully' });
    } catch (error) {
        console.error('Error deleting incident:', error);
        res.status(500).json({ error: 'Failed to delete incident' });
    }
}

async function getIncidentStats(req, res) {
    try {
        const stats = {
            total: 0,
            bySeverity: {
                critical: 0,
                high: 0,
                medium: 0,
                low: 0
            },
            byStatus: {
                new: 0,
                investigating: 0,
                resolved: 0,
                false_positive: 0
            }
        };
        
        const incidents = await database.all('SELECT severity, status FROM incidents');
        stats.total = incidents.length;
        
        incidents.forEach(incident => {
            if (stats.bySeverity[incident.severity] !== undefined) {
                stats.bySeverity[incident.severity]++;
            }
            if (stats.byStatus[incident.status] !== undefined) {
                stats.byStatus[incident.status]++;
            }
        });
        
        res.json(stats);
    } catch (error) {
        console.error('Error fetching incident stats:', error);
        res.status(500).json({ error: 'Failed to fetch incident statistics' });
    }
}

async function analyzeIncident(req, res) {
    try {
        const { id } = req.params;
        
        const incident = await database.get('SELECT * FROM incidents WHERE id = ?', [id]);
        if (!incident) {
            return res.status(404).json({ error: 'Incident not found' });
        }
        
        // Mock AI analysis (in production, this would call a real AI service)
        const aiAnalysis = {
            summary: `Automated analysis of ${incident.detection_type || 'security'} incident`,
            severity_assessment: incident.severity,
            attack_classification: incident.detection_type || 'Unknown',
            recommended_actions: [
                'Investigate source IP address',
                'Review related log entries',
                'Check for similar patterns',
                'Update security rules if needed'
            ],
            mitre_attack: {
                tactics: ['Initial Access', 'Credential Access'],
                techniques: ['T1078 - Valid Accounts', 'T1110 - Brute Force']
            },
            confidence: 0.85
        };
        
        // Update incident with AI summary
        const summaryText = `AI Analysis: ${aiAnalysis.attack_classification}. Confidence: ${(aiAnalysis.confidence * 100).toFixed(0)}%. Recommended: ${aiAnalysis.recommended_actions[0]}`;
        
        await database.run(
            'UPDATE incidents SET ai_summary = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [summaryText, id]
        );
        
        res.json(aiAnalysis);
    } catch (error) {
        console.error('Error analyzing incident:', error);
        res.status(500).json({ error: 'Failed to analyze incident' });
    }
}

async function linkIncidentToAsset(req, res) {
    try {
        const { id } = req.params;
        const { asset_id } = req.body;
        
        if (!asset_id) {
            return res.status(400).json({ error: 'Asset ID is required' });
        }
        
        const incident = await database.get('SELECT * FROM incidents WHERE id = ?', [id]);
        if (!incident) {
            return res.status(404).json({ error: 'Incident not found' });
        }
        
        const asset = await database.get('SELECT * FROM assets WHERE id = ?', [asset_id]);
        if (!asset) {
            return res.status(404).json({ error: 'Asset not found' });
        }
        
        await database.run(
            'UPDATE incidents SET asset_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [asset_id, id]
        );
        
        res.json({ message: 'Incident linked to asset successfully' });
    } catch (error) {
        console.error('Error linking incident to asset:', error);
        res.status(500).json({ error: 'Failed to link incident to asset' });
    }
}

async function linkIncidentToRisk(req, res) {
    try {
        const { id } = req.params;
        const { risk_id } = req.body;
        
        if (!risk_id) {
            return res.status(400).json({ error: 'Risk ID is required' });
        }
        
        const incident = await database.get('SELECT * FROM incidents WHERE id = ?', [id]);
        if (!incident) {
            return res.status(404).json({ error: 'Incident not found' });
        }
        
        const risk = await database.get('SELECT * FROM risks WHERE id = ?', [risk_id]);
        if (!risk) {
            return res.status(404).json({ error: 'Risk not found' });
        }
        
        await database.run(
            'UPDATE incidents SET risk_id = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
            [risk_id, id]
        );
        
        res.json({ message: 'Incident linked to risk successfully' });
    } catch (error) {
        console.error('Error linking incident to risk:', error);
        res.status(500).json({ error: 'Failed to link incident to risk' });
    }
}

module.exports = {
    getAllIncidents,
    getIncidentById,
    createIncident,
    updateIncident,
    deleteIncident,
    getIncidentStats,
    analyzeIncident,
    linkIncidentToAsset,
    linkIncidentToRisk
};
