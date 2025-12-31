/**
 * Risk Controller
 * Handles CRUD operations for risks and risk assessment
 */

const database = require('../config/database');
const { calculateRiskScore, calculateRiskLevel, generateRiskMatrix } = require('../utils/riskCalculator');

/**
 * Get all risks with related asset, threat, and vulnerability info
 */
async function getAllRisks(req, res) {
    try {
        const risks = await database.all(`
            SELECT 
                r.*,
                a.name as asset_name,
                a.category as asset_category,
                t.name as threat_name,
                v.name as vulnerability_name
            FROM risks r
            LEFT JOIN assets a ON r.asset_id = a.id
            LEFT JOIN threats t ON r.threat_id = t.id
            LEFT JOIN vulnerabilities v ON r.vulnerability_id = v.id
            ORDER BY r.risk_score DESC, r.created_at DESC
        `);
        res.json(risks);
    } catch (error) {
        console.error('Error fetching risks:', error);
        res.status(500).json({ error: 'Failed to fetch risks' });
    }
}

/**
 * Get single risk by ID
 */
async function getRiskById(req, res) {
    try {
        const { id } = req.params;
        const risk = await database.get(`
            SELECT 
                r.*,
                a.name as asset_name,
                a.category as asset_category,
                a.criticality as asset_criticality,
                t.name as threat_name,
                t.category as threat_category,
                v.name as vulnerability_name,
                v.severity as vulnerability_severity
            FROM risks r
            LEFT JOIN assets a ON r.asset_id = a.id
            LEFT JOIN threats t ON r.threat_id = t.id
            LEFT JOIN vulnerabilities v ON r.vulnerability_id = v.id
            WHERE r.id = ?
        `, [id]);
        
        if (!risk) {
            return res.status(404).json({ error: 'Risk not found' });
        }
        
        res.json(risk);
    } catch (error) {
        console.error('Error fetching risk:', error);
        res.status(500).json({ error: 'Failed to fetch risk' });
    }
}

/**
 * Create new risk
 */
async function createRisk(req, res) {
    try {
        const { asset_id, threat_id, vulnerability_id, likelihood, impact, description, status } = req.body;
        
        // Validation
        if (!asset_id || !threat_id || !vulnerability_id || !likelihood || !impact) {
            return res.status(400).json({ error: 'Asset, threat, vulnerability, likelihood, and impact are required' });
        }
        
        if (likelihood < 1 || likelihood > 5 || impact < 1 || impact > 5) {
            return res.status(400).json({ error: 'Likelihood and impact must be between 1 and 5' });
        }
        
        // Verify foreign keys exist
        const asset = await database.get('SELECT id FROM assets WHERE id = ?', [asset_id]);
        const threat = await database.get('SELECT id FROM threats WHERE id = ?', [threat_id]);
        const vulnerability = await database.get('SELECT id FROM vulnerabilities WHERE id = ?', [vulnerability_id]);
        
        if (!asset || !threat || !vulnerability) {
            return res.status(400).json({ error: 'Invalid asset, threat, or vulnerability ID' });
        }
        
        // Calculate risk score and level
        const risk_score = calculateRiskScore(likelihood, impact);
        const risk_level = calculateRiskLevel(risk_score);
        
        const result = await database.run(
            `INSERT INTO risks (asset_id, threat_id, vulnerability_id, likelihood, impact, risk_score, risk_level, description, status) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [asset_id, threat_id, vulnerability_id, likelihood, impact, risk_score, risk_level, description || null, status || 'Active']
        );
        
        const newRisk = await database.get(`
            SELECT 
                r.*,
                a.name as asset_name,
                t.name as threat_name,
                v.name as vulnerability_name
            FROM risks r
            LEFT JOIN assets a ON r.asset_id = a.id
            LEFT JOIN threats t ON r.threat_id = t.id
            LEFT JOIN vulnerabilities v ON r.vulnerability_id = v.id
            WHERE r.id = ?
        `, [result.id]);
        
        res.status(201).json(newRisk);
    } catch (error) {
        console.error('Error creating risk:', error);
        res.status(500).json({ error: 'Failed to create risk' });
    }
}

/**
 * Update risk
 */
async function updateRisk(req, res) {
    try {
        const { id } = req.params;
        const { asset_id, threat_id, vulnerability_id, likelihood, impact, description, status } = req.body;
        
        const existing = await database.get('SELECT * FROM risks WHERE id = ?', [id]);
        if (!existing) {
            return res.status(404).json({ error: 'Risk not found' });
        }
        
        // Validation
        if ((likelihood && (likelihood < 1 || likelihood > 5)) || (impact && (impact < 1 || impact > 5))) {
            return res.status(400).json({ error: 'Likelihood and impact must be between 1 and 5' });
        }
        
        // Recalculate risk score if likelihood or impact changed
        const newLikelihood = likelihood || existing.likelihood;
        const newImpact = impact || existing.impact;
        const risk_score = calculateRiskScore(newLikelihood, newImpact);
        const risk_level = calculateRiskLevel(risk_score);
        
        await database.run(
            `UPDATE risks SET 
                asset_id = COALESCE(?, asset_id),
                threat_id = COALESCE(?, threat_id),
                vulnerability_id = COALESCE(?, vulnerability_id),
                likelihood = COALESCE(?, likelihood),
                impact = COALESCE(?, impact),
                risk_score = ?,
                risk_level = ?,
                description = COALESCE(?, description),
                status = COALESCE(?, status),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?`,
            [asset_id, threat_id, vulnerability_id, likelihood, impact, risk_score, risk_level, description, status, id]
        );
        
        const updated = await database.get(`
            SELECT 
                r.*,
                a.name as asset_name,
                t.name as threat_name,
                v.name as vulnerability_name
            FROM risks r
            LEFT JOIN assets a ON r.asset_id = a.id
            LEFT JOIN threats t ON r.threat_id = t.id
            LEFT JOIN vulnerabilities v ON r.vulnerability_id = v.id
            WHERE r.id = ?
        `, [id]);
        
        res.json(updated);
    } catch (error) {
        console.error('Error updating risk:', error);
        res.status(500).json({ error: 'Failed to update risk' });
    }
}

/**
 * Delete risk
 */
async function deleteRisk(req, res) {
    try {
        const { id } = req.params;
        
        const existing = await database.get('SELECT * FROM risks WHERE id = ?', [id]);
        if (!existing) {
            return res.status(404).json({ error: 'Risk not found' });
        }
        
        await database.run('DELETE FROM risks WHERE id = ?', [id]);
        res.json({ message: 'Risk deleted successfully' });
    } catch (error) {
        console.error('Error deleting risk:', error);
        res.status(500).json({ error: 'Failed to delete risk' });
    }
}

/**
 * Get risk statistics
 */
async function getRiskStats(req, res) {
    try {
        const stats = {
            total: 0,
            byLevel: {
                Critical: 0,
                High: 0,
                Medium: 0,
                Low: 0
            },
            byStatus: {
                Active: 0,
                Mitigated: 0,
                Accepted: 0,
                Closed: 0
            }
        };
        
        const risks = await database.all('SELECT risk_level, status FROM risks');
        stats.total = risks.length;
        
        risks.forEach(risk => {
            if (stats.byLevel[risk.risk_level] !== undefined) {
                stats.byLevel[risk.risk_level]++;
            }
            if (stats.byStatus[risk.status] !== undefined) {
                stats.byStatus[risk.status]++;
            }
        });
        
        res.json(stats);
    } catch (error) {
        console.error('Error fetching risk stats:', error);
        res.status(500).json({ error: 'Failed to fetch risk statistics' });
    }
}

/**
 * Get risk matrix data
 */
async function getRiskMatrix(req, res) {
    try {
        const matrix = generateRiskMatrix();
        
        // Get actual risk counts for each cell
        const risks = await database.all('SELECT likelihood, impact FROM risks WHERE status = "Active"');
        
        // Count risks in each cell
        const cellCounts = {};
        risks.forEach(risk => {
            const key = `${risk.likelihood}-${risk.impact}`;
            cellCounts[key] = (cellCounts[key] || 0) + 1;
        });
        
        // Add counts to matrix
        const matrixWithCounts = matrix.map(cell => ({
            ...cell,
            count: cellCounts[`${cell.likelihood}-${cell.impact}`] || 0
        }));
        
        res.json(matrixWithCounts);
    } catch (error) {
        console.error('Error fetching risk matrix:', error);
        res.status(500).json({ error: 'Failed to fetch risk matrix' });
    }
}

module.exports = {
    getAllRisks,
    getRiskById,
    createRisk,
    updateRisk,
    deleteRisk,
    getRiskStats,
    getRiskMatrix
};
