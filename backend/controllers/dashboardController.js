/**
 * Dashboard Controller
 * Provides unified statistics and metrics
 */

const database = require('../config/database');

/**
 * Get unified dashboard statistics
 */
async function getDashboardStats(req, res) {
    try {
        // Get total counts
        const assetCount = await database.get('SELECT COUNT(*) as count FROM assets');
        const riskCount = await database.get('SELECT COUNT(*) as count FROM risks');
        const incidentCount = await database.get('SELECT COUNT(*) as count FROM incidents');
        const treatmentCount = await database.get('SELECT COUNT(*) as count FROM treatments');
        
        // Get risk distribution by level
        const risksByLevel = await database.all(`
            SELECT risk_level, COUNT(*) as count 
            FROM risks 
            WHERE status = 'Active'
            GROUP BY risk_level
        `);
        
        const riskDistribution = {
            Critical: 0,
            High: 0,
            Medium: 0,
            Low: 0
        };
        risksByLevel.forEach(r => {
            riskDistribution[r.risk_level] = r.count;
        });
        
        // Get incident distribution by severity
        const incidentsBySeverity = await database.all(`
            SELECT severity, COUNT(*) as count 
            FROM incidents 
            GROUP BY severity
        `);
        
        const incidentDistribution = {
            critical: 0,
            high: 0,
            medium: 0,
            low: 0
        };
        incidentsBySeverity.forEach(i => {
            incidentDistribution[i.severity] = i.count;
        });
        
        // Get incident distribution by status
        const incidentsByStatus = await database.all(`
            SELECT status, COUNT(*) as count 
            FROM incidents 
            GROUP BY status
        `);
        
        const incidentStatusDistribution = {
            new: 0,
            investigating: 0,
            resolved: 0,
            false_positive: 0
        };
        incidentsByStatus.forEach(i => {
            incidentStatusDistribution[i.status] = i.count;
        });
        
        // Get top 10 highest risks
        const topRisks = await database.all(`
            SELECT 
                r.id,
                r.description,
                r.risk_score,
                r.risk_level,
                a.name as asset_name,
                t.name as threat_name
            FROM risks r
            LEFT JOIN assets a ON r.asset_id = a.id
            LEFT JOIN threats t ON r.threat_id = t.id
            WHERE r.status = 'Active'
            ORDER BY r.risk_score DESC, r.created_at DESC
            LIMIT 10
        `);
        
        // Get recent incidents (last 10)
        const recentIncidents = await database.all(`
            SELECT 
                i.id,
                i.alert,
                i.severity,
                i.status,
                i.timestamp,
                a.name as asset_name
            FROM incidents i
            LEFT JOIN assets a ON i.asset_id = a.id
            ORDER BY i.timestamp DESC
            LIMIT 10
        `);
        
        // Get treatment progress
        const treatmentsByStatus = await database.all(`
            SELECT status, COUNT(*) as count 
            FROM treatments 
            GROUP BY status
        `);
        
        const treatmentProgress = {
            Planned: 0,
            'In Progress': 0,
            Completed: 0,
            Cancelled: 0
        };
        treatmentsByStatus.forEach(t => {
            treatmentProgress[t.status] = t.count;
        });
        
        // Get asset distribution by category
        const assetsByCategory = await database.all(`
            SELECT category, COUNT(*) as count 
            FROM assets 
            GROUP BY category
        `);
        
        const assetDistribution = {};
        assetsByCategory.forEach(a => {
            assetDistribution[a.category] = a.count;
        });
        
        // Get asset distribution by criticality
        const assetsByCriticality = await database.all(`
            SELECT criticality, COUNT(*) as count 
            FROM assets 
            GROUP BY criticality
            ORDER BY criticality DESC
        `);
        
        const criticalityDistribution = {};
        assetsByCriticality.forEach(a => {
            criticalityDistribution[`Level ${a.criticality}`] = a.count;
        });
        
        res.json({
            summary: {
                totalAssets: assetCount.count,
                totalRisks: riskCount.count,
                totalIncidents: incidentCount.count,
                totalTreatments: treatmentCount.count,
                criticalRisks: riskDistribution.Critical,
                highRisks: riskDistribution.High,
                openIncidents: incidentStatusDistribution.new + incidentStatusDistribution.investigating,
                criticalIncidents: incidentDistribution.critical
            },
            riskDistribution,
            incidentDistribution,
            incidentStatusDistribution,
            treatmentProgress,
            assetDistribution,
            criticalityDistribution,
            topRisks,
            recentIncidents
        });
    } catch (error) {
        console.error('Error fetching dashboard stats:', error);
        res.status(500).json({ error: 'Failed to fetch dashboard statistics' });
    }
}

module.exports = {
    getDashboardStats
};
