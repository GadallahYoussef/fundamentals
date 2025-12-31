/**
 * Treatment Controller
 * Handles CRUD operations for risk treatments
 */

const database = require('../config/database');

async function getAllTreatments(req, res) {
    try {
        const treatments = await database.all(`
            SELECT 
                t.*,
                r.description as risk_description,
                r.risk_level,
                r.risk_score
            FROM treatments t
            LEFT JOIN risks r ON t.risk_id = r.id
            ORDER BY t.created_at DESC
        `);
        res.json(treatments);
    } catch (error) {
        console.error('Error fetching treatments:', error);
        res.status(500).json({ error: 'Failed to fetch treatments' });
    }
}

async function getTreatmentById(req, res) {
    try {
        const { id } = req.params;
        const treatment = await database.get(`
            SELECT 
                t.*,
                r.description as risk_description,
                r.risk_level,
                r.risk_score
            FROM treatments t
            LEFT JOIN risks r ON t.risk_id = r.id
            WHERE t.id = ?
        `, [id]);
        
        if (!treatment) {
            return res.status(404).json({ error: 'Treatment not found' });
        }
        
        res.json(treatment);
    } catch (error) {
        console.error('Error fetching treatment:', error);
        res.status(500).json({ error: 'Failed to fetch treatment' });
    }
}

async function createTreatment(req, res) {
    try {
        const { risk_id, treatment_type, description, owner, status, due_date, notes } = req.body;
        
        if (!risk_id || !treatment_type || !description) {
            return res.status(400).json({ error: 'Risk ID, treatment type, and description are required' });
        }
        
        const validTypes = ['Mitigate', 'Accept', 'Transfer', 'Avoid'];
        if (!validTypes.includes(treatment_type)) {
            return res.status(400).json({ error: 'Invalid treatment type' });
        }
        
        const risk = await database.get('SELECT id FROM risks WHERE id = ?', [risk_id]);
        if (!risk) {
            return res.status(400).json({ error: 'Invalid risk ID' });
        }
        
        const result = await database.run(
            `INSERT INTO treatments (risk_id, treatment_type, description, owner, status, due_date, notes) 
             VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [risk_id, treatment_type, description, owner || null, status || 'Planned', due_date || null, notes || null]
        );
        
        const newTreatment = await database.get(`
            SELECT 
                t.*,
                r.description as risk_description,
                r.risk_level
            FROM treatments t
            LEFT JOIN risks r ON t.risk_id = r.id
            WHERE t.id = ?
        `, [result.id]);
        
        res.status(201).json(newTreatment);
    } catch (error) {
        console.error('Error creating treatment:', error);
        res.status(500).json({ error: 'Failed to create treatment' });
    }
}

async function updateTreatment(req, res) {
    try {
        const { id } = req.params;
        const { risk_id, treatment_type, description, owner, status, due_date, notes } = req.body;
        
        const existing = await database.get('SELECT * FROM treatments WHERE id = ?', [id]);
        if (!existing) {
            return res.status(404).json({ error: 'Treatment not found' });
        }
        
        const validTypes = ['Mitigate', 'Accept', 'Transfer', 'Avoid'];
        if (treatment_type && !validTypes.includes(treatment_type)) {
            return res.status(400).json({ error: 'Invalid treatment type' });
        }
        
        const validStatuses = ['Planned', 'In Progress', 'Completed', 'Cancelled'];
        if (status && !validStatuses.includes(status)) {
            return res.status(400).json({ error: 'Invalid status' });
        }
        
        await database.run(
            `UPDATE treatments SET 
                risk_id = COALESCE(?, risk_id),
                treatment_type = COALESCE(?, treatment_type),
                description = COALESCE(?, description),
                owner = COALESCE(?, owner),
                status = COALESCE(?, status),
                due_date = COALESCE(?, due_date),
                notes = COALESCE(?, notes),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?`,
            [risk_id, treatment_type, description, owner, status, due_date, notes, id]
        );
        
        const updated = await database.get(`
            SELECT 
                t.*,
                r.description as risk_description,
                r.risk_level
            FROM treatments t
            LEFT JOIN risks r ON t.risk_id = r.id
            WHERE t.id = ?
        `, [id]);
        
        res.json(updated);
    } catch (error) {
        console.error('Error updating treatment:', error);
        res.status(500).json({ error: 'Failed to update treatment' });
    }
}

async function deleteTreatment(req, res) {
    try {
        const { id } = req.params;
        
        const existing = await database.get('SELECT * FROM treatments WHERE id = ?', [id]);
        if (!existing) {
            return res.status(404).json({ error: 'Treatment not found' });
        }
        
        await database.run('DELETE FROM treatments WHERE id = ?', [id]);
        res.json({ message: 'Treatment deleted successfully' });
    } catch (error) {
        console.error('Error deleting treatment:', error);
        res.status(500).json({ error: 'Failed to delete treatment' });
    }
}

async function getTreatmentStats(req, res) {
    try {
        const stats = {
            total: 0,
            byStatus: {
                Planned: 0,
                'In Progress': 0,
                Completed: 0,
                Cancelled: 0
            },
            byType: {
                Mitigate: 0,
                Accept: 0,
                Transfer: 0,
                Avoid: 0
            }
        };
        
        const treatments = await database.all('SELECT treatment_type, status FROM treatments');
        stats.total = treatments.length;
        
        treatments.forEach(treatment => {
            if (stats.byStatus[treatment.status] !== undefined) {
                stats.byStatus[treatment.status]++;
            }
            if (stats.byType[treatment.treatment_type] !== undefined) {
                stats.byType[treatment.treatment_type]++;
            }
        });
        
        res.json(stats);
    } catch (error) {
        console.error('Error fetching treatment stats:', error);
        res.status(500).json({ error: 'Failed to fetch treatment statistics' });
    }
}

module.exports = {
    getAllTreatments,
    getTreatmentById,
    createTreatment,
    updateTreatment,
    deleteTreatment,
    getTreatmentStats
};
