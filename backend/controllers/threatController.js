/**
 * Threat Controller
 * Handles CRUD operations for threats
 */

const database = require('../config/database');

async function getAllThreats(req, res) {
    try {
        const threats = await database.all('SELECT * FROM threats ORDER BY created_at DESC');
        res.json(threats);
    } catch (error) {
        console.error('Error fetching threats:', error);
        res.status(500).json({ error: 'Failed to fetch threats' });
    }
}

async function getThreatById(req, res) {
    try {
        const { id } = req.params;
        const threat = await database.get('SELECT * FROM threats WHERE id = ?', [id]);
        
        if (!threat) {
            return res.status(404).json({ error: 'Threat not found' });
        }
        
        res.json(threat);
    } catch (error) {
        console.error('Error fetching threat:', error);
        res.status(500).json({ error: 'Failed to fetch threat' });
    }
}

async function createThreat(req, res) {
    try {
        const { name, category, description } = req.body;
        
        if (!name || !category) {
            return res.status(400).json({ error: 'Name and category are required' });
        }
        
        const result = await database.run(
            'INSERT INTO threats (name, category, description) VALUES (?, ?, ?)',
            [name, category, description || null]
        );
        
        const newThreat = await database.get('SELECT * FROM threats WHERE id = ?', [result.id]);
        res.status(201).json(newThreat);
    } catch (error) {
        console.error('Error creating threat:', error);
        res.status(500).json({ error: 'Failed to create threat' });
    }
}

async function updateThreat(req, res) {
    try {
        const { id } = req.params;
        const { name, category, description } = req.body;
        
        const existing = await database.get('SELECT * FROM threats WHERE id = ?', [id]);
        if (!existing) {
            return res.status(404).json({ error: 'Threat not found' });
        }
        
        await database.run(
            `UPDATE threats SET 
                name = COALESCE(?, name),
                category = COALESCE(?, category),
                description = COALESCE(?, description)
            WHERE id = ?`,
            [name, category, description, id]
        );
        
        const updated = await database.get('SELECT * FROM threats WHERE id = ?', [id]);
        res.json(updated);
    } catch (error) {
        console.error('Error updating threat:', error);
        res.status(500).json({ error: 'Failed to update threat' });
    }
}

async function deleteThreat(req, res) {
    try {
        const { id } = req.params;
        
        const existing = await database.get('SELECT * FROM threats WHERE id = ?', [id]);
        if (!existing) {
            return res.status(404).json({ error: 'Threat not found' });
        }
        
        await database.run('DELETE FROM threats WHERE id = ?', [id]);
        res.json({ message: 'Threat deleted successfully' });
    } catch (error) {
        console.error('Error deleting threat:', error);
        res.status(500).json({ error: 'Failed to delete threat' });
    }
}

module.exports = {
    getAllThreats,
    getThreatById,
    createThreat,
    updateThreat,
    deleteThreat
};
