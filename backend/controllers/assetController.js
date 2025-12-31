/**
 * Asset Controller
 * Handles CRUD operations for assets
 */

const database = require('../config/database');

/**
 * Get all assets
 */
async function getAllAssets(req, res) {
    try {
        const assets = await database.all('SELECT * FROM assets ORDER BY created_at DESC');
        res.json(assets);
    } catch (error) {
        console.error('Error fetching assets:', error);
        res.status(500).json({ error: 'Failed to fetch assets' });
    }
}

/**
 * Get single asset by ID
 */
async function getAssetById(req, res) {
    try {
        const { id } = req.params;
        const asset = await database.get('SELECT * FROM assets WHERE id = ?', [id]);
        
        if (!asset) {
            return res.status(404).json({ error: 'Asset not found' });
        }
        
        res.json(asset);
    } catch (error) {
        console.error('Error fetching asset:', error);
        res.status(500).json({ error: 'Failed to fetch asset' });
    }
}

/**
 * Create new asset
 */
async function createAsset(req, res) {
    try {
        const { name, category, description, criticality, value, owner } = req.body;
        
        // Validation
        if (!name || !category || !criticality) {
            return res.status(400).json({ error: 'Name, category, and criticality are required' });
        }
        
        if (criticality < 1 || criticality > 5) {
            return res.status(400).json({ error: 'Criticality must be between 1 and 5' });
        }
        
        const validCategories = ['Hardware', 'Software', 'Data', 'Personnel', 'Facilities'];
        if (!validCategories.includes(category)) {
            return res.status(400).json({ error: 'Invalid category' });
        }
        
        const result = await database.run(
            'INSERT INTO assets (name, category, description, criticality, value, owner) VALUES (?, ?, ?, ?, ?, ?)',
            [name, category, description || null, criticality, value || null, owner || null]
        );
        
        const newAsset = await database.get('SELECT * FROM assets WHERE id = ?', [result.id]);
        res.status(201).json(newAsset);
    } catch (error) {
        console.error('Error creating asset:', error);
        res.status(500).json({ error: 'Failed to create asset' });
    }
}

/**
 * Update asset
 */
async function updateAsset(req, res) {
    try {
        const { id } = req.params;
        const { name, category, description, criticality, value, owner } = req.body;
        
        // Check if asset exists
        const existing = await database.get('SELECT * FROM assets WHERE id = ?', [id]);
        if (!existing) {
            return res.status(404).json({ error: 'Asset not found' });
        }
        
        // Validation
        if (criticality && (criticality < 1 || criticality > 5)) {
            return res.status(400).json({ error: 'Criticality must be between 1 and 5' });
        }
        
        const validCategories = ['Hardware', 'Software', 'Data', 'Personnel', 'Facilities'];
        if (category && !validCategories.includes(category)) {
            return res.status(400).json({ error: 'Invalid category' });
        }
        
        await database.run(
            `UPDATE assets SET 
                name = COALESCE(?, name),
                category = COALESCE(?, category),
                description = COALESCE(?, description),
                criticality = COALESCE(?, criticality),
                value = COALESCE(?, value),
                owner = COALESCE(?, owner),
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?`,
            [name, category, description, criticality, value, owner, id]
        );
        
        const updated = await database.get('SELECT * FROM assets WHERE id = ?', [id]);
        res.json(updated);
    } catch (error) {
        console.error('Error updating asset:', error);
        res.status(500).json({ error: 'Failed to update asset' });
    }
}

/**
 * Delete asset
 */
async function deleteAsset(req, res) {
    try {
        const { id } = req.params;
        
        const existing = await database.get('SELECT * FROM assets WHERE id = ?', [id]);
        if (!existing) {
            return res.status(404).json({ error: 'Asset not found' });
        }
        
        await database.run('DELETE FROM assets WHERE id = ?', [id]);
        res.json({ message: 'Asset deleted successfully' });
    } catch (error) {
        console.error('Error deleting asset:', error);
        res.status(500).json({ error: 'Failed to delete asset' });
    }
}

module.exports = {
    getAllAssets,
    getAssetById,
    createAsset,
    updateAsset,
    deleteAsset
};
