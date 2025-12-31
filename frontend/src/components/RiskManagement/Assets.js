import React, { useState, useEffect } from 'react';
import { assetsAPI } from '../../services/api';

function Assets() {
    const [assets, setAssets] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [showModal, setShowModal] = useState(false);
    const [editingAsset, setEditingAsset] = useState(null);
    const [formData, setFormData] = useState({
        name: '',
        category: 'Hardware',
        description: '',
        criticality: 3,
        value: '',
        owner: '',
    });

    useEffect(() => {
        fetchAssets();
    }, []);

    const fetchAssets = async () => {
        try {
            setLoading(true);
            const response = await assetsAPI.getAll();
            setAssets(response.data);
            setError(null);
        } catch (err) {
            console.error('Error fetching assets:', err);
            setError('Failed to load assets');
        } finally {
            setLoading(false);
        }
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        try {
            if (editingAsset) {
                await assetsAPI.update(editingAsset.id, formData);
            } else {
                await assetsAPI.create(formData);
            }
            fetchAssets();
            closeModal();
        } catch (err) {
            console.error('Error saving asset:', err);
            alert('Failed to save asset');
        }
    };

    const handleDelete = async (id) => {
        if (window.confirm('Are you sure you want to delete this asset?')) {
            try {
                await assetsAPI.delete(id);
                fetchAssets();
            } catch (err) {
                console.error('Error deleting asset:', err);
                alert('Failed to delete asset');
            }
        }
    };

    const openModal = (asset = null) => {
        if (asset) {
            setEditingAsset(asset);
            setFormData({
                name: asset.name,
                category: asset.category,
                description: asset.description || '',
                criticality: asset.criticality,
                value: asset.value || '',
                owner: asset.owner || '',
            });
        } else {
            setEditingAsset(null);
            setFormData({
                name: '',
                category: 'Hardware',
                description: '',
                criticality: 3,
                value: '',
                owner: '',
            });
        }
        setShowModal(true);
    };

    const closeModal = () => {
        setShowModal(false);
        setEditingAsset(null);
    };

    if (loading) {
        return <div className="loading"><div className="spinner"></div></div>;
    }

    return (
        <div>
            <div className="page-header">
                <h1 className="page-title">Assets</h1>
                <p className="page-description">Manage organizational assets</p>
            </div>

            <div className="action-bar">
                <div></div>
                <button className="btn btn-primary" onClick={() => openModal()}>
                    + Add Asset
                </button>
            </div>

            {error && <div className="error-message">{error}</div>}

            <div className="card">
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th>Category</th>
                                <th>Criticality</th>
                                <th>Value</th>
                                <th>Owner</th>
                                <th>Actions</th>
                            </tr>
                        </thead>
                        <tbody>
                            {assets.length > 0 ? (
                                assets.map((asset) => (
                                    <tr key={asset.id}>
                                        <td>{asset.id}</td>
                                        <td>{asset.name}</td>
                                        <td>{asset.category}</td>
                                        <td>
                                            <span className={`badge ${
                                                asset.criticality >= 4 ? 'badge-critical' :
                                                asset.criticality === 3 ? 'badge-high' :
                                                'badge-medium'
                                            }`}>
                                                {asset.criticality}
                                            </span>
                                        </td>
                                        <td>${asset.value || 0}</td>
                                        <td>{asset.owner || 'N/A'}</td>
                                        <td>
                                            <button
                                                className="btn btn-sm btn-secondary"
                                                onClick={() => openModal(asset)}
                                                style={{ marginRight: '5px' }}
                                            >
                                                Edit
                                            </button>
                                            <button
                                                className="btn btn-sm btn-danger"
                                                onClick={() => handleDelete(asset.id)}
                                            >
                                                Delete
                                            </button>
                                        </td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="7" style={{ textAlign: 'center' }}>
                                        No assets found
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Modal */}
            {showModal && (
                <div className="modal-overlay" onClick={closeModal}>
                    <div className="modal" onClick={(e) => e.stopPropagation()}>
                        <div className="modal-header">
                            {editingAsset ? 'Edit Asset' : 'Add New Asset'}
                        </div>
                        <form onSubmit={handleSubmit}>
                            <div className="form-group">
                                <label>Name *</label>
                                <input
                                    type="text"
                                    className="form-control"
                                    value={formData.name}
                                    onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label>Category *</label>
                                <select
                                    className="form-control"
                                    value={formData.category}
                                    onChange={(e) => setFormData({ ...formData, category: e.target.value })}
                                    required
                                >
                                    <option value="Hardware">Hardware</option>
                                    <option value="Software">Software</option>
                                    <option value="Data">Data</option>
                                    <option value="Personnel">Personnel</option>
                                    <option value="Facilities">Facilities</option>
                                </select>
                            </div>
                            <div className="form-group">
                                <label>Criticality (1-5) *</label>
                                <input
                                    type="number"
                                    className="form-control"
                                    value={formData.criticality}
                                    onChange={(e) => setFormData({ ...formData, criticality: parseInt(e.target.value) })}
                                    min="1"
                                    max="5"
                                    required
                                />
                            </div>
                            <div className="form-group">
                                <label>Value ($)</label>
                                <input
                                    type="number"
                                    className="form-control"
                                    value={formData.value}
                                    onChange={(e) => setFormData({ ...formData, value: e.target.value })}
                                />
                            </div>
                            <div className="form-group">
                                <label>Owner</label>
                                <input
                                    type="text"
                                    className="form-control"
                                    value={formData.owner}
                                    onChange={(e) => setFormData({ ...formData, owner: e.target.value })}
                                />
                            </div>
                            <div className="form-group">
                                <label>Description</label>
                                <textarea
                                    className="form-control"
                                    value={formData.description}
                                    onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                                />
                            </div>
                            <div className="modal-actions">
                                <button type="button" className="btn btn-secondary" onClick={closeModal}>
                                    Cancel
                                </button>
                                <button type="submit" className="btn btn-primary">
                                    {editingAsset ? 'Update' : 'Create'}
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}

export default Assets;
