import React, { useState, useEffect } from 'react';
import { threatsAPI } from '../../services/api';

function Threats() {
    const [threats, setThreats] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchThreats();
    }, []);

    const fetchThreats = async () => {
        try {
            const response = await threatsAPI.getAll();
            setThreats(response.data);
        } catch (err) {
            console.error('Error fetching threats:', err);
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return <div className="loading"><div className="spinner"></div></div>;
    }

    return (
        <div>
            <div className="page-header">
                <h1 className="page-title">Threats</h1>
                <p className="page-description">Manage security threats</p>
            </div>
            <div className="card">
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th>Category</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {threats.map((threat) => (
                                <tr key={threat.id}>
                                    <td>{threat.id}</td>
                                    <td>{threat.name}</td>
                                    <td>{threat.category}</td>
                                    <td>{threat.description}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}

export default Threats;
