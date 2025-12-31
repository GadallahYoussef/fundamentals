import React, { useState, useEffect } from 'react';
import { risksAPI } from '../../services/api';

function Risks() {
    const [risks, setRisks] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchRisks();
    }, []);

    const fetchRisks = async () => {
        try {
            const response = await risksAPI.getAll();
            setRisks(response.data);
        } catch (err) {
            console.error('Error fetching risks:', err);
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
                <h1 className="page-title">Risks</h1>
                <p className="page-description">Risk assessment and management</p>
            </div>

            <div className="card">
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Description</th>
                                <th>Asset</th>
                                <th>Threat</th>
                                <th>Vulnerability</th>
                                <th>Risk Level</th>
                                <th>Risk Score</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {risks.length > 0 ? (
                                risks.map((risk) => (
                                    <tr key={risk.id}>
                                        <td>{risk.id}</td>
                                        <td>{risk.description}</td>
                                        <td>{risk.asset_name}</td>
                                        <td>{risk.threat_name}</td>
                                        <td>{risk.vulnerability_name}</td>
                                        <td>
                                            <span className={`badge badge-${risk.risk_level.toLowerCase()}`}>
                                                {risk.risk_level}
                                            </span>
                                        </td>
                                        <td>{risk.risk_score}</td>
                                        <td>{risk.status}</td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="8" style={{ textAlign: 'center' }}>
                                        No risks found
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}

export default Risks;
