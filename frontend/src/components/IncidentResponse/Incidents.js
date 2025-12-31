import React, { useState, useEffect } from 'react';
import { incidentsAPI } from '../../services/api';

function Incidents() {
    const [incidents, setIncidents] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchIncidents();
    }, []);

    const fetchIncidents = async () => {
        try {
            const response = await incidentsAPI.getAll();
            setIncidents(response.data);
        } catch (err) {
            console.error('Error fetching incidents:', err);
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
                <h1 className="page-title">Incidents</h1>
                <p className="page-description">Security incident management</p>
            </div>

            <div className="card">
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Alert</th>
                                <th>Severity</th>
                                <th>Status</th>
                                <th>Detection Type</th>
                                <th>Source IPs</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            {incidents.length > 0 ? (
                                incidents.map((incident) => (
                                    <tr key={incident.id}>
                                        <td>{incident.id}</td>
                                        <td>{incident.alert}</td>
                                        <td>
                                            <span className={`badge badge-${incident.severity}`}>
                                                {incident.severity}
                                            </span>
                                        </td>
                                        <td>
                                            <span className={`badge badge-${incident.status}`}>
                                                {incident.status}
                                            </span>
                                        </td>
                                        <td>{incident.detection_type || 'N/A'}</td>
                                        <td>{incident.source_ips || 'N/A'}</td>
                                        <td>{new Date(incident.timestamp).toLocaleString()}</td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="7" style={{ textAlign: 'center' }}>
                                        No incidents found
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

export default Incidents;
