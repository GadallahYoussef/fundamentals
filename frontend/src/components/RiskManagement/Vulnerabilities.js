import React, { useState, useEffect } from 'react';
import { vulnerabilitiesAPI } from '../../services/api';

function Vulnerabilities() {
    const [vulnerabilities, setVulnerabilities] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchVulnerabilities();
    }, []);

    const fetchVulnerabilities = async () => {
        try {
            const response = await vulnerabilitiesAPI.getAll();
            setVulnerabilities(response.data);
        } catch (err) {
            console.error('Error fetching vulnerabilities:', err);
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
                <h1 className="page-title">Vulnerabilities</h1>
                <p className="page-description">Manage system vulnerabilities</p>
            </div>
            <div className="card">
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Name</th>
                                <th>Category</th>
                                <th>Severity</th>
                                <th>Description</th>
                            </tr>
                        </thead>
                        <tbody>
                            {vulnerabilities.map((vuln) => (
                                <tr key={vuln.id}>
                                    <td>{vuln.id}</td>
                                    <td>{vuln.name}</td>
                                    <td>{vuln.category}</td>
                                    <td>
                                        <span className={`badge badge-${vuln.severity?.toLowerCase()}`}>
                                            {vuln.severity}
                                        </span>
                                    </td>
                                    <td>{vuln.description}</td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}

export default Vulnerabilities;
