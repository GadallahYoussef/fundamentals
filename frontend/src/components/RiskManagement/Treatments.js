import React, { useState, useEffect } from 'react';
import { treatmentsAPI } from '../../services/api';

function Treatments() {
    const [treatments, setTreatments] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchTreatments();
    }, []);

    const fetchTreatments = async () => {
        try {
            const response = await treatmentsAPI.getAll();
            setTreatments(response.data);
        } catch (err) {
            console.error('Error fetching treatments:', err);
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
                <h1 className="page-title">Risk Treatments</h1>
                <p className="page-description">Risk treatment plans and progress</p>
            </div>

            <div className="card">
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Risk Description</th>
                                <th>Treatment Type</th>
                                <th>Description</th>
                                <th>Owner</th>
                                <th>Status</th>
                                <th>Due Date</th>
                            </tr>
                        </thead>
                        <tbody>
                            {treatments.length > 0 ? (
                                treatments.map((treatment) => (
                                    <tr key={treatment.id}>
                                        <td>{treatment.id}</td>
                                        <td>{treatment.risk_description}</td>
                                        <td>
                                            <span className="badge badge-medium">
                                                {treatment.treatment_type}
                                            </span>
                                        </td>
                                        <td>{treatment.description}</td>
                                        <td>{treatment.owner || 'N/A'}</td>
                                        <td>
                                            <span className={`badge ${
                                                treatment.status === 'Completed' ? 'badge-resolved' :
                                                treatment.status === 'In Progress' ? 'badge-investigating' :
                                                'badge-new'
                                            }`}>
                                                {treatment.status}
                                            </span>
                                        </td>
                                        <td>{treatment.due_date || 'N/A'}</td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="7" style={{ textAlign: 'center' }}>
                                        No treatments found
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

export default Treatments;
