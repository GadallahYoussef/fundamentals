import React, { useState, useEffect } from 'react';
import { risksAPI } from '../../services/api';

function RiskMatrix() {
    const [matrix, setMatrix] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        fetchMatrix();
    }, []);

    const fetchMatrix = async () => {
        try {
            const response = await risksAPI.getMatrix();
            setMatrix(response.data);
        } catch (err) {
            console.error('Error fetching risk matrix:', err);
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return <div className="loading"><div className="spinner"></div></div>;
    }

    // Group matrix by likelihood
    const matrixByLikelihood = {};
    matrix.forEach(cell => {
        if (!matrixByLikelihood[cell.likelihood]) {
            matrixByLikelihood[cell.likelihood] = [];
        }
        matrixByLikelihood[cell.likelihood].push(cell);
    });

    return (
        <div>
            <div className="page-header">
                <h1 className="page-title">Risk Matrix</h1>
                <p className="page-description">5×5 Risk heat map visualization</p>
            </div>

            <div className="card">
                <div className="card-header">Risk Matrix (Likelihood × Impact)</div>
                <div style={{ padding: '20px' }}>
                    <div style={{ marginBottom: '20px' }}>
                        <p><strong>Likelihood:</strong> 5 = Very High, 4 = High, 3 = Medium, 2 = Low, 1 = Very Low</p>
                        <p><strong>Impact:</strong> 5 = Catastrophic, 4 = Major, 3 = Moderate, 2 = Minor, 1 = Insignificant</p>
                    </div>
                    <div className="risk-matrix">
                        {Object.keys(matrixByLikelihood).sort((a, b) => b - a).map(likelihood => (
                            matrixByLikelihood[likelihood].map(cell => (
                                <div
                                    key={`${cell.likelihood}-${cell.impact}`}
                                    className="risk-cell"
                                    style={{ backgroundColor: cell.color }}
                                    title={`L${cell.likelihood} × I${cell.impact} = ${cell.score} (${cell.level}) - ${cell.count} risks`}
                                >
                                    {cell.count > 0 ? cell.count : ''}
                                </div>
                            ))
                        ))}
                    </div>
                    <div style={{ marginTop: '20px' }}>
                        <div style={{ display: 'flex', gap: '20px', justifyContent: 'center' }}>
                            <span><span style={{ backgroundColor: '#dc2626', padding: '5px 10px', borderRadius: '3px', color: 'white' }}>Critical (20-25)</span></span>
                            <span><span style={{ backgroundColor: '#f97316', padding: '5px 10px', borderRadius: '3px', color: 'white' }}>High (12-19)</span></span>
                            <span><span style={{ backgroundColor: '#fbbf24', padding: '5px 10px', borderRadius: '3px', color: 'white' }}>Medium (6-11)</span></span>
                            <span><span style={{ backgroundColor: '#22c55e', padding: '5px 10px', borderRadius: '3px', color: 'white' }}>Low (1-5)</span></span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}

export default RiskMatrix;
