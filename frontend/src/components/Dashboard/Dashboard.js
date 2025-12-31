import React, { useState, useEffect } from 'react';
import { dashboardAPI } from '../../services/api';
import { Chart as ChartJS, ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend } from 'chart.js';
import { Pie, Bar } from 'react-chartjs-2';

ChartJS.register(ArcElement, CategoryScale, LinearScale, BarElement, Title, Tooltip, Legend);

function Dashboard() {
    const [stats, setStats] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    useEffect(() => {
        fetchDashboardStats();
    }, []);

    const fetchDashboardStats = async () => {
        try {
            setLoading(true);
            const response = await dashboardAPI.getStats();
            setStats(response.data);
            setError(null);
        } catch (err) {
            console.error('Error fetching dashboard stats:', err);
            setError('Failed to load dashboard statistics');
        } finally {
            setLoading(false);
        }
    };

    if (loading) {
        return (
            <div className="loading">
                <div className="spinner"></div>
            </div>
        );
    }

    if (error) {
        return <div className="error-message">{error}</div>;
    }

    if (!stats) {
        return <div>No data available</div>;
    }

    // Risk Distribution Chart Data
    const riskChartData = {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [
            {
                label: 'Risks by Level',
                data: [
                    stats.riskDistribution?.Critical || 0,
                    stats.riskDistribution?.High || 0,
                    stats.riskDistribution?.Medium || 0,
                    stats.riskDistribution?.Low || 0,
                ],
                backgroundColor: ['#dc2626', '#f97316', '#fbbf24', '#22c55e'],
            },
        ],
    };

    // Incident Distribution Chart Data
    const incidentChartData = {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [
            {
                label: 'Incidents by Severity',
                data: [
                    stats.incidentDistribution?.critical || 0,
                    stats.incidentDistribution?.high || 0,
                    stats.incidentDistribution?.medium || 0,
                    stats.incidentDistribution?.low || 0,
                ],
                backgroundColor: ['#dc2626', '#f97316', '#fbbf24', '#22c55e'],
            },
        ],
    };

    // Treatment Progress Chart Data
    const treatmentChartData = {
        labels: ['Planned', 'In Progress', 'Completed', 'Cancelled'],
        datasets: [
            {
                label: 'Treatment Status',
                data: [
                    stats.treatmentProgress?.Planned || 0,
                    stats.treatmentProgress?.['In Progress'] || 0,
                    stats.treatmentProgress?.Completed || 0,
                    stats.treatmentProgress?.Cancelled || 0,
                ],
                backgroundColor: ['#3b82f6', '#fbbf24', '#22c55e', '#6b7280'],
            },
        ],
    };

    return (
        <div>
            <div className="page-header">
                <h1 className="page-title">Dashboard</h1>
                <p className="page-description">Unified security operations overview</p>
            </div>

            {/* Summary Statistics */}
            <div className="stats-grid">
                <div className="stat-card">
                    <div className="stat-info">
                        <h3>Total Assets</h3>
                        <div className="stat-value">{stats.summary?.totalAssets || 0}</div>
                    </div>
                    <div className="stat-icon">💼</div>
                </div>

                <div className="stat-card">
                    <div className="stat-info">
                        <h3>Total Risks</h3>
                        <div className="stat-value">{stats.summary?.totalRisks || 0}</div>
                    </div>
                    <div className="stat-icon">🎯</div>
                </div>

                <div className="stat-card">
                    <div className="stat-info">
                        <h3>Critical Risks</h3>
                        <div className="stat-value" style={{ color: '#dc2626' }}>
                            {stats.summary?.criticalRisks || 0}
                        </div>
                    </div>
                    <div className="stat-icon">⚠️</div>
                </div>

                <div className="stat-card">
                    <div className="stat-info">
                        <h3>Total Incidents</h3>
                        <div className="stat-value">{stats.summary?.totalIncidents || 0}</div>
                    </div>
                    <div className="stat-icon">🚨</div>
                </div>

                <div className="stat-card">
                    <div className="stat-info">
                        <h3>Open Incidents</h3>
                        <div className="stat-value" style={{ color: '#f97316' }}>
                            {stats.summary?.openIncidents || 0}
                        </div>
                    </div>
                    <div className="stat-icon">🔓</div>
                </div>

                <div className="stat-card">
                    <div className="stat-info">
                        <h3>Critical Incidents</h3>
                        <div className="stat-value" style={{ color: '#dc2626' }}>
                            {stats.summary?.criticalIncidents || 0}
                        </div>
                    </div>
                    <div className="stat-icon">🔥</div>
                </div>
            </div>

            {/* Charts */}
            <div className="stats-grid">
                <div className="card">
                    <div className="card-header">Risk Distribution</div>
                    <div className="chart-container" style={{ height: '300px' }}>
                        <Pie data={riskChartData} options={{ maintainAspectRatio: false }} />
                    </div>
                </div>

                <div className="card">
                    <div className="card-header">Incident Severity</div>
                    <div className="chart-container" style={{ height: '300px' }}>
                        <Bar data={incidentChartData} options={{ maintainAspectRatio: false }} />
                    </div>
                </div>

                <div className="card">
                    <div className="card-header">Treatment Progress</div>
                    <div className="chart-container" style={{ height: '300px' }}>
                        <Bar data={treatmentChartData} options={{ maintainAspectRatio: false }} />
                    </div>
                </div>
            </div>

            {/* Top Risks */}
            <div className="card">
                <div className="card-header">Top 10 Highest Risks</div>
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Description</th>
                                <th>Asset</th>
                                <th>Threat</th>
                                <th>Risk Level</th>
                                <th>Risk Score</th>
                            </tr>
                        </thead>
                        <tbody>
                            {stats.topRisks && stats.topRisks.length > 0 ? (
                                stats.topRisks.map((risk) => (
                                    <tr key={risk.id}>
                                        <td>{risk.id}</td>
                                        <td>{risk.description}</td>
                                        <td>{risk.asset_name}</td>
                                        <td>{risk.threat_name}</td>
                                        <td>
                                            <span className={`badge badge-${risk.risk_level.toLowerCase()}`}>
                                                {risk.risk_level}
                                            </span>
                                        </td>
                                        <td>{risk.risk_score}</td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="6" style={{ textAlign: 'center' }}>
                                        No risks found
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>

            {/* Recent Incidents */}
            <div className="card">
                <div className="card-header">Recent Incidents</div>
                <div className="table-container">
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Alert</th>
                                <th>Severity</th>
                                <th>Status</th>
                                <th>Asset</th>
                                <th>Timestamp</th>
                            </tr>
                        </thead>
                        <tbody>
                            {stats.recentIncidents && stats.recentIncidents.length > 0 ? (
                                stats.recentIncidents.map((incident) => (
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
                                        <td>{incident.asset_name || 'N/A'}</td>
                                        <td>{new Date(incident.timestamp).toLocaleString()}</td>
                                    </tr>
                                ))
                            ) : (
                                <tr>
                                    <td colSpan="6" style={{ textAlign: 'center' }}>
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

export default Dashboard;
