import React, { useState } from 'react';
import { reportsAPI } from '../../services/api';

function Reports() {
    const [loading, setLoading] = useState(false);

    const downloadPDF = async () => {
        try {
            setLoading(true);
            const response = await reportsAPI.getPDF();
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `secureops-report-${Date.now()}.pdf`);
            document.body.appendChild(link);
            link.click();
            link.remove();
        } catch (err) {
            console.error('Error downloading PDF:', err);
            alert('Failed to generate PDF report');
        } finally {
            setLoading(false);
        }
    };

    const downloadExcel = async () => {
        try {
            setLoading(true);
            const response = await reportsAPI.getExcel();
            const url = window.URL.createObjectURL(new Blob([response.data]));
            const link = document.createElement('a');
            link.href = url;
            link.setAttribute('download', `secureops-report-${Date.now()}.xlsx`);
            document.body.appendChild(link);
            link.click();
            link.remove();
        } catch (err) {
            console.error('Error downloading Excel:', err);
            alert('Failed to generate Excel report');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div>
            <div className="page-header">
                <h1 className="page-title">Reports</h1>
                <p className="page-description">Generate comprehensive security reports</p>
            </div>

            <div className="card">
                <div className="card-header">Generate Reports</div>
                <div style={{ display: 'flex', gap: '15px', flexWrap: 'wrap' }}>
                    <button
                        className="btn btn-primary"
                        onClick={downloadPDF}
                        disabled={loading}
                    >
                        📄 Download PDF Report
                    </button>
                    <button
                        className="btn btn-success"
                        onClick={downloadExcel}
                        disabled={loading}
                    >
                        📊 Download Excel Report
                    </button>
                </div>
                <p style={{ marginTop: '20px', color: '#718096' }}>
                    Reports include comprehensive data on assets, risks, incidents, and treatments.
                </p>
            </div>
        </div>
    );
}

export default Reports;
