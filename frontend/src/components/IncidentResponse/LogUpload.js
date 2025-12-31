import React, { useState } from 'react';
import { logsAPI } from '../../services/api';

function LogUpload() {
    const [file, setFile] = useState(null);
    const [result, setResult] = useState(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    const handleFileChange = (e) => {
        setFile(e.target.files[0]);
        setResult(null);
        setError(null);
    };

    const handleUpload = async (e) => {
        e.preventDefault();
        if (!file) {
            setError('Please select a file');
            return;
        }

        const formData = new FormData();
        formData.append('logFile', file);
        formData.append('format', 'auto');

        try {
            setLoading(true);
            setError(null);
            const response = await logsAPI.upload(formData);
            setResult(response.data);
        } catch (err) {
            console.error('Error uploading log:', err);
            setError('Failed to upload and process log file');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div>
            <div className="page-header">
                <h1 className="page-title">Log Upload</h1>
                <p className="page-description">Upload and analyze security logs</p>
            </div>

            <div className="card">
                <div className="card-header">Upload Log File</div>
                <form onSubmit={handleUpload}>
                    <div className="form-group">
                        <label>Select Log File</label>
                        <input
                            type="file"
                            className="form-control"
                            onChange={handleFileChange}
                            accept=".log,.txt,.json"
                        />
                        <small>Supported formats: Linux auth.log, Windows Security JSON, IDS logs</small>
                    </div>
                    <button type="submit" className="btn btn-primary" disabled={loading}>
                        {loading ? 'Processing...' : 'Upload and Analyze'}
                    </button>
                </form>

                {error && <div className="error-message" style={{ marginTop: '20px' }}>{error}</div>}

                {result && (
                    <div className="success-message" style={{ marginTop: '20px' }}>
                        <h4>Processing Complete!</h4>
                        <p>File: {result.filename}</p>
                        <p>Events parsed: {result.eventsCount}</p>
                        <p>Threats detected: {result.threatsDetected}</p>
                        <p>Incidents created: {result.incidentsCreated}</p>
                    </div>
                )}
            </div>
        </div>
    );
}

export default LogUpload;
