import axios from 'axios';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://localhost:5000/api';

const api = axios.create({
    baseURL: API_BASE_URL,
    timeout: 10000,
    headers: {
        'Content-Type': 'application/json',
    },
});

// Assets API
export const assetsAPI = {
    getAll: () => api.get('/assets'),
    getById: (id) => api.get(`/assets/${id}`),
    create: (data) => api.post('/assets', data),
    update: (id, data) => api.put(`/assets/${id}`, data),
    delete: (id) => api.delete(`/assets/${id}`),
};

// Threats API
export const threatsAPI = {
    getAll: () => api.get('/threats'),
    getById: (id) => api.get(`/threats/${id}`),
    create: (data) => api.post('/threats', data),
    update: (id, data) => api.put(`/threats/${id}`, data),
    delete: (id) => api.delete(`/threats/${id}`),
};

// Vulnerabilities API
export const vulnerabilitiesAPI = {
    getAll: () => api.get('/vulnerabilities'),
    getById: (id) => api.get(`/vulnerabilities/${id}`),
    create: (data) => api.post('/vulnerabilities', data),
    update: (id, data) => api.put(`/vulnerabilities/${id}`, data),
    delete: (id) => api.delete(`/vulnerabilities/${id}`),
};

// Risks API
export const risksAPI = {
    getAll: () => api.get('/risks'),
    getById: (id) => api.get(`/risks/${id}`),
    create: (data) => api.post('/risks', data),
    update: (id, data) => api.put(`/risks/${id}`, data),
    delete: (id) => api.delete(`/risks/${id}`),
    getStats: () => api.get('/risks/stats'),
    getMatrix: () => api.get('/risks/matrix'),
};

// Treatments API
export const treatmentsAPI = {
    getAll: () => api.get('/treatments'),
    getById: (id) => api.get(`/treatments/${id}`),
    create: (data) => api.post('/treatments', data),
    update: (id, data) => api.put(`/treatments/${id}`, data),
    delete: (id) => api.delete(`/treatments/${id}`),
    getStats: () => api.get('/treatments/stats'),
};

// Incidents API
export const incidentsAPI = {
    getAll: () => api.get('/incidents'),
    getById: (id) => api.get(`/incidents/${id}`),
    create: (data) => api.post('/incidents', data),
    update: (id, data) => api.put(`/incidents/${id}`, data),
    delete: (id) => api.delete(`/incidents/${id}`),
    getStats: () => api.get('/incidents/stats'),
    analyze: (id) => api.post(`/incidents/${id}/analyze`),
    linkToAsset: (id, assetId) => api.put(`/incidents/${id}/link-asset`, { asset_id: assetId }),
    linkToRisk: (id, riskId) => api.put(`/incidents/${id}/link-risk`, { risk_id: riskId }),
};

// Logs API
export const logsAPI = {
    upload: (formData) => api.post('/logs/upload', formData, {
        headers: {
            'Content-Type': 'multipart/form-data',
        },
    }),
    detect: (logContent, format) => api.post('/logs/detect', { logContent, format }),
};

// Dashboard API
export const dashboardAPI = {
    getStats: () => api.get('/dashboard/stats'),
};

// Reports API
export const reportsAPI = {
    getPDF: (type = 'unified') => api.get(`/reports/pdf?type=${type}`, { responseType: 'blob' }),
    getExcel: (type = 'unified') => api.get(`/reports/excel?type=${type}`, { responseType: 'blob' }),
    getJSON: (type = 'unified') => api.get(`/reports/json?type=${type}`),
};

export default api;
