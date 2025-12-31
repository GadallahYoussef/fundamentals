/**
 * SecureOps Platform Backend Server
 */

const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const morgan = require('morgan');
const database = require('./config/database');

// Import routes
const assetsRoutes = require('./routes/assets');
const threatsRoutes = require('./routes/threats');
const vulnerabilitiesRoutes = require('./routes/vulnerabilities');
const risksRoutes = require('./routes/risks');
const treatmentsRoutes = require('./routes/treatments');
const incidentsRoutes = require('./routes/incidents');
const logsRoutes = require('./routes/logs');
const dashboardRoutes = require('./routes/dashboard');
const reportsRoutes = require('./routes/reports');

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware
app.use(helmet()); // Security headers
app.use(cors()); // Enable CORS
app.use(morgan('dev')); // Request logging
app.use(bodyParser.json()); // Parse JSON request bodies
app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded request bodies

// API Routes
app.use('/api/assets', assetsRoutes);
app.use('/api/threats', threatsRoutes);
app.use('/api/vulnerabilities', vulnerabilitiesRoutes);
app.use('/api/risks', risksRoutes);
app.use('/api/treatments', treatmentsRoutes);
app.use('/api/incidents', incidentsRoutes);
app.use('/api/logs', logsRoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/reports', reportsRoutes);

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        message: 'SecureOps Platform API is running',
        timestamp: new Date().toISOString()
    });
});

// Root endpoint
app.get('/', (req, res) => {
    res.json({ 
        message: 'SecureOps Platform API',
        version: '1.0.0',
        endpoints: {
            assets: '/api/assets',
            threats: '/api/threats',
            vulnerabilities: '/api/vulnerabilities',
            risks: '/api/risks',
            treatments: '/api/treatments',
            incidents: '/api/incidents',
            logs: '/api/logs',
            dashboard: '/api/dashboard',
            reports: '/api/reports'
        }
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Error:', err);
    res.status(err.status || 500).json({ 
        error: err.message || 'Internal server error' 
    });
});

// Initialize database and start server
async function startServer() {
    try {
        console.log('🚀 Starting SecureOps Platform...');
        
        // Connect to database
        await database.connect();
        console.log('✓ Database connected');
        
        // Initialize database schema
        await database.initialize();
        console.log('✓ Database schema initialized');
        
        // Start server
        app.listen(PORT, () => {
            console.log(`✓ Server running on port ${PORT}`);
            console.log(`✓ API available at http://localhost:${PORT}`);
            console.log(`✓ Health check: http://localhost:${PORT}/api/health`);
            console.log('\n📊 SecureOps Platform is ready!\n');
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

// Handle shutdown gracefully
process.on('SIGINT', async () => {
    console.log('\n\nShutting down gracefully...');
    await database.close();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('\n\nShutting down gracefully...');
    await database.close();
    process.exit(0);
});

// Start the server
startServer();

module.exports = app;
