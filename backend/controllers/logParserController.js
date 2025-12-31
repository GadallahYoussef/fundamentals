/**
 * Log Parser Controller
 * Handles log file upload and parsing
 */

const database = require('../config/database');
const { parseLog } = require('../utils/logParser');
const { detectThreats } = require('../utils/threatDetector');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

// Configure multer for file upload
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const uploadDir = path.join(__dirname, '..', 'uploads');
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir, { recursive: true });
        }
        cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'log-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({
    storage: storage,
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
    fileFilter: (req, file, cb) => {
        // Allow common log file extensions
        const allowedExts = ['.log', '.txt', '.json', '.csv'];
        const ext = path.extname(file.originalname).toLowerCase();
        if (allowedExts.includes(ext) || !path.extname(file.originalname)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type. Only log files are allowed.'));
        }
    }
}).single('logFile');

/**
 * Upload and parse log file
 */
async function uploadLog(req, res) {
    upload(req, res, async (err) => {
        if (err) {
            return res.status(400).json({ error: err.message });
        }
        
        if (!req.file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }
        
        try {
            const logPath = req.file.path;
            const logFormat = req.body.format || 'auto';
            
            // Read log file
            const logContent = fs.readFileSync(logPath, 'utf8');
            
            // Parse log
            const events = parseLog(logContent, logFormat);
            
            // Detect threats
            const threats = detectThreats(events);
            
            // Create incidents from detected threats
            const incidentIds = [];
            for (const threat of threats) {
                const result = await database.run(
                    `INSERT INTO incidents (alert, severity, status, detection_type, source_ips, users, log_snippet, timestamp) 
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                    [
                        threat.description,
                        threat.severity,
                        'new',
                        threat.type,
                        threat.source_ip || threat.source_ips?.join(',') || null,
                        threat.user || threat.users?.join(',') || null,
                        threat.evidence?.slice(0, 3).join('\n') || null,
                        new Date().toISOString()
                    ]
                );
                incidentIds.push(result.id);
            }
            
            // Optionally delete uploaded file after processing
            // fs.unlinkSync(logPath);
            
            res.json({
                message: 'Log file processed successfully',
                filename: req.file.originalname,
                eventsCount: events.length,
                threatsDetected: threats.length,
                incidentsCreated: incidentIds.length,
                incidents: incidentIds
            });
        } catch (error) {
            console.error('Error processing log file:', error);
            res.status(500).json({ error: 'Failed to process log file' });
        }
    });
}

/**
 * Detect threats from raw log data (without file upload)
 */
async function detectThreatsFromLog(req, res) {
    try {
        const { logContent, format } = req.body;
        
        if (!logContent) {
            return res.status(400).json({ error: 'Log content is required' });
        }
        
        // Parse log
        const events = parseLog(logContent, format || 'auto');
        
        // Detect threats
        const threats = detectThreats(events);
        
        res.json({
            eventsCount: events.length,
            threatsDetected: threats.length,
            threats
        });
    } catch (error) {
        console.error('Error detecting threats:', error);
        res.status(500).json({ error: 'Failed to detect threats' });
    }
}

module.exports = {
    uploadLog,
    detectThreatsFromLog
};
