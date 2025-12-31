/**
 * Report Controller
 * Generates PDF, Excel, and JSON reports
 */

const database = require('../config/database');
const { generatePDFReport, generateExcelReport, generateJSONReport } = require('../utils/reportGenerator');

/**
 * Fetch report data
 */
async function getReportData() {
    const assets = await database.all('SELECT * FROM assets ORDER BY criticality DESC');
    
    const risks = await database.all(`
        SELECT 
            r.*,
            a.name as asset_name,
            t.name as threat_name,
            v.name as vulnerability_name
        FROM risks r
        LEFT JOIN assets a ON r.asset_id = a.id
        LEFT JOIN threats t ON r.threat_id = t.id
        LEFT JOIN vulnerabilities v ON r.vulnerability_id = v.id
        ORDER BY r.risk_score DESC
    `);
    
    const incidents = await database.all(`
        SELECT 
            i.*,
            a.name as asset_name
        FROM incidents i
        LEFT JOIN assets a ON i.asset_id = a.id
        ORDER BY i.timestamp DESC
    `);
    
    const treatments = await database.all(`
        SELECT 
            t.*,
            r.description as risk_description
        FROM treatments t
        LEFT JOIN risks r ON t.risk_id = r.id
        ORDER BY t.due_date ASC
    `);
    
    // Calculate stats
    const stats = {
        totalAssets: assets.length,
        totalRisks: risks.length,
        totalIncidents: incidents.length,
        totalTreatments: treatments.length,
        criticalRisks: risks.filter(r => r.risk_level === 'Critical').length,
        highRisks: risks.filter(r => r.risk_level === 'High').length,
        openIncidents: incidents.filter(i => i.status === 'new' || i.status === 'investigating').length,
        criticalIncidents: incidents.filter(i => i.severity === 'critical').length
    };
    
    return { assets, risks, incidents, treatments, stats };
}

/**
 * Generate PDF report
 */
async function generatePDF(req, res) {
    try {
        const reportType = req.query.type || 'unified';
        const data = await getReportData();
        
        const pdfBuffer = await generatePDFReport(data, reportType);
        
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="secureops-report-${Date.now()}.pdf"`);
        res.send(pdfBuffer);
    } catch (error) {
        console.error('Error generating PDF report:', error);
        res.status(500).json({ error: 'Failed to generate PDF report' });
    }
}

/**
 * Generate Excel report
 */
async function generateExcel(req, res) {
    try {
        const reportType = req.query.type || 'unified';
        const data = await getReportData();
        
        const excelBuffer = await generateExcelReport(data, reportType);
        
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="secureops-report-${Date.now()}.xlsx"`);
        res.send(excelBuffer);
    } catch (error) {
        console.error('Error generating Excel report:', error);
        res.status(500).json({ error: 'Failed to generate Excel report' });
    }
}

/**
 * Generate JSON report
 */
async function generateJSON(req, res) {
    try {
        const reportType = req.query.type || 'unified';
        const data = await getReportData();
        
        const jsonReport = generateJSONReport(data, reportType);
        
        res.json(jsonReport);
    } catch (error) {
        console.error('Error generating JSON report:', error);
        res.status(500).json({ error: 'Failed to generate JSON report' });
    }
}

module.exports = {
    generatePDF,
    generateExcel,
    generateJSON
};
