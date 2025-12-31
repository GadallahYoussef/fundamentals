/**
 * Report Generator Utility
 * Generates PDF, Excel, and JSON reports for risks and incidents
 */

const PDFDocument = require('pdfkit');
const ExcelJS = require('exceljs');
const fs = require('fs');
const path = require('path');

/**
 * Generate PDF report
 */
async function generatePDFReport(data, reportType = 'unified') {
    return new Promise((resolve, reject) => {
        const doc = new PDFDocument({ margin: 50 });
        const chunks = [];
        
        doc.on('data', chunk => chunks.push(chunk));
        doc.on('end', () => resolve(Buffer.concat(chunks)));
        doc.on('error', reject);
        
        // Header
        doc.fontSize(20).text('SecureOps Platform Report', { align: 'center' });
        doc.moveDown();
        doc.fontSize(12).text(`Report Type: ${reportType.toUpperCase()}`, { align: 'center' });
        doc.text(`Generated: ${new Date().toLocaleString()}`, { align: 'center' });
        doc.moveDown(2);
        
        // Summary Statistics
        if (data.stats) {
            doc.fontSize(16).text('Summary Statistics', { underline: true });
            doc.moveDown(0.5);
            doc.fontSize(12);
            doc.text(`Total Assets: ${data.stats.totalAssets || 0}`);
            doc.text(`Total Risks: ${data.stats.totalRisks || 0}`);
            doc.text(`Total Incidents: ${data.stats.totalIncidents || 0}`);
            doc.text(`Critical Risks: ${data.stats.criticalRisks || 0}`);
            doc.text(`Open Incidents: ${data.stats.openIncidents || 0}`);
            doc.moveDown(2);
        }
        
        // Risk Summary
        if (data.risks && data.risks.length > 0) {
            doc.fontSize(16).text('Top Risks', { underline: true });
            doc.moveDown(0.5);
            
            data.risks.slice(0, 10).forEach((risk, index) => {
                doc.fontSize(12);
                doc.text(`${index + 1}. ${risk.description || 'N/A'}`);
                doc.fontSize(10);
                doc.text(`   Level: ${risk.risk_level} | Score: ${risk.risk_score} | Asset: ${risk.asset_name || 'N/A'}`);
                doc.moveDown(0.5);
            });
            doc.moveDown();
        }
        
        // Incident Summary
        if (data.incidents && data.incidents.length > 0) {
            doc.fontSize(16).text('Recent Incidents', { underline: true });
            doc.moveDown(0.5);
            
            data.incidents.slice(0, 10).forEach((incident, index) => {
                doc.fontSize(12);
                doc.text(`${index + 1}. ${incident.alert}`);
                doc.fontSize(10);
                doc.text(`   Severity: ${incident.severity} | Status: ${incident.status} | Time: ${new Date(incident.timestamp).toLocaleString()}`);
                doc.moveDown(0.5);
            });
        }
        
        // Footer
        doc.fontSize(8).text('SecureOps Platform - Confidential', 50, doc.page.height - 50, {
            align: 'center'
        });
        
        doc.end();
    });
}

/**
 * Generate Excel report
 */
async function generateExcelReport(data, reportType = 'unified') {
    const workbook = new ExcelJS.Workbook();
    
    // Summary Sheet
    const summarySheet = workbook.addWorksheet('Summary');
    summarySheet.addRow(['SecureOps Platform Report']);
    summarySheet.addRow(['Report Type', reportType.toUpperCase()]);
    summarySheet.addRow(['Generated', new Date().toLocaleString()]);
    summarySheet.addRow([]);
    
    if (data.stats) {
        summarySheet.addRow(['Total Assets', data.stats.totalAssets || 0]);
        summarySheet.addRow(['Total Risks', data.stats.totalRisks || 0]);
        summarySheet.addRow(['Total Incidents', data.stats.totalIncidents || 0]);
        summarySheet.addRow(['Critical Risks', data.stats.criticalRisks || 0]);
        summarySheet.addRow(['Open Incidents', data.stats.openIncidents || 0]);
    }
    
    // Risks Sheet
    if (data.risks && data.risks.length > 0) {
        const risksSheet = workbook.addWorksheet('Risks');
        risksSheet.columns = [
            { header: 'ID', key: 'id', width: 10 },
            { header: 'Description', key: 'description', width: 40 },
            { header: 'Asset', key: 'asset_name', width: 20 },
            { header: 'Risk Level', key: 'risk_level', width: 15 },
            { header: 'Risk Score', key: 'risk_score', width: 12 },
            { header: 'Likelihood', key: 'likelihood', width: 12 },
            { header: 'Impact', key: 'impact', width: 12 },
            { header: 'Status', key: 'status', width: 15 },
        ];
        
        data.risks.forEach(risk => risksSheet.addRow(risk));
        
        // Style header row
        risksSheet.getRow(1).font = { bold: true };
    }
    
    // Incidents Sheet
    if (data.incidents && data.incidents.length > 0) {
        const incidentsSheet = workbook.addWorksheet('Incidents');
        incidentsSheet.columns = [
            { header: 'ID', key: 'id', width: 10 },
            { header: 'Alert', key: 'alert', width: 40 },
            { header: 'Severity', key: 'severity', width: 15 },
            { header: 'Status', key: 'status', width: 15 },
            { header: 'Detection Type', key: 'detection_type', width: 20 },
            { header: 'Source IPs', key: 'source_ips', width: 20 },
            { header: 'Users', key: 'users', width: 20 },
            { header: 'Timestamp', key: 'timestamp', width: 20 },
        ];
        
        data.incidents.forEach(incident => incidentsSheet.addRow(incident));
        
        // Style header row
        incidentsSheet.getRow(1).font = { bold: true };
    }
    
    // Assets Sheet
    if (data.assets && data.assets.length > 0) {
        const assetsSheet = workbook.addWorksheet('Assets');
        assetsSheet.columns = [
            { header: 'ID', key: 'id', width: 10 },
            { header: 'Name', key: 'name', width: 25 },
            { header: 'Category', key: 'category', width: 15 },
            { header: 'Criticality', key: 'criticality', width: 12 },
            { header: 'Owner', key: 'owner', width: 20 },
            { header: 'Description', key: 'description', width: 40 },
        ];
        
        data.assets.forEach(asset => assetsSheet.addRow(asset));
        
        // Style header row
        assetsSheet.getRow(1).font = { bold: true };
    }
    
    const buffer = await workbook.xlsx.writeBuffer();
    return buffer;
}

/**
 * Generate JSON report
 */
function generateJSONReport(data, reportType = 'unified') {
    return {
        reportType,
        generated: new Date().toISOString(),
        stats: data.stats || {},
        risks: data.risks || [],
        incidents: data.incidents || [],
        assets: data.assets || [],
        treatments: data.treatments || []
    };
}

module.exports = {
    generatePDFReport,
    generateExcelReport,
    generateJSONReport
};
