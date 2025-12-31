/**
 * Log Parser Utility
 * Parses various log formats: Linux auth.log, Windows Security events, Snort/IDS logs
 */

/**
 * Parse Linux auth.log format
 * Example: Dec 31 10:15:30 server sshd[12345]: Failed password for root from 192.168.1.100 port 22 ssh2
 */
function parseLinuxAuthLog(logContent) {
    const events = [];
    const lines = logContent.split('\n');
    
    for (const line of lines) {
        if (!line.trim()) continue;
        
        // Failed password attempts
        const failedMatch = line.match(/Failed password for (\w+) from ([\d.]+) port (\d+)/);
        if (failedMatch) {
            events.push({
                timestamp: extractTimestamp(line),
                type: 'failed_login',
                user: failedMatch[1],
                source_ip: failedMatch[2],
                port: failedMatch[3],
                raw: line
            });
            continue;
        }
        
        // Successful authentication
        const successMatch = line.match(/Accepted password for (\w+) from ([\d.]+) port (\d+)/);
        if (successMatch) {
            events.push({
                timestamp: extractTimestamp(line),
                type: 'successful_login',
                user: successMatch[1],
                source_ip: successMatch[2],
                port: successMatch[3],
                raw: line
            });
            continue;
        }
        
        // Invalid user attempts
        const invalidMatch = line.match(/Invalid user (\w+) from ([\d.]+)/);
        if (invalidMatch) {
            events.push({
                timestamp: extractTimestamp(line),
                type: 'invalid_user',
                user: invalidMatch[1],
                source_ip: invalidMatch[2],
                raw: line
            });
            continue;
        }
        
        // Root login attempts
        if (line.includes('root') && (line.includes('Failed') || line.includes('Accepted'))) {
            const ipMatch = line.match(/([\d.]+)/);
            events.push({
                timestamp: extractTimestamp(line),
                type: 'privileged_access',
                user: 'root',
                source_ip: ipMatch ? ipMatch[1] : 'unknown',
                raw: line
            });
        }
    }
    
    return events;
}

/**
 * Parse Windows Security Event JSON
 */
function parseWindowsSecurityLog(logContent) {
    const events = [];
    
    try {
        const logs = JSON.parse(logContent);
        const logArray = Array.isArray(logs) ? logs : [logs];
        
        for (const log of logArray) {
            if (log.EventID === 4625) {  // Failed login
                events.push({
                    timestamp: log.TimeCreated || new Date().toISOString(),
                    type: 'failed_login',
                    user: log.TargetUserName || 'unknown',
                    source_ip: log.IpAddress || 'unknown',
                    workstation: log.WorkstationName || 'unknown',
                    raw: JSON.stringify(log)
                });
            } else if (log.EventID === 4624) {  // Successful login
                events.push({
                    timestamp: log.TimeCreated || new Date().toISOString(),
                    type: 'successful_login',
                    user: log.TargetUserName || 'unknown',
                    source_ip: log.IpAddress || 'unknown',
                    logon_type: log.LogonType,
                    raw: JSON.stringify(log)
                });
            } else if (log.EventID === 4720) {  // Account created
                events.push({
                    timestamp: log.TimeCreated || new Date().toISOString(),
                    type: 'account_created',
                    user: log.TargetUserName || 'unknown',
                    creator: log.SubjectUserName || 'unknown',
                    raw: JSON.stringify(log)
                });
            }
        }
    } catch (err) {
        console.error('Error parsing Windows log:', err.message);
    }
    
    return events;
}

/**
 * Parse Snort/Suricata IDS JSON logs
 */
function parseIDSLog(logContent) {
    const events = [];
    
    try {
        const lines = logContent.trim().split('\n');
        
        for (const line of lines) {
            if (!line.trim()) continue;
            
            const alert = JSON.parse(line);
            events.push({
                timestamp: alert.timestamp || new Date().toISOString(),
                type: 'ids_alert',
                alert_signature: alert.alert?.signature || 'Unknown',
                severity: alert.alert?.severity || 3,
                source_ip: alert.src_ip || 'unknown',
                dest_ip: alert.dest_ip || 'unknown',
                protocol: alert.proto || 'unknown',
                category: alert.alert?.category || 'unknown',
                raw: line
            });
        }
    } catch (err) {
        console.error('Error parsing IDS log:', err.message);
    }
    
    return events;
}

/**
 * Extract timestamp from log line
 */
function extractTimestamp(line) {
    // Try to extract common timestamp formats
    const patterns = [
        /^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})/,  // Dec 31 10:15:30
        /(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})/,   // ISO format
    ];
    
    for (const pattern of patterns) {
        const match = line.match(pattern);
        if (match) {
            return match[1];
        }
    }
    
    return new Date().toISOString();
}

/**
 * Auto-detect log format and parse accordingly
 */
function parseLog(logContent, format = 'auto') {
    if (!logContent || logContent.trim().length === 0) {
        return [];
    }
    
    // Auto-detect format if not specified
    if (format === 'auto') {
        if (logContent.includes('sshd') || logContent.includes('Failed password')) {
            format = 'linux_auth';
        } else if (logContent.trim().startsWith('{') || logContent.includes('EventID')) {
            format = 'windows';
        } else if (logContent.includes('alert') && logContent.includes('src_ip')) {
            format = 'ids';
        }
    }
    
    switch (format) {
        case 'linux_auth':
            return parseLinuxAuthLog(logContent);
        case 'windows':
            return parseWindowsSecurityLog(logContent);
        case 'ids':
            return parseIDSLog(logContent);
        default:
            console.warn('Unknown log format, attempting Linux auth log parsing');
            return parseLinuxAuthLog(logContent);
    }
}

module.exports = {
    parseLog,
    parseLinuxAuthLog,
    parseWindowsSecurityLog,
    parseIDSLog
};
