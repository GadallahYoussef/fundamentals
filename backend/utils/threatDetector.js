/**
 * Threat Detector Utility
 * Analyzes parsed log events to detect security threats
 */

/**
 * Detect brute force attacks (5+ failed logins from same IP in 5 minutes)
 */
function detectBruteForce(events) {
    const threats = [];
    const failedLogins = {};
    const timeWindow = 5 * 60 * 1000; // 5 minutes in milliseconds
    
    for (const event of events) {
        if (event.type === 'failed_login' || event.type === 'invalid_user') {
            const ip = event.source_ip;
            const timestamp = new Date(event.timestamp).getTime();
            
            if (!failedLogins[ip]) {
                failedLogins[ip] = [];
            }
            
            // Add current attempt
            failedLogins[ip].push({ timestamp, user: event.user, raw: event.raw });
            
            // Remove old attempts outside time window
            failedLogins[ip] = failedLogins[ip].filter(
                attempt => timestamp - attempt.timestamp < timeWindow
            );
            
            // Check if threshold exceeded
            if (failedLogins[ip].length >= 5) {
                threats.push({
                    type: 'brute_force',
                    severity: 'high',
                    source_ip: ip,
                    attempts: failedLogins[ip].length,
                    users: [...new Set(failedLogins[ip].map(a => a.user))],
                    description: `Brute force attack detected: ${failedLogins[ip].length} failed login attempts from ${ip}`,
                    evidence: failedLogins[ip].slice(0, 10).map(a => a.raw)
                });
            }
        }
    }
    
    return threats;
}

/**
 * Detect suspicious login times (10 PM - 6 AM)
 */
function detectSuspiciousHours(events) {
    const threats = [];
    
    for (const event of events) {
        if (event.type === 'successful_login') {
            const timestamp = new Date(event.timestamp);
            const hour = timestamp.getHours();
            
            // Check if login occurred during suspicious hours (22:00 - 06:00)
            if (hour >= 22 || hour < 6) {
                threats.push({
                    type: 'suspicious_hours',
                    severity: 'medium',
                    source_ip: event.source_ip,
                    user: event.user,
                    timestamp: event.timestamp,
                    description: `Login during suspicious hours (${hour}:00) by ${event.user} from ${event.source_ip}`,
                    evidence: [event.raw]
                });
            }
        }
    }
    
    return threats;
}

/**
 * Detect privileged user access (root/Administrator)
 */
function detectPrivilegedAccess(events) {
    const threats = [];
    const privilegedUsers = ['root', 'administrator', 'admin', 'system'];
    
    for (const event of events) {
        if (event.user) {
            const username = event.user.toLowerCase();
            if (privilegedUsers.includes(username)) {
                const severity = event.type === 'failed_login' ? 'high' : 'medium';
                threats.push({
                    type: 'privileged_access',
                    severity,
                    source_ip: event.source_ip,
                    user: event.user,
                    login_type: event.type,
                    timestamp: event.timestamp,
                    description: `Privileged user ${event.user} ${event.type === 'failed_login' ? 'failed' : 'successful'} login from ${event.source_ip}`,
                    evidence: [event.raw]
                });
            }
        }
    }
    
    return threats;
}

/**
 * Detect multiple failed logins for different users from same IP
 */
function detectUserEnumeration(events) {
    const threats = [];
    const ipUsers = {};
    
    for (const event of events) {
        if (event.type === 'failed_login' || event.type === 'invalid_user') {
            const ip = event.source_ip;
            if (!ipUsers[ip]) {
                ipUsers[ip] = new Set();
            }
            ipUsers[ip].add(event.user);
        }
    }
    
    // Check if IP tried to access multiple different users
    for (const [ip, users] of Object.entries(ipUsers)) {
        if (users.size >= 5) {
            threats.push({
                type: 'user_enumeration',
                severity: 'medium',
                source_ip: ip,
                users: Array.from(users),
                description: `Possible user enumeration attack: ${users.size} different usernames attempted from ${ip}`,
                evidence: []
            });
        }
    }
    
    return threats;
}

/**
 * Detect geographic anomalies (multiple locations in short time)
 */
function detectGeographicAnomalies(events) {
    const threats = [];
    const userIPs = {};
    
    for (const event of events) {
        if (event.type === 'successful_login' && event.user) {
            const user = event.user;
            if (!userIPs[user]) {
                userIPs[user] = [];
            }
            userIPs[user].push({
                ip: event.source_ip,
                timestamp: new Date(event.timestamp).getTime()
            });
        }
    }
    
    // Check for same user logging in from different IPs in short time
    for (const [user, logins] of Object.entries(userIPs)) {
        const uniqueIPs = [...new Set(logins.map(l => l.ip))];
        if (uniqueIPs.length > 1) {
            threats.push({
                type: 'geographic_anomaly',
                severity: 'medium',
                user,
                source_ips: uniqueIPs,
                description: `User ${user} logged in from ${uniqueIPs.length} different IP addresses`,
                evidence: []
            });
        }
    }
    
    return threats;
}

/**
 * Main threat detection function
 * Runs all detection rules on parsed events
 */
function detectThreats(events) {
    if (!events || events.length === 0) {
        return [];
    }
    
    const allThreats = [
        ...detectBruteForce(events),
        ...detectSuspiciousHours(events),
        ...detectPrivilegedAccess(events),
        ...detectUserEnumeration(events),
        ...detectGeographicAnomalies(events)
    ];
    
    // Deduplicate threats (same type + source_ip)
    const uniqueThreats = [];
    const seen = new Set();
    
    for (const threat of allThreats) {
        const key = `${threat.type}-${threat.source_ip || 'unknown'}`;
        if (!seen.has(key)) {
            seen.add(key);
            uniqueThreats.push(threat);
        }
    }
    
    return uniqueThreats;
}

/**
 * Calculate threat score based on severity and type
 */
function calculateThreatScore(threat) {
    const severityScores = {
        'critical': 10,
        'high': 7,
        'medium': 5,
        'low': 3
    };
    
    const typeMultipliers = {
        'brute_force': 1.5,
        'privileged_access': 1.3,
        'user_enumeration': 1.2,
        'suspicious_hours': 1.1,
        'geographic_anomaly': 1.1
    };
    
    const baseScore = severityScores[threat.severity] || 5;
    const multiplier = typeMultipliers[threat.type] || 1;
    
    return Math.round(baseScore * multiplier);
}

module.exports = {
    detectThreats,
    detectBruteForce,
    detectSuspiciousHours,
    detectPrivilegedAccess,
    detectUserEnumeration,
    detectGeographicAnomalies,
    calculateThreatScore
};
