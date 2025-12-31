/**
 * Risk Calculator Utility
 * Calculates risk score and level based on likelihood and impact
 */

/**
 * Calculate risk score using the formula: Likelihood × Impact
 * @param {number} likelihood - Value from 1-5
 * @param {number} impact - Value from 1-5
 * @returns {number} Risk score (1-25)
 */
function calculateRiskScore(likelihood, impact) {
    if (!likelihood || !impact) {
        throw new Error('Likelihood and impact are required');
    }
    
    if (likelihood < 1 || likelihood > 5 || impact < 1 || impact > 5) {
        throw new Error('Likelihood and impact must be between 1 and 5');
    }
    
    return likelihood * impact;
}

/**
 * Determine risk level based on risk score
 * @param {number} riskScore - Risk score (1-25)
 * @returns {string} Risk level (Critical/High/Medium/Low)
 */
function calculateRiskLevel(riskScore) {
    if (riskScore >= 20) {
        return 'Critical';
    } else if (riskScore >= 12) {
        return 'High';
    } else if (riskScore >= 6) {
        return 'Medium';
    } else {
        return 'Low';
    }
}

/**
 * Get risk color for visualization
 * @param {string} riskLevel - Risk level
 * @returns {string} Color code
 */
function getRiskColor(riskLevel) {
    const colors = {
        'Critical': '#dc2626',  // Red
        'High': '#f97316',      // Orange
        'Medium': '#fbbf24',    // Yellow
        'Low': '#22c55e'        // Green
    };
    return colors[riskLevel] || '#6b7280';
}

/**
 * Generate risk matrix data (5x5 grid)
 * @returns {Array} Matrix data for visualization
 */
function generateRiskMatrix() {
    const matrix = [];
    for (let likelihood = 5; likelihood >= 1; likelihood--) {
        for (let impact = 1; impact <= 5; impact++) {
            const score = calculateRiskScore(likelihood, impact);
            const level = calculateRiskLevel(score);
            matrix.push({
                likelihood,
                impact,
                score,
                level,
                color: getRiskColor(level)
            });
        }
    }
    return matrix;
}

module.exports = {
    calculateRiskScore,
    calculateRiskLevel,
    getRiskColor,
    generateRiskMatrix
};
