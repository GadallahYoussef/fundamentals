# Sample Log Files for Testing

This directory contains sample log files for testing the log upload and threat detection features.

## Available Samples

### auth.log
Linux authentication log with:
- Brute force attack patterns (multiple failed logins)
- Suspicious login hours (2:30 AM)
- Invalid user attempts
- Privileged account access attempts

### How to Use

1. Go to the **Log Upload** page in the SecureOps Platform
2. Select one of these sample files
3. Click "Upload and Analyze"
4. The system will:
   - Parse the log entries
   - Detect threats automatically
   - Create incidents for detected threats
   - Display results

### Expected Detections

From **auth.log**:
- Brute force attack from 192.168.1.100 (6+ failed attempts)
- Suspicious hours login at 2:30 AM
- User enumeration from 203.0.113.42
- Privileged access attempts (root, administrator)
