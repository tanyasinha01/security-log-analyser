# Security Log Analyser

Python tool that analyses SSH authentication logs 
to detect security threats — simulating SOC L1 
monitoring workflows.

## What it detects
- Brute force / repeated failed login attempts (HIGH severity)
- Invalid user login attempts
- Successful logins flagged for anomaly review
- Privilege escalation events (sudo to root)

## Results on 10,000 log lines
- Brute Force IPs Detected    : 6
- Successful Logins           : 1555
- Privilege Escalation Events : 788
- Invalid User Attempts       : 2103

## Files
- log_analyser.py — main analysis and alert report engine
- generate_logs.py — generates large scale realistic 
  auth log data for testing

## How to run
python generate_logs.py
python log_analyser.py

## Skills demonstrated
Python | Regex | Log Analysis | Threat Detection | 
Incident Reporting | SOC L1 workflows
