#!/usr/bin/env python3
"""
Example line-based script for httpjail --sh option.
Reads JSON requests from stdin and outputs allow/deny decisions.
"""
import json
import sys

# Allowlist of trusted domains
ALLOWED_DOMAINS = ['github.com', 'api.github.com', 'crates.io', 'docs.rs']

# Enable line buffering for real-time responses
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(line_buffering=True)

for line in sys.stdin:
    try:
        request = json.loads(line.strip())
        host = request.get('host', '')
        
        # Check if host is in allowlist
        allowed = any(domain in host for domain in ALLOWED_DOMAINS)
        
        if allowed:
            print('true')
        else:
            print(json.dumps({
                'allow': False,
                'message': f'Host {host} is not in the allowlist'
            }))
        sys.stdout.flush()
        
    except Exception as e:
        print(json.dumps({'allow': False, 'message': str(e)}))
        sys.stdout.flush()