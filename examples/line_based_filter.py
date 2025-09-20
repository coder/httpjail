#!/usr/bin/env python3
"""
Example line-based script for httpjail --sh-line option.
This script reads JSON requests from stdin (one per line) and outputs allow/deny decisions.
"""
import json
import sys

# Allowlist of trusted domains
ALLOWED_DOMAINS = [
    'github.com',
    'api.github.com',
    'raw.githubusercontent.com',
    'crates.io',
    'docs.rs',
    'rust-lang.org'
]

# Blocklist of domains
BLOCKED_DOMAINS = [
    'facebook.com',
    'twitter.com',
    'instagram.com'
]

def main():
    # Make stdout unbuffered for real-time responses
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(line_buffering=True)
    
    for line in sys.stdin:
        try:
            # Parse the JSON request
            request = json.loads(line.strip())
            
            host = request.get('host', '')
            method = request.get('method', '')
            path = request.get('path', '')
            
            # Check blocklist first
            for blocked in BLOCKED_DOMAINS:
                if blocked in host:
                    response = {
                        'allow': False,
                        'message': f'Access to {blocked} is blocked by policy'
                    }
                    print(json.dumps(response))
                    sys.stdout.flush()
                    break
            else:
                # Check allowlist
                allowed = False
                for domain in ALLOWED_DOMAINS:
                    if domain in host:
                        allowed = True
                        break
                
                if allowed:
                    # Additional check: block POST to certain paths
                    if method == 'POST' and '/webhook' in path:
                        response = {
                            'allow': False,
                            'message': 'POST to webhook endpoints is not allowed'
                        }
                    else:
                        response = {'allow': True}
                else:
                    response = {
                        'allow': False,
                        'message': f'Host {host} is not in the allowlist'
                    }
                
                print(json.dumps(response))
                sys.stdout.flush()
                
        except json.JSONDecodeError as e:
            # On parse error, deny the request
            print(json.dumps({
                'allow': False,
                'message': f'Invalid request format: {e}'
            }))
            sys.stdout.flush()
        except Exception as e:
            # On any other error, deny the request
            print(json.dumps({
                'allow': False, 
                'message': f'Script error: {e}'
            }))
            sys.stdout.flush()

if __name__ == '__main__':
    main()