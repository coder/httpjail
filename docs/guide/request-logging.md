# Request Logging

Log all HTTP/HTTPS requests to a file for auditing, debugging, or analysis.

## Basic Usage

```bash
httpjail --request-log requests.log --js "true" -- npm install
```

## Log Format

Each request is logged on a single line:

```
<timestamp> <+/-> <METHOD> <URL>
```

- `+` indicates allowed requests
- `-` indicates blocked requests

## Example Output

```
2025-09-22T14:23:45.123Z + GET https://registry.npmjs.org/react
2025-09-22T14:23:45.234Z + GET https://registry.npmjs.org/react-dom
2025-09-22T14:23:45.345Z - POST https://analytics.example.com/track
```

## Example: BigQuery Integration

Achieve more advanced logging with the line processor
rule engine (`--proc`). Here's an example of how to log to
every request to BigQuery:

```bash
#!/bin/bash
# log-to-bigquery.sh

while read -r line; do
    # Create BigQuery insert payload
    echo "$line" | jq -c '{
        rows: [{
            insertId: (now | tostring),
            json: . + {timestamp: (now | todate)}
        }]
    }' | bq insert my-project:httpjail_logs.requests
    
    # Allow all requests
    echo "true"
done
```

Usage:

```bash
httpjail --proc ./log-to-bigquery.sh --request-log local-backup.log -- your-app
```

This example shows real-time logging where each request is immediately inserted into BigQuery. Note: `bq insert` is intended for testing only - for production use BigQuery client libraries.
