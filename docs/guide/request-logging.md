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

## BigQuery Integration

Stream request logs to BigQuery using Line Processor mode:

```bash
#!/bin/bash
# log-to-bigquery.sh

# Configure BigQuery
PROJECT="my-project"
DATASET="httpjail_logs"
TABLE="requests"

# Process requests and log to BigQuery
while read -r line; do
    # Parse the request JSON
    request=$(echo "$line" | jq -c '{
        timestamp: now | todate,
        url: .url,
        method: .method,
        host: .host,
        path: .path
    }')
    
    # Log to BigQuery (streaming insert)
    echo "$request" | bq insert --project_id="$PROJECT" \
        "$DATASET.$TABLE"
    
    # Allow all requests
    echo "true"
done
```

Usage:
```bash
httpjail --proc ./log-to-bigquery.sh --request-log local-backup.log -- your-app
```

This approach:
- Streams requests to BigQuery in real-time
- Maintains a local backup in `local-backup.log`
- Allows custom processing and enrichment
- Scales to high-volume applications