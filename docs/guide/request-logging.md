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

LOG_FILE="/tmp/requests-$$.ndjson"

# Process each request
while read -r line; do
    # Append to newline-delimited JSON file
    echo "$line" | jq -c '{
        timestamp: now | todate,
        url: .url,
        method: .method,
        host: .host,
        path: .path
    }' >> "$LOG_FILE"
    
    # Allow all requests
    echo "true"
done

# On exit, load all data to BigQuery
trap 'bq load --source_format=NEWLINE_DELIMITED_JSON \
    --autodetect \
    my-project:httpjail_logs.requests \
    "$LOG_FILE"' EXIT
```

Usage:

```bash
httpjail --proc ./log-to-bigquery.sh --request-log local-backup.log -- your-app
```

This example shows how to:

- Collect requests in newline-delimited JSON format
- Load data to BigQuery on process exit
- Combine local logging with cloud analytics
