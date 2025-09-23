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

# Configure BigQuery
PROJECT="my-project"
DATASET="httpjail_logs"
TABLE="requests"
BATCH_FILE="/tmp/requests-$$.ndjson"

# Process requests in batches
batch_count=0
max_batch=100

while read -r line; do
    # Parse and enrich the request
    echo "$line" | jq -c '{
        timestamp: now | todate,
        url: .url,
        method: .method,
        host: .host,
        path: .path,
        requester_ip: .requester_ip
    }' >> "$BATCH_FILE"
    
    batch_count=$((batch_count + 1))
    
    # Load batch when threshold reached
    if [ $batch_count -ge $max_batch ]; then
        bq load --source_format=NEWLINE_DELIMITED_JSON \
            --autodetect \
            "$PROJECT:$DATASET.$TABLE" \
            "$BATCH_FILE"
        
        > "$BATCH_FILE"  # Clear batch file
        batch_count=0
    fi
    
    # Allow all requests
    echo "true"
done

# Load any remaining records on exit
trap 'bq load --source_format=NEWLINE_DELIMITED_JSON --autodetect "$PROJECT:$DATASET.$TABLE" "$BATCH_FILE"' EXIT
```

Usage:

```bash
httpjail --proc ./log-to-bigquery.sh --request-log local-backup.log -- your-app
```

This approach:

- Batches requests for efficient BigQuery loading
- Maintains a local backup in `local-backup.log`
- Uses newline-delimited JSON format (required by BigQuery)
- Handles graceful shutdown with trap to load remaining data
- Avoids per-request overhead of streaming inserts
