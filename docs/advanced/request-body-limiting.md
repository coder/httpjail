# Request Body Limiting

The `max_tx_bytes` feature allows you to limit the total size of HTTP requests sent to upstream servers.

This is primarily designed for mitigating code exfiltration attacks through covert channels.

## Size Calculation

The `max_tx_bytes` limit applies to **complete** HTTP requests, including:

1. **Request line**: `METHOD /path HTTP/1.1\r\n`
2. **Headers**: Each header as `Name: Value\r\n`
3. **Header separator**: Final `\r\n` between headers and body
4. **Body**: Request body bytes

## Response Format

To enable request body limiting, return an object with `max_tx_bytes` in your rule response:

```javascript
// JavaScript engine
{allow: {max_tx_bytes: 1024}}  // Limit to 1KB total request size
```

```json
// Line processor engine
{"allow": {"max_tx_bytes": 1024}}
```

> **Note**: The `max_tx_bytes` feature is only available in the JavaScript (`--js`) and Line Processor (`--proc`) engines, not in Shell scripts.

## Behavior

The limiting behavior depends on whether the request includes a `Content-Length` header:

### With Content-Length Header

When the request includes a `Content-Length` header (most standard HTTP clients):

1. **Early Detection**: httpjail calculates the total request size
2. **Immediate Rejection**: If it exceeds `max_tx_bytes`, the client receives a `413 Payload Too Large` error immediately
3. **No Upstream Contact**: The upstream server is never contacted, preventing unnecessary load
4. **Clear Feedback**: The error message indicates the actual size and limit

**Example error response:**
```
HTTP/1.1 413 Payload Too Large
Content-Type: text/plain

Request body size (5000 bytes) exceeds maximum allowed (1024 bytes)
```

### Without Content-Length Header

When the request uses chunked encoding or doesn't include `Content-Length`:

1. **Stream Truncation**: The request body is truncated at the limit during streaming
2. **Upstream Receives Partial**: The upstream server receives exactly `max_tx_bytes` total bytes (url + headers + truncated body)
3. **Connection Closes**: The connection terminates after reaching the limit

## Examples

### JavaScript Engine - Upload Endpoint Limiting

```javascript
// Limit upload endpoints to 1KB total request size
const uploadHosts = ['uploads.example.com', 'upload.github.com'];

uploadHosts.includes(r.host)
  ? {allow: {max_tx_bytes: 1024}}
  : r.host.endsWith('.example.com')
```

### Line Processor Engine - Python Example

```python
#!/usr/bin/env python3
import sys, json

upload_hosts = {'uploads.example.com', 'data.api.com'}

for line in sys.stdin:
    try:
        req = json.loads(line)
        if req['host'] in upload_hosts:
            # Limit upload endpoints to 1KB requests
            # Returns 413 error if Content-Length exceeds limit
            # Truncates body if no Content-Length header
            response = {"allow": {"max_tx_bytes": 1024}}
            print(json.dumps(response))
        elif req['host'].endswith('.example.com'):
            print("true")
        else:
            print("false")
    except:
        print("false")
    sys.stdout.flush()
```


## Use Cases

### 1. Limiting File Uploads

Prevent users from uploading large files to specific endpoints:

```javascript
// JavaScript engine
const uploadPaths = ['/upload', '/api/files'];
uploadPaths.some(path => r.path.startsWith(path))
  ? {allow: {max_tx_bytes: 10485760}}  // 10MB limit
  : true
```

### 2. API Cost Control

Limit request sizes to metered APIs to prevent unexpected costs:

```javascript
// JavaScript engine
r.host === 'api.expensive-service.com'
  ? {allow: {max_tx_bytes: 1024}}  // 1KB limit for expensive API
  : true
```

### 3. Data Exfiltration Prevention

Prevent large data uploads that might indicate data exfiltration:

```javascript
// JavaScript engine
const externalHosts = ['pastebin.com', 'transfer.sh', 'file.io'];
externalHosts.some(host => r.host.includes(host))
  ? {allow: {max_tx_bytes: 4096}}  // 4KB limit for paste sites
  : true
```

## Limitations

- **Shell scripts**: The `max_tx_bytes` feature is not available when using shell script rules (`--shell`)
- **HTTP wire format**: The byte count is based on HTTP wire format, not just the body size
- **Partial uploads**: When truncating (no Content-Length), the upstream server receives incomplete data which may cause application errors

## See Also

- [JavaScript Engine](../guide/rule-engines/javascript.md)
- [Line Processor Engine](../guide/rule-engines/line-processor.md)
- [Configuration](../guide/configuration.md)
