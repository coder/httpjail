| Response Format | Meaning |
|----------------|---------|
| `true` | Allow the request |
| `false` | Deny the request |
| `{allow: true}` | Allow (object form) |
| `{allow: false}` | Deny (object form) |
| <pre><code>{<br>  allow: false,<br>  deny_message: "Access denied"<br>}</code></pre> | Deny with custom message |
| `{deny_message: "Blocked"}` | Deny (message implies deny) |
| <pre><code>{<br>  allow: {<br>    max_tx_bytes: 1024<br>  }<br>}</code></pre> | Allow with [request body limiting](../../advanced/request-body-limiting.md) |
