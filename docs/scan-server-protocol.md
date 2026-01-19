# Semgrep Scan Server Protocol

**Transport:** TCP (`--port`) or Unix socket (`--socket`), newline-delimited JSON-RPC 2.0

---

## Methods

### `scan`
```json
{"jsonrpc":"2.0","id":1,"method":"scan","params":{
  "content": "def foo(): pass",
  "filename": "test.py",
  "language": "python",
  "rules": [...],
  "session_id": "my-session"
}}
```
- `content`, `filename`, `language`: required
- `rules` (inline JSON) or `session_id`: optional (rules takes precedence)

**Response:**
```json
{"jsonrpc":"2.0","id":1,"result":{
  "matches": [{
    "rule_id": "my-rule",
    "path": "test.py",
    "start": {"line":1,"col":0},
    "end": {"line":1,"col":10},
    "extra": {"message":"...","severity":"WARNING","metadata":{}}
  }],
  "errors": []
}}
```

### `initialize`
```json
{"jsonrpc":"2.0","id":2,"method":"initialize","params":{
  "session_id": "my-session",
  "rules_file": "/path/to/rules.yaml"
}}
```
Or use `"rules": {...}` for inline JSON. One of `rules_file` or `rules` required.

**Response:** `{"jsonrpc":"2.0","id":2,"result":{"session_id":"...","rules_count":N}}`

### `status`
```json
{"jsonrpc":"2.0","id":3,"method":"status"}
```
**Response:** `{"jsonrpc":"2.0","id":3,"result":{"status":"running","total_requests":N,"total_scans":N,"sessions":[{"id":"...","created_at":1234.5}]}}`

### `shutdown`
```json
{"jsonrpc":"2.0","id":4,"method":"shutdown"}
```
**Response:** `{"jsonrpc":"2.0","id":4,"result":{"message":"Server shutting down","total_requests":N,"total_scans":N}}`

---

## Error Codes
| Code | Meaning |
|------|---------|
| -32700 | Parse error |
| -32600 | Invalid request |
| -32601 | Method not found |
| -32602 | Invalid params |
| -32603 | Internal error |
| -32001 | Scan error |
| -32002 | Session not found |
| -32003 | Timeout |

---

## CLI Usage

```bash
# TCP server
semgrep serve --port 9876 --rules rules.yaml --workers 4 --timeout 30.0

# Unix socket server
semgrep serve --socket /tmp/semgrep.sock --rules rules.yaml
```

### Options
- `--port`, `-p`: TCP port (1-65535)
- `--socket`, `-s`: Unix socket path
- `--host`: Host to bind (default: 127.0.0.1)
- `--rules`, `-c`: Preload rules file into default session
- `--workers`, `-j`: Worker count (default: CPU cores - 1)
- `--timeout`: Scan timeout in seconds (default: 30.0)
