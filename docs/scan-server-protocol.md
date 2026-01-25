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

### `create-session`
Create a named session with preloaded rules. Sessions cache parsed rules for efficient repeated scans.
```json
{"jsonrpc":"2.0","id":2,"method":"create-session","params":{
  "session_id": "my-session",
  "rules_file": "/path/to/rules.yaml"
}}
```
Or use `"rules": {...}` for inline JSON. One of `rules_file` or `rules` required.

**Response:** `{"jsonrpc":"2.0","id":2,"result":{"session_id":"...","rules_count":N}}`

### `destroy-session`
Remove a session and free its resources.
```json
{"jsonrpc":"2.0","id":3,"method":"destroy-session","params":{
  "session_id": "my-session"
}}
```

**Response:** `{"jsonrpc":"2.0","id":3,"result":{"destroyed":true,"session_id":"..."}}`

### `status`
```json
{"jsonrpc":"2.0","id":4,"method":"status"}
```
**Response:**
```json
{"jsonrpc":"2.0","id":4,"result":{
  "status":"running",
  "total_requests":N,
  "total_scans":N,
  "sessions":[{
    "id":"...",
    "created_at":1234.5,
    "last_accessed_at":1234.5,
    "rules_count":N
  }]
}}
```

### `shutdown`
```json
{"jsonrpc":"2.0","id":5,"method":"shutdown"}
```
**Response:** `{"jsonrpc":"2.0","id":5,"result":{"message":"Server shutting down","total_requests":N,"total_scans":N}}`

---

## Session Management

Sessions are automatically managed by the server:

- **Idle Timeout**: Sessions not accessed within `--session-ttl` seconds are automatically cleaned up. Default: 3600 seconds (1 hour). Set to 0 to disable.
- **Max Sessions**: When `--max-sessions` limit is reached, the least recently used session is evicted to make room. Default: 100. Set to 0 for unlimited.
- **Protected Session**: The `_default` session (created with `--rules`) is never automatically evicted.

Cleanup runs every 60 seconds in a background fiber.

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

## Starting the Server

The scan server is an **experimental** feature and requires the `--experimental` flag.

### From Installed Semgrep

```bash
# TCP server
semgrep serve --experimental --port 9876 --rules rules.yaml

# Unix socket server
semgrep serve --experimental --socket /tmp/semgrep.sock --rules rules.yaml

# With all options
semgrep serve --experimental --port 9876 --rules rules.yaml \
    --workers 4 --timeout 30.0 --session-ttl 1800 --max-sessions 50
```

### From Development Build

When running from a development build, you need to set the library path for tree-sitter:

```bash
# Set library path and run via dune
export LD_LIBRARY_PATH=/path/to/semgrep/libs/ocaml-tree-sitter-core/tree-sitter-0.22.6/lib:$LD_LIBRARY_PATH

# Run the server
dune exec -- osemgrep serve --experimental --port 9876 --rules rules.yaml -j 1

# Or run the built binary directly
/path/to/semgrep/_build/install/default/bin/osemgrep \
    serve --experimental --port 9876 --rules rules.yaml -j 1
```

### Server Options

| Option | Description |
|--------|-------------|
| `--port`, `-p` | TCP port (1-65535) |
| `--socket`, `-s` | Unix socket path |
| `--host` | Host to bind (default: 127.0.0.1) |
| `--rules`, `-c` | Preload rules file into `_default` session |
| `--workers`, `-j` | Worker count (default: CPU cores - 1) |
| `--timeout` | Scan timeout in seconds (default: 30.0) |
| `--session-ttl` | Session idle timeout in seconds (default: 3600, 0 = no expiration) |
| `--max-sessions` | Maximum concurrent sessions (default: 100, 0 = unlimited)

---

## CLI Client

A standalone Python CLI client is available for testing:

```bash
# Setup (one-time)
cd scripts
uv venv .venv && uv pip install click pyyaml

# Activate
source scripts/.venv/bin/activate

# Commands
python scripts/scan_server_client.py status --port 9876
python scripts/scan_server_client.py scan --port 9876 \
    --content "eval(input())" --filename test.py --language python \
    --session-id _default
python scripts/scan_server_client.py create-session --port 9876 \
    --session-id my-session --rules-file rules.yaml
python scripts/scan_server_client.py destroy-session --port 9876 \
    --session-id my-session
python scripts/scan_server_client.py shutdown --port 9876

# Options
#   --json       Output as JSON
#   --verbose    Show JSON-RPC messages
#   --socket     Use Unix socket instead of TCP port
```
