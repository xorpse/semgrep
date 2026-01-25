#!/usr/bin/env python3
"""
Scan Server CLI Client

A standalone client for testing the Semgrep scan server JSON-RPC 2.0 API.

Usage:
    python scan_server_client.py status --port 9876
    python scan_server_client.py scan --port 9876 --content "eval(input())" --filename test.py --language python
    python scan_server_client.py create-session --port 9876 --session-id test --rules-file rules.yaml
    python scan_server_client.py destroy-session --port 9876 --session-id test
    python scan_server_client.py shutdown --port 9876
"""

import json
import socket
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

import click

try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False


# --- Error Codes ---
ERROR_CODES = {
    -32700: "Parse error",
    -32600: "Invalid request",
    -32601: "Method not found",
    -32602: "Invalid params",
    -32603: "Internal error",
    -32001: "Scan error",
    -32002: "Session not found",
    -32003: "Timeout",
}


# --- Transport Layer ---


class Transport(ABC):
    """Abstract base class for JSON-RPC transports."""

    @abstractmethod
    def connect(self) -> None:
        """Establish connection to the server."""
        pass

    @abstractmethod
    def send(self, data: str) -> None:
        """Send data to the server."""
        pass

    @abstractmethod
    def receive(self) -> str:
        """Receive a complete response from the server."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close the connection."""
        pass

    def __enter__(self) -> "Transport":
        self.connect()
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()


class TCPTransport(Transport):
    """TCP socket transport for JSON-RPC."""

    def __init__(self, host: str, port: int, timeout: float = 30.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._socket: Optional[socket.socket] = None
        self._buffer = ""

    def connect(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(self.timeout)
        self._socket.connect((self.host, self.port))

    def send(self, data: str) -> None:
        if self._socket is None:
            raise RuntimeError("Not connected")
        # Newline-delimited protocol
        message = data + "\n"
        self._socket.sendall(message.encode("utf-8"))

    def receive(self) -> str:
        if self._socket is None:
            raise RuntimeError("Not connected")

        # Read until we get a complete newline-delimited message
        while "\n" not in self._buffer:
            chunk = self._socket.recv(4096)
            if not chunk:
                raise ConnectionError("Server closed connection")
            self._buffer += chunk.decode("utf-8")

        line, self._buffer = self._buffer.split("\n", 1)
        return line

    def close(self) -> None:
        if self._socket:
            self._socket.close()
            self._socket = None


class UnixSocketTransport(Transport):
    """Unix socket transport for JSON-RPC."""

    def __init__(self, socket_path: str, timeout: float = 30.0):
        self.socket_path = socket_path
        self.timeout = timeout
        self._socket: Optional[socket.socket] = None
        self._buffer = ""

    def connect(self) -> None:
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.settimeout(self.timeout)
        self._socket.connect(self.socket_path)

    def send(self, data: str) -> None:
        if self._socket is None:
            raise RuntimeError("Not connected")
        message = data + "\n"
        self._socket.sendall(message.encode("utf-8"))

    def receive(self) -> str:
        if self._socket is None:
            raise RuntimeError("Not connected")

        while "\n" not in self._buffer:
            chunk = self._socket.recv(4096)
            if not chunk:
                raise ConnectionError("Server closed connection")
            self._buffer += chunk.decode("utf-8")

        line, self._buffer = self._buffer.split("\n", 1)
        return line

    def close(self) -> None:
        if self._socket:
            self._socket.close()
            self._socket = None


# --- JSON-RPC Client ---


class JsonRpcError(Exception):
    """JSON-RPC error response."""

    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"[{code}] {message}")

    def __str__(self) -> str:
        error_name = ERROR_CODES.get(self.code, "Unknown error")
        msg = f"{error_name} ({self.code}): {self.message}"
        if self.data:
            msg += f"\nDetails: {self.data}"
        return msg


@dataclass
class JsonRpcClient:
    """JSON-RPC 2.0 client."""

    transport: Transport
    verbose: bool = False
    _request_id: int = 0

    def _next_id(self) -> int:
        self._request_id += 1
        return self._request_id

    def call(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Make a JSON-RPC call and return the result."""
        request_id = self._next_id()
        request: Dict[str, Any] = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params:
            request["params"] = params

        request_json = json.dumps(request)

        if self.verbose:
            click.echo(f"-> {request_json}", err=True)

        self.transport.send(request_json)
        response_json = self.transport.receive()

        if self.verbose:
            click.echo(f"<- {response_json}", err=True)

        response = json.loads(response_json)

        if "error" in response:
            error = response["error"]
            raise JsonRpcError(
                code=error.get("code", -32603),
                message=error.get("message", "Unknown error"),
                data=error.get("data"),
            )

        return response.get("result")


# --- Helper Functions ---


def create_transport(
    port: Optional[int], socket_path: Optional[str], host: str, timeout: float
) -> Transport:
    """Create the appropriate transport based on options."""
    if socket_path:
        return UnixSocketTransport(socket_path, timeout)
    elif port:
        return TCPTransport(host, port, timeout)
    else:
        raise click.UsageError("Either --port or --socket must be specified")


def load_rules_file(rules_file: str) -> List[Dict[str, Any]]:
    """Load rules from a YAML or JSON file."""
    path = Path(rules_file)
    if not path.exists():
        raise click.ClickException(f"Rules file not found: {rules_file}")

    content = path.read_text()

    if path.suffix in (".yaml", ".yml"):
        if not HAS_YAML:
            raise click.ClickException(
                "PyYAML is required to load YAML rules files. Install with: pip install pyyaml"
            )
        data = yaml.safe_load(content)
    else:
        data = json.loads(content)

    # Handle both {"rules": [...]} and bare [...] formats
    if isinstance(data, dict) and "rules" in data:
        return data["rules"]
    elif isinstance(data, list):
        return data
    else:
        raise click.ClickException(f"Invalid rules file format: {rules_file}")


def format_matches(matches: List[Dict[str, Any]]) -> Iterator[str]:
    """Format scan matches for human-readable output."""
    for match in matches:
        rule_id = match.get("rule_id", "unknown")
        path = match.get("path", "unknown")
        start = match.get("start", {})
        end = match.get("end", {})
        extra = match.get("extra", {})

        location = f"{path}:{start.get('line', '?')}:{start.get('col', '?')}"
        message = extra.get("message", "")
        severity = extra.get("severity", "INFO")

        yield f"[{severity}] {rule_id}"
        yield f"  {location}"
        if message:
            yield f"  {message}"
        yield ""


def format_errors(errors: List[Dict[str, Any]]) -> Iterator[str]:
    """Format scan errors for human-readable output."""
    for error in errors:
        yield f"Error: {error}"


# --- CLI Commands ---


@click.group()
@click.version_option(version="1.0.0")
def cli() -> None:
    """Semgrep Scan Server CLI Client

    A client for testing and interacting with the Semgrep scan server JSON-RPC 2.0 API.
    """
    pass


# Common options for all commands
def common_options(f):
    """Decorator to add common connection options."""
    f = click.option(
        "--port", "-p", type=int, help="TCP port to connect to (e.g., 9876)"
    )(f)
    f = click.option(
        "--socket", "-s", "socket_path", type=str, help="Unix socket path to connect to"
    )(f)
    f = click.option(
        "--host", "-h", default="127.0.0.1", help="Host to connect to (default: 127.0.0.1)"
    )(f)
    f = click.option(
        "--timeout",
        "-t",
        default=30.0,
        type=float,
        help="Connection timeout in seconds (default: 30.0)",
    )(f)
    f = click.option("--verbose", "-v", is_flag=True, help="Show JSON-RPC messages")(f)
    f = click.option(
        "--json", "json_output", is_flag=True, help="Output results as JSON"
    )(f)
    return f


@cli.command()
@common_options
def status(
    port: Optional[int],
    socket_path: Optional[str],
    host: str,
    timeout: float,
    verbose: bool,
    json_output: bool,
) -> None:
    """Get server status and session information."""
    try:
        transport = create_transport(port, socket_path, host, timeout)
        with transport:
            client = JsonRpcClient(transport=transport, verbose=verbose)
            result = client.call("status")

            if json_output:
                click.echo(json.dumps(result, indent=2))
            else:
                click.echo(f"Status: {result.get('status', 'unknown')}")
                click.echo(f"Total requests: {result.get('total_requests', 0)}")
                click.echo(f"Total scans: {result.get('total_scans', 0)}")

                sessions = result.get("sessions", [])
                if sessions:
                    click.echo(f"\nSessions ({len(sessions)}):")
                    for session in sessions:
                        click.echo(f"  - {session.get('id', 'unknown')}")
                        click.echo(f"    Rules: {session.get('rules_count', 0)}")
                else:
                    click.echo("\nNo active sessions")

    except JsonRpcError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ConnectionError as e:
        click.echo(f"Connection error: {e}", err=True)
        sys.exit(1)
    except socket.error as e:
        click.echo(f"Socket error: {e}", err=True)
        sys.exit(1)


@cli.command()
@common_options
@click.option("--content", "-c", help="Code content to scan (inline)")
@click.option("--file", "-f", "file_path", type=click.Path(exists=True), help="File to scan")
@click.option("--filename", required=True, help="Filename for the code (used for language detection)")
@click.option("--language", "-l", required=True, help="Language of the code (e.g., python, javascript)")
@click.option("--session-id", help="Session ID to use for rules")
@click.option("--rules-file", type=click.Path(exists=True), help="Rules file (YAML/JSON) for inline rules")
def scan(
    port: Optional[int],
    socket_path: Optional[str],
    host: str,
    timeout: float,
    verbose: bool,
    json_output: bool,
    content: Optional[str],
    file_path: Optional[str],
    filename: str,
    language: str,
    session_id: Optional[str],
    rules_file: Optional[str],
) -> None:
    """Scan code content for security issues.

    Provide code either via --content (inline) or --file (from disk).
    Rules can be specified via --session-id (use existing session) or --rules-file (inline rules).
    """
    # Get content from file or inline
    if file_path:
        content = Path(file_path).read_text()
    elif content is None:
        raise click.UsageError("Either --content or --file must be specified")

    # Build params
    params: Dict[str, Any] = {
        "content": content,
        "filename": filename,
        "language": language,
    }

    if session_id:
        params["session_id"] = session_id
    elif rules_file:
        params["rules"] = load_rules_file(rules_file)
    else:
        raise click.UsageError("Either --session-id or --rules-file must be specified")

    try:
        transport = create_transport(port, socket_path, host, timeout)
        with transport:
            client = JsonRpcClient(transport=transport, verbose=verbose)
            result = client.call("scan", params)

            if json_output:
                click.echo(json.dumps(result, indent=2))
            else:
                matches = result.get("matches", [])
                errors = result.get("errors", [])

                if matches:
                    click.echo(f"Found {len(matches)} match(es):\n")
                    for line in format_matches(matches):
                        click.echo(line)
                else:
                    click.echo("No matches found")

                if errors:
                    click.echo("\nErrors:")
                    for line in format_errors(errors):
                        click.echo(line)

    except JsonRpcError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ConnectionError as e:
        click.echo(f"Connection error: {e}", err=True)
        sys.exit(1)
    except socket.error as e:
        click.echo(f"Socket error: {e}", err=True)
        sys.exit(1)


@cli.command(name="create-session")
@common_options
@click.option("--session-id", required=True, help="Unique session identifier")
@click.option("--rules-file", type=click.Path(exists=True), help="Rules file path (YAML/JSON)")
@click.option("--rules-json", help="Inline rules as JSON string")
def create_session(
    port: Optional[int],
    socket_path: Optional[str],
    host: str,
    timeout: float,
    verbose: bool,
    json_output: bool,
    session_id: str,
    rules_file: Optional[str],
    rules_json: Optional[str],
) -> None:
    """Create a named session with preloaded rules.

    Sessions cache parsed rules for efficient repeated scans.
    """
    params: Dict[str, Any] = {"session_id": session_id}

    if rules_file:
        # Pass the file path to the server (it will load it)
        params["rules_file"] = str(Path(rules_file).resolve())
    elif rules_json:
        params["rules"] = json.loads(rules_json)
    else:
        raise click.UsageError("Either --rules-file or --rules-json must be specified")

    try:
        transport = create_transport(port, socket_path, host, timeout)
        with transport:
            client = JsonRpcClient(transport=transport, verbose=verbose)
            result = client.call("create-session", params)

            if json_output:
                click.echo(json.dumps(result, indent=2))
            else:
                click.echo(f"Session created: {result.get('session_id', session_id)}")
                click.echo(f"Rules loaded: {result.get('rules_count', 0)}")

    except JsonRpcError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ConnectionError as e:
        click.echo(f"Connection error: {e}", err=True)
        sys.exit(1)
    except socket.error as e:
        click.echo(f"Socket error: {e}", err=True)
        sys.exit(1)


@cli.command(name="destroy-session")
@common_options
@click.option("--session-id", required=True, help="Session identifier to destroy")
def destroy_session(
    port: Optional[int],
    socket_path: Optional[str],
    host: str,
    timeout: float,
    verbose: bool,
    json_output: bool,
    session_id: str,
) -> None:
    """Remove a session and free its resources."""
    params = {"session_id": session_id}

    try:
        transport = create_transport(port, socket_path, host, timeout)
        with transport:
            client = JsonRpcClient(transport=transport, verbose=verbose)
            result = client.call("destroy-session", params)

            if json_output:
                click.echo(json.dumps(result, indent=2))
            else:
                if result.get("destroyed"):
                    click.echo(f"Session destroyed: {result.get('session_id', session_id)}")
                else:
                    click.echo(f"Failed to destroy session: {session_id}")

    except JsonRpcError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ConnectionError as e:
        click.echo(f"Connection error: {e}", err=True)
        sys.exit(1)
    except socket.error as e:
        click.echo(f"Socket error: {e}", err=True)
        sys.exit(1)


@cli.command()
@common_options
def shutdown(
    port: Optional[int],
    socket_path: Optional[str],
    host: str,
    timeout: float,
    verbose: bool,
    json_output: bool,
) -> None:
    """Shutdown the scan server."""
    try:
        transport = create_transport(port, socket_path, host, timeout)
        with transport:
            client = JsonRpcClient(transport=transport, verbose=verbose)
            result = client.call("shutdown")

            if json_output:
                click.echo(json.dumps(result, indent=2))
            else:
                click.echo(result.get("message", "Server shutting down"))
                click.echo(f"Total requests processed: {result.get('total_requests', 0)}")
                click.echo(f"Total scans performed: {result.get('total_scans', 0)}")

    except JsonRpcError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    except ConnectionError as e:
        # Connection closed by server during shutdown is expected
        if "Server closed connection" in str(e):
            click.echo("Server shutdown initiated")
        else:
            click.echo(f"Connection error: {e}", err=True)
            sys.exit(1)
    except socket.error as e:
        click.echo(f"Socket error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    cli()
