"""A stdio MCP server whose instructions, descriptions, results, and errors carry markers.

Run by absolute path under ``python3 -I``, so it puts its own repository root on the path.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from probe import markers  # noqa: E402

PROTOCOL = "2025-11-25"
BIG_SIZE = 200_000


def _text(*parts: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": part} for part in parts]}


def _structured() -> dict[str, Any]:
    data = {"value": markers.STRUCTURED_RESULT, "other": markers.SIBLING}
    return {"content": [{"type": "text", "text": json.dumps(data)}], "structuredContent": data}


def _big() -> dict[str, Any]:
    fill = BIG_SIZE - len(markers.BIG_HEAD) - len(markers.BIG_TAIL)
    return _text(markers.BIG_HEAD + "." * fill + markers.BIG_TAIL)


RESULTS = {
    "echo_text": lambda: _text(
        f"Primary value {markers.TEXT_RESULT}. Secondary value {markers.SIBLING}."
    ),
    "echo_structured": _structured,
    "echo_split": lambda: _text(
        f"First part {markers.SPLIT_A}.", f"Second part {markers.SPLIT_B}."
    ),
    "echo_big": _big,
    "fail_tool": lambda: {**_text(f"The tool failed: {markers.TOOL_ERROR}."), "isError": True},
    "follow_on": lambda: _text("followed"),
}
EMPTY_SCHEMA = {"type": "object", "properties": {}}


def _tools() -> list[dict[str, Any]]:
    tools = [
        {
            "name": "echo_text",
            "description": f"Return a text value. {markers.TOOL_DESCRIPTION}",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "note": {
                        "type": "string",
                        "description": f"Optional note. {markers.PARAM_DESCRIPTION}",
                    }
                },
            },
        }
    ]
    for name in (
        "echo_structured",
        "echo_split",
        "echo_big",
        "fail_tool",
        "proto_error",
        "follow_on",
    ):
        tools.append(
            {"name": name, "description": f"Probe tool {name}.", "inputSchema": EMPTY_SCHEMA}
        )
    return tools


def handle(method: str, params: dict[str, Any], counter: Path) -> dict[str, Any]:
    """Return a JSON-RPC ``result`` or ``error`` member for one request."""
    if method == "initialize":
        return {
            "result": {
                "protocolVersion": PROTOCOL,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "probe", "version": "0"},
                "instructions": f"Probe server. {markers.INSTRUCTIONS}",
            }
        }
    if method == "ping":
        return {"result": {}}
    if method == "tools/list":
        return {"result": {"tools": _tools()}}
    if method == "tools/call":
        name = str(params.get("name"))
        with counter.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"tool": name}) + "\n")
        if name == "proto_error":
            return {"error": {"code": -32000, "message": f"Failure: {markers.PROTOCOL_ERROR}"}}
        if name in RESULTS:
            return {"result": RESULTS[name]()}
        return {"error": {"code": -32602, "message": "unknown tool"}}
    return {"error": {"code": -32601, "message": "method not found"}}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--counter", type=Path, required=True)
    counter = parser.parse_args().counter
    for line in sys.stdin:
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if not isinstance(msg, dict) or "id" not in msg:
            continue  # a notification, or noise
        params = msg.get("params")
        reply = handle(str(msg.get("method")), params if isinstance(params, dict) else {}, counter)
        sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": msg["id"], **reply}) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
