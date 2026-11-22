"""A loopback stand-in for the model endpoint: scripted replies, and a record of every request."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from probe.sandbox import SYNTHETIC_KEY


@dataclass(frozen=True)
class ToolCall:
    name: str
    input: dict[str, Any]
    id: str


@dataclass(frozen=True)
class Reply:
    text: str = ""
    tool_calls: tuple[ToolCall, ...] = ()


def _blocks(reply: Reply) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    if reply.text:
        blocks.append({"type": "text", "text": reply.text})
    for call in reply.tool_calls:
        blocks.append({"type": "tool_use", "id": call.id, "name": call.name, "input": call.input})
    return blocks or [{"type": "text", "text": ""}]


def _message(reply: Reply, n: int, model: str) -> dict[str, Any]:
    return {
        "id": f"msg_probe_{n:04d}",
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": _blocks(reply),
        "stop_reason": "tool_use" if reply.tool_calls else "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }


def _sse(message: dict[str, Any]) -> bytes:
    out: list[tuple[str, dict[str, Any]]] = []
    start = {**message, "content": [], "stop_reason": None}
    out.append(("message_start", {"type": "message_start", "message": start}))
    for index, block in enumerate(message["content"]):
        if block["type"] == "text":
            opening = {"type": "text", "text": ""}
            delta = {"type": "text_delta", "text": block["text"]}
        else:
            opening = {**block, "input": {}}
            delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
        out.append(
            (
                "content_block_start",
                {"type": "content_block_start", "index": index, "content_block": opening},
            )
        )
        out.append(
            ("content_block_delta", {"type": "content_block_delta", "index": index, "delta": delta})
        )
        out.append(("content_block_stop", {"type": "content_block_stop", "index": index}))
    out.append(
        (
            "message_delta",
            {
                "type": "message_delta",
                "delta": {"stop_reason": message["stop_reason"], "stop_sequence": None},
                "usage": {"output_tokens": 1},
            },
        )
    )
    out.append(("message_stop", {"type": "message_stop"}))
    return "".join(f"event: {name}\ndata: {json.dumps(data)}\n\n" for name, data in out).encode()


def _auth(headers: Any) -> str:
    key = headers.get("x-api-key")
    if key is not None:
        return "synthetic" if key == SYNTHETIC_KEY else "other-key"
    if (headers.get("authorization") or "").lower().startswith("bearer "):
        return "bearer"
    return "none"


class Stub:
    def __init__(self, script: list[Reply], capture: Path) -> None:
        self._script = list(script)
        self._capture = capture
        self._lock = threading.Lock()
        self._n = 0
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"

    def __enter__(self) -> Stub:
        self._capture.touch()
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._server.shutdown()
        self._server.server_close()

    def requests(self) -> list[dict[str, Any]]:
        lines = self._capture.read_text(encoding="utf-8").splitlines()
        return [json.loads(line) for line in lines if line]

    def _answer(self, path: str, body: dict[str, Any], auth: str) -> tuple[int, dict[str, Any]]:
        """Record the request and pick the reply, atomically."""
        route = path.split("?", 1)[0].rstrip("/")
        is_messages = route.endswith("/v1/messages")
        scripted = is_messages and bool(body.get("tools"))
        with self._lock:
            n = self._n
            self._n += 1
            record = {"n": n, "path": path, "scripted": scripted, "auth": auth, "body": body}
            with self._capture.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
            if scripted:
                reply = self._script.pop(0) if self._script else Reply(text="done")
        model = str(body.get("model") or "probe-model")
        if scripted:
            return 200, _message(reply, n, model)
        if is_messages:
            return 200, _message(Reply(text="ok"), n, model)
        if route.endswith("count_tokens"):
            return 200, {"input_tokens": 1}
        return 404, {"type": "error", "error": {"type": "not_found_error", "message": "probe"}}

    def _handler(self) -> type[BaseHTTPRequestHandler]:
        stub = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _send(self, status: int, payload: bytes, ctype: str) -> None:
                self.send_response(status)
                self.send_header("content-type", ctype)
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _handle(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    body = json.loads(raw) if raw else {}
                    if not isinstance(body, dict):
                        body = {"_unparsed": True}
                except ValueError:
                    body = {"_unparsed": True}
                status, payload = stub._answer(self.path, body, _auth(self.headers))
                if status == 200 and body.get("stream") is True and "content" in payload:
                    self._send(200, _sse(payload), "text/event-stream")
                else:
                    self._send(status, json.dumps(payload).encode(), "application/json")

            do_POST = _handle  # noqa: N815
            do_GET = _handle  # noqa: N815
            do_HEAD = _handle  # noqa: N815

        return Handler
