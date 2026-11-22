import json
import subprocess
import sys
from pathlib import Path

import pytest

from probe import markers

SERVER = Path(__file__).resolve().parent.parent / "probe" / "fake_mcp.py"


class Client:
    def __init__(self, counter):
        self.proc = subprocess.Popen(
            [sys.executable, "-I", str(SERVER), "--counter", str(counter)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.stdin = self.proc.stdin
        self.stdout = self.proc.stdout
        self.next_id = 0
        self.init: dict = {}

    def request(self, method, params=None):
        self.next_id += 1
        msg = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params or {}}
        self.stdin.write(json.dumps(msg) + "\n")
        self.stdin.flush()
        reply = json.loads(self.stdout.readline())
        assert reply["id"] == self.next_id
        return reply

    def notify(self, method):
        self.stdin.write(json.dumps({"jsonrpc": "2.0", "method": method}) + "\n")
        self.stdin.flush()

    def call(self, tool, arguments=None):
        return self.request("tools/call", {"name": tool, "arguments": arguments or {}})

    def close(self):
        self.stdin.close()
        self.proc.wait(timeout=5)


@pytest.fixture
def counter(tmp_path):
    return tmp_path / "calls.jsonl"


@pytest.fixture
def server(counter):
    client = Client(counter)
    client.init = client.request(
        "initialize",
        {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"},
        },
    )
    client.notify("notifications/initialized")
    yield client
    client.close()


def text_of(reply):
    return "".join(b.get("text", "") for b in reply["result"]["content"])


def test_initialize_and_list_carry_markers(server):
    init = server.init["result"]
    assert markers.INSTRUCTIONS in init["instructions"]
    assert init["serverInfo"]["name"] == "probe"
    tools = {t["name"]: t for t in server.request("tools/list")["result"]["tools"]}
    assert len(tools) == 7
    echo = tools["echo_text"]
    assert markers.TOOL_DESCRIPTION in echo["description"]
    (param,) = echo["inputSchema"]["properties"].values()
    assert markers.PARAM_DESCRIPTION in param["description"]


@pytest.mark.parametrize(
    "tool,marker",
    [
        ("echo_text", markers.TEXT_RESULT),
        ("echo_text", markers.SIBLING),
        ("echo_split", markers.SPLIT_A),
        ("echo_split", markers.SPLIT_B),
        ("fail_tool", markers.TOOL_ERROR),
    ],
)
def test_tool_results(server, tool, marker):
    assert marker in text_of(server.call(tool))


def test_fail_tool_sets_is_error(server):
    assert server.call("fail_tool")["result"]["isError"] is True


def test_split_has_two_blocks(server):
    assert len(server.call("echo_split")["result"]["content"]) == 2


def test_structured_result(server):
    result = server.call("echo_structured")["result"]
    assert result["structuredContent"] == {
        "value": markers.STRUCTURED_RESULT,
        "other": markers.SIBLING,
    }
    assert json.loads(result["content"][0]["text"]) == result["structuredContent"]


def test_big_result_is_whole(server):
    text = text_of(server.call("echo_big"))
    assert len(text) == 200_000
    assert text.startswith(markers.BIG_HEAD)
    assert text.endswith(markers.BIG_TAIL)


def test_proto_error_is_a_jsonrpc_error(server):
    reply = server.call("proto_error")
    assert "result" not in reply
    assert reply["error"]["code"] == -32000
    assert markers.PROTOCOL_ERROR in reply["error"]["message"]


def test_unknown_method_and_tool(server):
    assert server.request("no/such")["error"]["code"] == -32601
    assert "error" in server.call("no_such_tool")


def test_counter_records_each_call(server, counter):
    server.call("follow_on")
    server.call("echo_text")
    lines = [json.loads(line) for line in counter.read_text().splitlines()]
    assert lines == [{"tool": "follow_on"}, {"tool": "echo_text"}]
