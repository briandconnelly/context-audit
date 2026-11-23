import json
import subprocess
import sys
from pathlib import Path

import pytest

from probe import markers
from probe.fake_mcp import DIRECTIVE

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
    assert len(tools) == 10
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
    assert markers.STRUCTURED_TEXT in result["content"][0]["text"]
    assert markers.STRUCTURED_RESULT not in result["content"][0]["text"]
    assert markers.STRUCTURED_TEXT not in json.dumps(result["structuredContent"])


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


SHAPES = ("text", "structured", "split", "big")


def test_directive_tools_are_listed(server):
    tools = {t["name"]: t for t in server.request("tools/list")["result"]["tools"]}
    assert {"echo_directive", "fail_directive", "submit_feedback"} <= set(tools)
    assert tools["echo_directive"]["inputSchema"]["properties"]["shape"]["enum"] == list(SHAPES)


@pytest.mark.parametrize("shape", SHAPES)
def test_echo_directive_carries_the_canary_in_each_shape(server, shape):
    result = server.call("echo_directive", {"shape": shape})["result"]
    if shape == "structured":
        assert DIRECTIVE in json.dumps(result["structuredContent"])
        assert DIRECTIVE not in result["content"][0]["text"]
    elif shape == "split":
        assert len(result["content"]) == 2
        assert DIRECTIVE in result["content"][1]["text"]
        assert DIRECTIVE not in result["content"][0]["text"]
    elif shape == "big":
        text = text_of({"result": result})
        assert len(text) == 140_000 and text.endswith(DIRECTIVE)
    else:
        assert DIRECTIVE in text_of({"result": result})


def test_fail_directive_is_a_tool_error_carrying_the_canary(server):
    result = server.call("fail_directive")["result"]
    assert result["isError"] is True
    assert DIRECTIVE in text_of({"result": result})


def test_submit_feedback_is_benign(server):
    assert "recorded" in text_of(server.call("submit_feedback"))


def _hook_output(tmp_path, event):
    hook = Path(__file__).resolve().parent.parent / "context_audit" / "hook.py"
    p = subprocess.run(
        [sys.executable, "-I", str(hook)],
        input=json.dumps(event),
        capture_output=True,
        text=True,
        env={"CONTEXT_AUDIT_HOME": str(tmp_path / "state"), "HOME": str(tmp_path)},
        timeout=30,
    )
    return json.loads(p.stdout) if p.stdout else None


@pytest.mark.parametrize("shape", SHAPES)
def test_the_packaged_hook_flags_each_directive_shape(server, tmp_path, shape):
    result = server.call("echo_directive", {"shape": shape})["result"]
    # As the harness delivers it: structuredContent as compact JSON, else the blocks.
    response = (
        json.dumps(result["structuredContent"]) if shape == "structured" else (result["content"])
    )
    event = {
        "hook_event_name": "PostToolUse",
        "tool_name": "mcp__probe__echo_directive",
        "tool_use_id": "toolu_x",
        "mcp_server": {"name": "probe"},
        "tool_response": response,
    }
    out = _hook_output(tmp_path, event)
    assert out is not None and "flagged" in out["systemMessage"]


def test_the_packaged_hook_flags_the_directive_error(server, tmp_path):
    text = text_of({"result": server.call("fail_directive")["result"]})
    event = {
        "hook_event_name": "PostToolUseFailure",
        "tool_name": "mcp__probe__fail_directive",
        "tool_use_id": "toolu_x",
        "mcp_server": {"name": "probe"},
        "error": text,
    }
    out = _hook_output(tmp_path, event)
    assert out is not None and "flagged" in out["systemMessage"]
