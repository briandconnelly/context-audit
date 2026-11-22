import json
import urllib.error
import urllib.request

from probe.stub import Reply, Stub, ToolCall

TOOLS = {"tools": [{"name": "x"}], "messages": []}


def post(url, body, headers=None):
    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def post_json(url, body, headers=None):
    return json.loads(post(url, body, headers)[1])


def test_scripted_tool_call_then_text(tmp_path):
    script = [
        Reply(tool_calls=(ToolCall("mcp__probe__echo_text", {"a": 1}, "toolu_01"),)),
        Reply(text="ok"),
    ]
    with Stub(script, tmp_path / "cap.jsonl") as stub:
        first = post_json(stub.url + "/v1/messages", TOOLS)
        second = post_json(stub.url + "/v1/messages", TOOLS)
    assert first["stop_reason"] == "tool_use"
    assert first["content"][0]["id"] == "toolu_01"
    assert first["content"][0]["input"] == {"a": 1}
    assert second["content"][0]["text"] == "ok"
    assert second["stop_reason"] == "end_turn"
    assert [r["scripted"] for r in stub.requests()] == [True, True]
    assert [r["n"] for r in stub.requests()] == [0, 1]


def test_unscripted_requests_do_not_consume_the_script(tmp_path):
    with Stub([Reply(text="first")], tmp_path / "cap.jsonl") as stub:
        plain = post_json(stub.url + "/v1/messages", {"messages": []})
        count = post_json(stub.url + "/v1/messages/count_tokens", TOOLS)
        scripted = post_json(stub.url + "/v1/messages", TOOLS)
    assert plain["content"][0]["type"] == "text"
    assert count == {"input_tokens": 1}
    assert scripted["content"][0]["text"] == "first"
    assert [r["scripted"] for r in stub.requests()] == [False, False, True]


def test_streaming_event_order(tmp_path):
    script = [Reply(tool_calls=(ToolCall("t", {"k": "v"}, "toolu_02"),))]
    with Stub(script, tmp_path / "cap.jsonl") as stub:
        _, raw = post(stub.url + "/v1/messages", {**TOOLS, "stream": True})
    events = [line[7:] for line in raw.splitlines() if line.startswith("event: ")]
    assert events == [
        "message_start",
        "content_block_start",
        "content_block_delta",
        "content_block_stop",
        "message_delta",
        "message_stop",
    ]
    datas = [json.loads(line[6:]) for line in raw.splitlines() if line.startswith("data: ")]
    delta = datas[2]["delta"]
    assert delta["type"] == "input_json_delta"
    assert json.loads(delta["partial_json"]) == {"k": "v"}
    assert datas[4]["delta"]["stop_reason"] == "tool_use"


def test_exhausted_script_and_unknown_path_do_not_crash(tmp_path):
    with Stub([], tmp_path / "cap.jsonl") as stub:
        done = post_json(stub.url + "/v1/messages", TOOLS)
        status, _ = post(stub.url + "/v1/something/else", {})
        again = post_json(stub.url + "/v1/messages", TOOLS)
    assert done["content"][0]["text"] == "done"
    assert status == 404
    assert again["content"][0]["text"] == "done"


def test_auth_is_classified_and_never_stored(tmp_path):
    cap = tmp_path / "cap.jsonl"
    with Stub([], cap) as stub:
        post(stub.url + "/v1/messages", TOOLS, {"x-api-key": "sk-ant-probe-synthetic"})
        post(stub.url + "/v1/messages", TOOLS, {"x-api-key": "real-123"})
        post(stub.url + "/v1/messages", TOOLS, {"authorization": "Bearer real-456"})
        post(stub.url + "/v1/messages", TOOLS)
    assert [r["auth"] for r in stub.requests()] == ["synthetic", "other-key", "bearer", "none"]
    text = cap.read_text()
    assert "real-123" not in text
    assert "real-456" not in text


def test_malformed_body_is_recorded_not_fatal(tmp_path):
    with Stub([], tmp_path / "cap.jsonl") as stub:
        req = urllib.request.Request(stub.url + "/v1/messages", data=b"{not json")
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
        ok = post_json(stub.url + "/v1/messages", TOOLS)
    assert ok["content"][0]["text"] == "done"
    assert stub.requests()[0]["body"] == {"_unparsed": True}
