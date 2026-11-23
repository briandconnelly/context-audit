import socket
import sys
import threading

from probe import markers
from probe.sandbox import Sandbox

CONNECT = (
    "import socket,sys\n"
    "s=socket.socket(); s.settimeout(3)\n"
    "s.connect((sys.argv[1], int(sys.argv[2]))); s.close()\n"
)


def test_env_is_an_allowlist(tmp_path, monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "real")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "real")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", "https://example.invalid")
    env = Sandbox(tmp_path).env
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in env
    assert "ANTHROPIC_BASE_URL" not in env
    assert env["ANTHROPIC_API_KEY"] == "sk-ant-probe-synthetic"
    assert env["HOME"].startswith(str(tmp_path))
    assert env["CLAUDE_CONFIG_DIR"].startswith(str(tmp_path))


def test_loopback_allowed_and_external_denied(tmp_path):
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    threading.Thread(target=lambda: listener.accept(), daemon=True).start()
    box = Sandbox(tmp_path)
    ok = box.run([sys.executable, "-c", CONNECT, "127.0.0.1", str(port)], cwd=tmp_path, timeout=10)
    assert ok.exit == 0, ok.stderr
    denied = box.run([sys.executable, "-c", CONNECT, "192.0.2.1", "80"], cwd=tmp_path, timeout=10)
    assert denied.exit not in (0, None)
    assert not denied.timed_out
    assert "timed out" not in denied.stderr.lower()
    listener.close()


def test_timeout_is_reported_not_raised(tmp_path):
    done = Sandbox(tmp_path).run(
        [sys.executable, "-c", "import time; time.sleep(30)"], cwd=tmp_path, timeout=1
    )
    assert done.timed_out
    assert done.exit is None


def test_stdin_is_passed(tmp_path):
    done = Sandbox(tmp_path).run(
        [sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"],
        cwd=tmp_path,
        timeout=10,
        stdin="abc",
    )
    assert done.stdout.strip() == "ABC"


def test_markers_are_unique():
    values = [v for k, v in vars(markers).items() if k.isupper()]
    assert len(values) == len(set(values)) == 16
    assert all(v.startswith("CTXA-") for v in values)
