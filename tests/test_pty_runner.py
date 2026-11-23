import sys

from probe.pty_runner import Step, drive, strip_ansi

ECHO = (
    "import sys\n"
    "print('ready', flush=True)\n"
    "line = sys.stdin.readline().strip()\n"
    "print('got:' + line, flush=True)\n"
    "sys.stdin.readline()\n"
)


def test_waits_then_sends_and_captures_output(tmp_path):
    steps = [Step("ready", "hello\r"), Step("got:hello", "\r")]
    screen, missing, exit_code, _ = drive([sys.executable, "-c", ECHO], steps, cwd=tmp_path, env={})
    assert missing is None
    assert "got:hello" in screen
    assert exit_code == 0


def test_missing_wait_text_is_reported(tmp_path):
    steps = [Step("never appears", "x\r", timeout=1)]
    screen, missing, _, _ = drive([sys.executable, "-c", ECHO], steps, cwd=tmp_path, env={})
    assert missing == "never appears"
    assert "ready" in screen


def test_escape_sequences_are_stripped():
    raw = "\x1b[31mred\x1b[0m \x1b]0;title\x07plain \x1b[2Kline\x1b[?25l"
    assert strip_ansi(raw) == "red plain line"


def test_until_text_ends_the_run(tmp_path):
    loop = "import time\nprint('started', flush=True)\ntime.sleep(60)\n"
    screen, missing, exit_code, _ = drive(
        [sys.executable, "-c", loop], [], cwd=tmp_path, env={}, until="started", timeout=20
    )
    assert missing is None
    assert "started" in screen
    assert exit_code != 0


def test_overall_timeout_stops_a_silent_program(tmp_path):
    loop = "import time\ntime.sleep(60)\n"
    screen, missing, _, _ = drive(
        [sys.executable, "-c", loop], [], cwd=tmp_path, env={}, until="never", timeout=2
    )
    assert missing == "never"


TWICE = (
    "import sys\n"
    "for n in (1, 2):\n"
    "    print('question?', flush=True)\n"
    "    print(f'answer{n}:' + sys.stdin.readline().strip(), flush=True)\n"
)


def test_a_repeated_prompt_is_waited_for_afresh(tmp_path):
    # the second wait must not be satisfied by the first prompt, still on screen
    steps = [Step("question?", "a\r"), Step("question?", "b\r")]
    screen, missing, _, seen = drive([sys.executable, "-c", TWICE], steps, cwd=tmp_path, env={})
    assert missing is None
    assert "answer1:a" in screen
    assert "answer2:b" in screen
    assert seen == [True, True]


def test_an_optional_step_is_skipped_when_its_text_never_comes(tmp_path):
    steps = [
        Step("ready", "hello\r"),
        Step("no such prompt", "x\r", timeout=2, optional=True),
        Step("got:hello", "\r"),
    ]
    screen, missing, _, seen = drive([sys.executable, "-c", ECHO], steps, cwd=tmp_path, env={})
    assert missing is None
    assert seen == [True, False, True]


def test_until_can_be_a_predicate(tmp_path):
    flag = tmp_path / "flag"
    prog = (
        "import pathlib, sys, time\n"
        "print('working', flush=True)\n"
        f"time.sleep(1); pathlib.Path({str(flag)!r}).write_text('x')\n"
        "time.sleep(60)\n"
    )
    screen, missing, _, _ = drive(
        [sys.executable, "-c", prog],
        [],
        cwd=tmp_path,
        env={},
        until=lambda screen: flag.exists(),
        timeout=20,
    )
    assert missing is None
    assert flag.exists()


def test_a_predicate_that_never_holds_is_reported(tmp_path):
    prog = "import time\ntime.sleep(60)\n"
    _, missing, _, _ = drive(
        [sys.executable, "-c", prog],
        [],
        cwd=tmp_path,
        env={},
        until=lambda screen: False,
        timeout=2,
    )
    assert missing == "the end condition"


def test_the_program_is_stopped_when_the_end_condition_raises(tmp_path):
    import os

    import pytest

    pidfile = tmp_path / "pid"
    prog = (
        "import os, pathlib, time\n"
        f"pathlib.Path({str(pidfile)!r}).write_text(str(os.getpid()))\n"
        "print('up', flush=True)\n"
        "time.sleep(60)\n"
    )

    def boom(screen):
        if pidfile.exists():
            raise ValueError("bad evidence")
        return False

    with pytest.raises(ValueError):
        drive([sys.executable, "-c", prog], [], cwd=tmp_path, env={}, until=boom, timeout=20)
    pid = int(pidfile.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)
