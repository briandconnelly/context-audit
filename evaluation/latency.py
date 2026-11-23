"""Hook latency as Claude Code sees it: a cold subprocess through `bin/context-audit-hook`.

Dev-only, standard library only. Run `python -m evaluation.latency`. Every run sets HOME
and CONTEXT_AUDIT_HOME to fresh temporary directories, so nothing touches the real home.
"""

from __future__ import annotations

import json
import os
import platform
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from pathlib import Path

from evaluation import benign
from evaluation.schema import CORPUS_FILES

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "bin" / "context-audit-hook"
TIMEOUT_S = 60.0  # Claude Code's default command-hook timeout
PAYLOAD_MIX = (
    "60% under 2 KB, 30% about 20 KB, 10% about 100 KB, built from benign generator "
    "results (seed 20261122); every 20th payload is an open-corpus hook canary instead; "
    "each a PostToolUse event for an mcp__ tool"
)
# The hook fails open, so exit status alone cannot show it worked: a canary payload must
# produce the hook's warning, a JSON object with `systemMessage`, or it is a failure.


@dataclass(frozen=True)
class LatencyRun:
    concurrency: int
    p50_ms: float
    p95_ms: float
    max_ms: float
    timeouts: int
    failures: int  # non-zero exits, and canary payloads that produced no warning
    canaries: int
    canaries_warned: int
    benign_warned: int  # benign payloads the scanner rated high: reported, not failures


@dataclass(frozen=True)
class LatencyReport:
    machine: str
    os: str
    python: str
    hook_python: str
    samples: int
    payload_mix: str
    payload_bytes: dict[str, int]
    timeout_s: float
    runs: tuple[LatencyRun, ...]


def _fill(texts: list[str], rng: random.Random, target: int) -> str:
    parts: list[str] = []
    size = 0
    while size < target:
        t = rng.choice(texts)
        parts.append(t)
        size += len(t.encode()) + 2
    return "\n\n".join(parts)


def payloads(samples: int, seed: int = benign.DEFAULT_SEED) -> list[tuple[bool, str]]:
    """The declared mix, as (is_canary, hook event serialized to JSON)."""
    rng = random.Random(seed)
    texts = [i["text"] for i in benign.generate(seed, 1000)]
    small = [t for t in texts if len(t.encode()) < 2048]
    canaries = [
        json.loads(line)["text"]
        for line in CORPUS_FILES["canary"].read_text(encoding="utf-8").splitlines()
        if json.loads(line)["surface"] == "tool_result" and json.loads(line)["expected"] == "high"
    ]
    out = []
    for n in range(samples):
        k = n % 10
        if n % 20 == 19:
            text = rng.choice(canaries)
        elif k < 6:
            text = rng.choice(small)
        elif k < 9:
            text = _fill(texts, rng, 20_000)
        else:
            text = _fill(texts, rng, 100_000)
        event = {
            "session_id": "latency",
            "transcript_path": "/nonexistent/latency.jsonl",
            "cwd": "/",
            "hook_event_name": "PostToolUse",
            "tool_name": "mcp__examplecloud__search",
            "tool_input": {},
            "tool_use_id": f"toolu_{n}",
            "mcp_server": {"name": "examplecloud", "source": "user"},
            "tool_response": [{"type": "text", "text": text}],
        }
        out.append((n % 20 == 19, json.dumps(event)))
    return out


def _hook_python() -> str:
    for py in ("python3.15", "python3.14", "python3.13", "python3"):
        if path := shutil.which(py):
            v = subprocess.run([path, "--version"], capture_output=True, text=True, check=False)
            return f"{path} ({v.stdout.strip() or v.stderr.strip()})"
    return "none found"


def _warned(stdout: bytes) -> bool:
    try:
        out = json.loads(stdout)
    except ValueError:
        return False
    return isinstance(out, dict) and isinstance(out.get("systemMessage"), str)


def _one(hook: Path, payload: str, env: dict[str, str], cwd: str) -> tuple[float, str]:
    start = time.perf_counter()
    try:
        p = subprocess.run(
            ["sh", str(hook)],
            input=payload.encode(),
            capture_output=True,
            env=env,
            cwd=cwd,
            timeout=TIMEOUT_S,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return (time.perf_counter() - start) * 1000, "timeout"
    ms = (time.perf_counter() - start) * 1000
    if p.returncode != 0:
        return ms, "failure"
    return ms, "warned" if _warned(p.stdout) else "silent" if not p.stdout else "other"


def _percentile(xs: list[float], q: float) -> float:
    return statistics.quantiles(xs, n=100, method="inclusive")[int(q) - 1] if len(xs) > 1 else xs[0]


def _run(items: list[tuple[bool, str]], concurrency: int, hook: Path) -> LatencyRun:
    with tempfile.TemporaryDirectory(prefix="ca-latency-") as tmp:
        home = Path(tmp) / "home"
        state = Path(tmp) / "state"
        home.mkdir()
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(home),
            "CONTEXT_AUDIT_HOME": str(state),
        }
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            results = list(pool.map(lambda it: _one(hook, it[1], env, tmp), items))
    ms = [t for t, _ in results]
    kinds = [(c, st) for (c, _), (_, st) in zip(items, results, strict=True)]
    bad = sum(
        1
        for c, st in kinds
        if st == "failure" or (c and st != "warned") or (not c and st == "other")
    )
    return LatencyRun(
        concurrency=concurrency,
        p50_ms=round(statistics.median(ms), 1),
        p95_ms=round(_percentile(ms, 95), 1),
        max_ms=round(max(ms), 1),
        timeouts=sum(1 for _, s in results if s == "timeout"),
        failures=bad,
        canaries=sum(1 for c, _ in kinds if c),
        canaries_warned=sum(1 for c, st in kinds if c and st == "warned"),
        benign_warned=sum(1 for c, st in kinds if not c and st == "warned"),
    )


def measure_latency(
    samples: int = 200, concurrency: tuple[int, ...] = (1, 8), hook: Path = HOOK
) -> LatencyReport:
    items = payloads(samples)
    sizes = [len(p.encode()) for _, p in items]
    return LatencyReport(
        machine=f"{platform.machine()} {platform.processor() or ''} {os.cpu_count()} CPUs".strip(),
        os=platform.platform(),
        python=sys.version.split()[0],
        hook_python=_hook_python(),
        samples=samples,
        payload_mix=PAYLOAD_MIX,
        payload_bytes={
            "min": min(sizes),
            "median": int(statistics.median(sizes)),
            "max": max(sizes),
        },
        timeout_s=TIMEOUT_S,
        runs=tuple(_run(items, c, hook) for c in concurrency),
    )


if __name__ == "__main__":
    print(json.dumps(asdict(measure_latency()), indent=2))
