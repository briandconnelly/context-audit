"""The `context-audit` command: inventory, scan, selftest, status, and show.

Runs as the `context-audit` console script or as ``python3 -I <repo>/context_audit/cli.py``.
`scan --json` prints only the closed report from `context_audit.report`; every other
output is for the owner's terminal and passes third-party text through `escape`.
"""

from __future__ import annotations

import sys
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import argparse  # noqa: E402
import contextlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import stat  # noqa: E402

from context_audit import __version__, state  # noqa: E402
from context_audit.ingest import from_hook_event, source_id_for  # noqa: E402
from context_audit.inventory import (  # noqa: E402
    Roots,
    Source,
    default_roots,
    enumerate_sources,
    read_source,
)
from context_audit.receipts import capability, installed_claude_version  # noqa: E402
from context_audit.report import (  # noqa: E402
    CAPABILITY_SCOPE,
    FINDING_ID,
    READ_KINDS,
    TOOL_SURFACES,
    TOTAL_UNKNOWN,
    VERSION_UNKNOWN,
    escape,
    model_report,
)
from context_audit.rules import Finding  # noqa: E402
from context_audit.scan import STATIC_BUDGET, ScanResult, scan_fields  # noqa: E402
from context_audit.selftest import SelfTest, run_selftest  # noqa: E402
from context_audit.text import Field  # noqa: E402

EXIT_OK, EXIT_HIGH, EXIT_USAGE, EXIT_SELFTEST, EXIT_UNAVAILABLE, EXIT_STATE = 0, 1, 2, 3, 4, 5
CONTEXT = 80
TRANSCRIPT_MAX_BYTES = 512 * 1024 * 1024


NOT_A_TERMINAL = (
    "evidence unavailable: show prints evidence only to a terminal; run it in a terminal"
)


def _is_terminal() -> bool:
    return sys.stdout.isatty()


class _Unavailable(Exception):
    """Evidence for a finding cannot be shown; the message says why."""


def _roots(args: argparse.Namespace) -> Roots:
    project = args.project if args.project is not None else Path.cwd()
    base = default_roots(project)
    return Roots(args.claude_dir or base.claude_dir, args.claude_json or base.claude_json, project)


def _open_state() -> Path:
    """The state directory, created and checked usable; raises StateError."""
    path = state.state_dir()
    try:
        root = state.ensure_state(path)
        state.span_digest(root, "")
        state.read_counters(root)
        state.read_events(root)
    except OSError as e:
        raise state.StateError(f"cannot use state directory {path}: {e.strerror or e}") from e
    return root


def _capability(root: Path) -> dict:
    """model_report arguments from the receipts that match the installed Claude Code and
    this plugin."""
    version = installed_claude_version()
    return {
        "capability": capability(root, version, __version__),
        "claude_version_known": version is not None,
    }


def _scan_source(source: Source, root: Path) -> tuple[list[Field], ScanResult | None]:
    """The source's fields and its scan, or None for the scan when it cannot be read."""
    fields, readable = read_source(source)
    if not readable:
        return [], None
    return fields, scan_fields(fields, state_root=root, budget=STATIC_BUDGET)


def _print_selftest(results: list[SelfTest]) -> None:
    print("Self-test (per entry point):")
    for t in results:
        verdict = "passed" if t.passed else "FAILED: its negative claims do not hold"
        print(f"  {t.entry}: {verdict} (missed {len(t.missed)}, flagged {len(t.flagged)})")


def _print_coverage(rep: dict) -> None:
    print("Capability (per behaviour):")
    for c in rep["capability"]:
        where = ""
        if c["status"] != "unverified":
            mode = c["permission_mode"] + (" mode" if c["permission_mode"] == "default" else "")
            where = f" ({c['frontend']}, {mode})"
        print(f"  {c['behaviour']}: {c['status']}{where}")
    for m in (CAPABILITY_SCOPE, VERSION_UNKNOWN):
        if m in rep["messages"]:
            print(f"  {m}")
    print("Observation (counts, not a verdict):")
    for k, v in rep["observation"].items():
        print(f"  {k}: {v}")
    print(f"  {TOTAL_UNKNOWN}")


# --- inventory ---------------------------------------------------------------------------


def cmd_inventory(args: argparse.Namespace) -> int:
    for s in enumerate_sources(_roots(args)):
        print(f"{s.kind}\t{escape(s.name) or '-'}\t{s.label}\t{s.skipped or '-'}")
    return EXIT_OK


# --- scan --------------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    root = _open_state()
    results = run_selftest(root)
    sources = enumerate_sources(_roots(args))
    found: list[tuple[Finding, Source]] = []
    outcomes: dict[str, str] = {}
    results_by_source: dict[str, ScanResult] = {}
    for s in sources:
        if s.kind in READ_KINDS and not s.skipped:
            result = _scan_source(s, root)[1]
            if result is None:
                outcomes[s.source_id] = "unreadable"
                continue
            outcomes[s.source_id] = result.outcome
            results_by_source[s.source_id] = result
            found.extend((f, s) for f in result.findings)
    on_record = {e.get("finding_id") for e in state.read_events(root) if e.get("event") == "scan"}
    for f, s in found:
        if f.finding_id in on_record:
            continue
        on_record.add(f.finding_id)
        state.append_event(root, _scan_record(f, s, results_by_source[s.source_id]))
    events = state.read_events(root)
    log = [e for e in events if e.get("event") in TOOL_SURFACES]
    rep = model_report(
        selftest=results,
        counters=state.read_counters(root),
        sources=sources,
        findings=found,
        log_records=log,
        trimmed=(root / "trimmed").exists(),
        outcomes=outcomes,
        **_capability(root),
    )
    if args.json:
        print(json.dumps(rep, ensure_ascii=True, indent=2))
    else:
        _print_selftest(results)
        _print_coverage(rep)
        _print_owner_findings(rep, found, log)
        for m in rep["messages"]:
            if m not in (TOTAL_UNKNOWN, CAPABILITY_SCOPE, VERSION_UNKNOWN):  # printed above
                print(m)
    if rep["voided"]:
        return EXIT_SELFTEST
    return EXIT_HIGH if any(f.severity == "high" for f, _ in found) else EXIT_OK


def _scan_record(f: Finding, s: Source, result: ScanResult) -> dict:
    from datetime import UTC, datetime

    return {
        "ts": datetime.now(UTC).isoformat(),
        "session": None,
        "event": "scan",
        "tool_use_id": None,
        "transcript": str(s.path),
        "source_id": f.source_id,
        "finding_id": f.finding_id,
        "features": list(f.features),
        "severity": f.severity,
        "rule_version": f.rule_version,
        "digest": f.digest,
        "locator": f.locator,
        "outcome": result.outcome,
        "reason": result.reason or None,
    }


def _print_owner_findings(rep: dict, found: list[tuple[Finding, Source]], log: list) -> None:
    where: dict[str, str] = {}
    for f, s in found:
        where[f.finding_id] = f"{s.kind} {escape(s.name)} at {escape(str(s.path))}"
    for e in log:
        fid = e.get("finding_id")
        if isinstance(fid, str):
            where.setdefault(fid, f"tool result {escape(str(e.get('tool_use_id')))}")
    print(f"Findings: {len(rep['findings'])}")
    for item in rep["findings"]:
        feats = "+".join(item["features"])
        print(f"  {item['severity']}\t{item['finding_id']}\t{feats}\t{where[item['finding_id']]}")


# --- selftest and status -----------------------------------------------------------------


def cmd_selftest(args: argparse.Namespace) -> int:
    results = run_selftest(_open_state())
    _print_selftest(results)
    return EXIT_OK if all(t.passed for t in results) else EXIT_SELFTEST


def cmd_status(args: argparse.Namespace) -> int:
    root = _open_state()
    results = run_selftest(root)
    sources = enumerate_sources(_roots(args))
    events = state.read_events(root)
    trimmed = root / "trimmed"
    rep = model_report(
        selftest=results,
        counters=state.read_counters(root),
        sources=sources,
        findings=[],
        log_records=[],
        trimmed=trimmed.exists(),
        **_capability(root),
    )
    print(f"State directory: {escape(str(root))}")
    _print_selftest(results)
    _print_coverage(rep)
    gaps: dict[str, int] = {}
    for e in events:
        if e.get("finding_id") is None and isinstance(e.get("reason"), str):
            gaps[e["reason"]] = gaps.get(e["reason"], 0) + 1
    print("Gap records by reason:" if gaps else "Gap records: none")
    for reason, n in sorted(gaps.items()):
        print(f"  {escape(reason)}: {n}")
    if trimmed.exists():
        try:
            when = trimmed.read_text(errors="replace").strip()
        except OSError:
            when = "unknown time"
        print(f"The event log was trimmed at its size cap (last at {escape(when)}).")
    return EXIT_OK


# --- show --------------------------------------------------------------------------------


def _print_spans(f: Finding, fields: list[Field]) -> None:
    by_locator = {fl.locator: fl.text for fl in fields}
    print(f"{f.finding_id} {f.severity} {'+'.join(f.features)}")
    for locator, start, end in f.ranges:
        text = by_locator.get(locator, "")
        before = escape(text[max(0, start - CONTEXT) : start])
        after = escape(text[end : end + CONTEXT])
        print(f"  {escape(locator)}: {before}>>>{escape(text[start:end])}<<<{after}")


def _show_static(record: dict, fid: str, args: argparse.Namespace, root: Path) -> None:
    path, sid = record.get("transcript"), record.get("source_id")
    source = next(
        (s for s in enumerate_sources(_roots(args)) if s.source_id == sid and str(s.path) == path),
        None,
    )
    if source is None:
        raise _Unavailable("the source is no longer in the inventory")
    fields, result = _scan_source(source, root)
    if result is None:
        raise _Unavailable(f"the file cannot be read now: {escape(str(path))}")
    match = next((f for f in result.findings if f.finding_id == fid), None)
    if match is None:
        raise _Unavailable(f"the file has changed since the scan: {escape(str(path))}")
    print(f"{source.kind} {escape(source.name)} at {escape(str(path))}")
    _print_spans(match, fields)


def _transcript_entries(path: str, tool_use_id: str) -> list[dict]:
    """The transcript's JSON lines that mention tool_use_id."""
    try:
        info = os.stat(path)
    except OSError:
        raise _Unavailable("the transcript is missing") from None
    if not stat.S_ISREG(info.st_mode) or info.st_size > TRANSCRIPT_MAX_BYTES:
        raise _Unavailable("the transcript is not a readable file")
    needle = tool_use_id.encode()
    entries = []
    try:
        with open(path, "rb") as fh:
            for line in fh:
                if needle not in line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    entries.append(obj)
    except OSError:
        raise _Unavailable("the transcript cannot be read") from None
    return entries


def _blocks(entry: dict) -> list:
    msg = entry.get("message")
    content = msg.get("content") if isinstance(msg, dict) else None
    return [b for b in content if isinstance(b, dict)] if isinstance(content, list) else []


def _tool_call(entries: list[dict], tool_use_id: str) -> tuple[str | None, list]:
    """The tool name from the call, and candidate result payloads (string or block list)."""
    name, payloads = None, []
    for entry in entries:
        for b in _blocks(entry):
            if b.get("type") == "tool_use" and b.get("id") == tool_use_id:
                name = b.get("name") if isinstance(b.get("name"), str) else name
            if b.get("type") == "tool_result" and b.get("tool_use_id") == tool_use_id:
                payloads.append(entry.get("toolUseResult"))
                payloads.append(b.get("content"))
    return name, [p for p in payloads if isinstance(p, (str, list))]


def _servers(tool: str, source_id: str) -> str | None:
    """The server name whose identity with `tool` gives `source_id`; raises if none does."""
    candidates: list[str | None] = [None]
    if tool.startswith("mcp__"):
        parts = tool[5:].split("__")
        candidates += ["__".join(parts[:k]) for k in range(1, len(parts))]
    for server in candidates:
        if source_id_for(tool, server) == source_id:
            return server
    raise _Unavailable("the tool in the transcript does not match the recorded source")


def _show_tool(record: dict, fid: str, root: Path) -> None:
    path, tuid = record.get("transcript"), record.get("tool_use_id")
    if not isinstance(path, str) or not path or not isinstance(tuid, str) or not tuid:
        raise _Unavailable("the record names no transcript or tool-use ID")
    name, payloads = _tool_call(_transcript_entries(path, tuid), tuid)
    if not payloads:
        raise _Unavailable("the transcript holds no result for this tool-use ID")
    if name is None:
        raise _Unavailable("the transcript holds no call for this tool-use ID")
    server = _servers(name, str(record.get("source_id")))
    kind = record["event"]
    for payload in payloads:
        event: dict = {"hook_event_name": kind, "tool_name": name, "tool_use_id": tuid}
        if server is not None:
            event["mcp_server"] = {"name": server}
        if kind == "PostToolUse":
            event["tool_response"] = payload
        elif isinstance(payload, str):
            event["error"] = payload
        elif len(payload) == 1 and isinstance(payload[0], dict):
            event["error"] = payload[0].get("text")
        ing = from_hook_event(event)
        result = scan_fields(ing.fields, state_root=root, own_tool=ing.tool)
        match = next((f for f in result.findings if f.finding_id == fid), None)
        if match is not None:
            print(f"tool result {escape(tuid)} in {escape(path)}")
            _print_spans(match, ing.fields)
            return
    raise _Unavailable("the transcript's result does not produce this finding")


def cmd_show(args: argparse.Namespace) -> int:
    fid = args.finding_id
    if not FINDING_ID.match(fid):
        print(f"not a finding ID: {escape(fid)}", file=sys.stderr)
        return EXIT_USAGE
    if not _is_terminal():  # third-party text is shown to the owner, never to a pipe
        print(NOT_A_TERMINAL)
        return EXIT_UNAVAILABLE
    root = _open_state()
    records = [e for e in state.read_events(root) if e.get("finding_id") == fid]
    try:
        if not records:
            raise _Unavailable("no finding with this ID is on record")
        record = records[-1]
        if record.get("event") == "scan":
            _show_static(record, fid, args, root)
        elif record.get("event") in TOOL_SURFACES:
            _show_tool(record, fid, root)
        else:
            raise _Unavailable("the record is of an unknown kind")
    except _Unavailable as e:
        print(f"evidence unavailable: {e}")
        return EXIT_UNAVAILABLE
    return EXIT_OK


# --- entry point -------------------------------------------------------------------------


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="context-audit")
    sub = p.add_subparsers(dest="command", required=True)

    def with_roots(name: str, help: str) -> argparse.ArgumentParser:
        sp = sub.add_parser(name, help=help)
        sp.add_argument("--claude-dir", type=Path, default=None)
        sp.add_argument("--claude-json", type=Path, default=None)
        sp.add_argument("--project", type=Path, default=None)
        return sp

    with_roots("inventory", "list third-party sources on disk").set_defaults(func=cmd_inventory)
    scan = with_roots("scan", "self-test, then scan the inventory")
    scan.add_argument("--json", action="store_true", help="print only the closed report")
    scan.set_defaults(func=cmd_scan)
    sub.add_parser("selftest", help="run the canaries and controls").set_defaults(func=cmd_selftest)
    with_roots("status", "coverage statements and state").set_defaults(func=cmd_status)
    show = with_roots("show", "print the evidence for a finding")
    show.add_argument("finding_id")
    show.set_defaults(func=cmd_show)
    return p


def main(argv: list[str] | None = None) -> int:
    # A backstop: any character the terminal cannot encode is escaped, never a crash.
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(ValueError, OSError):
                reconfigure(errors="backslashreplace")
    args = _parser().parse_args(argv)
    try:
        return args.func(args)
    except state.StateError as e:
        print(f"context-audit: {escape(str(e))}", file=sys.stderr)
        return EXIT_STATE


if __name__ == "__main__":
    sys.exit(main())
