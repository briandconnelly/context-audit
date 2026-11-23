"""Write the probe's results as a Markdown document and a JSON file."""

from __future__ import annotations

import json
import platform
import re
import tempfile
from datetime import datetime
from pathlib import Path

from probe.scenario import Result
from probe.scenarios import delivery, interactive, replacement, routing

# What the design does when a behaviour is not shown; from the spec's Probe table.
IF_NOT_SHOWN = {
    routing.ROUTING.claim: "The probe is inconclusive, and the builder stops for the owner.",
    delivery.RESULT_CLAIM: (
        "That result shape is not covered; if no shape is delivered, approach C is reconsidered."
    ),
    delivery.ERROR_CLAIM: "Error content is not covered.",
    delivery.METADATA_CLAIM: (
        "Expected absent: live listing stays the only way to read tool descriptions and server "
        "instructions, and absence is claimed only for the events inspected."
    ),
    delivery.TRANSCRIPT_CLAIM: (
        "The investigate command cannot read results back, so the owner decides at the checkpoint "
        "whether the evidence store is on by default."
    ),
    replacement.CLAIM: "Redaction is not offered.",
    replacement.TRANSCRIPT_CLAIM: (
        "After a replacement the transcript holds the replacement, so the investigate command "
        "cannot show the original, and the design's Redaction section needs correcting."
    ),
    delivery.EXCLUSION_CLAIM: (
        "The probe's flags do not keep outside instruction files out, so it relies on the "
        "working directory alone."
    ),
    delivery.ISOLATION_CLAIM: (
        "The isolation guard cannot be trusted, so no run is known to be free of outside "
        "instructions."
    ),
    interactive.DIRECT_CLAIM: "Delivery is deferred on that path.",
    interactive.ASK_CLAIM: "Follow-on gating is not offered.",
}
NOT_PROBED = (
    "Two gated tools at once, and parallel gated calls.",
    "Auto mode, which is the interactive default, and headless delivery of messages and prompts.",
    "First-run behaviour: the interactive profile is seeded as already set up.",
    "Replacement of structured, split, or oversized results.",
    "A long error string, where the hooks reference documents middle truncation.",
    "Any hook event that did not fire in these runs.",
    "A leaked skill list: the isolation guard detects instruction files only.",
)
IF_SHOWN_METADATA = "A hook event carries metadata, so the design uses it and narrows live listing."


def _clean(text: str) -> str:
    """Shorten private paths: the home directory becomes ~ and temp roots become <tmp>."""
    home = str(Path.home())
    text = text.replace(home, "~")
    for root in {tempfile.gettempdir(), str(Path(tempfile.gettempdir()).resolve())}:
        text = text.replace(root, "<tmp>")
    return re.sub(r"/(?:private/)?var/folders/[^/\s]+/[^/\s]+/T", "<tmp>", text)


def _by_claim(results: list[Result]) -> dict[str, list[Result]]:
    grouped: dict[str, list[Result]] = {}
    for result in results:
        grouped.setdefault(result.claim, []).append(result)
    return grouped


def _consequence(claim: str, group: list[Result]) -> str:
    outcomes = {r.outcome for r in group}
    if claim == delivery.METADATA_CLAIM:
        return IF_SHOWN_METADATA if "shown" in outcomes else IF_NOT_SHOWN[claim]
    if outcomes == {"shown"}:
        return "Shown on this build for every scenario run."
    failing = ", ".join(f"`{r.name}` ({r.outcome})" for r in group if r.outcome != "shown")
    rule = IF_NOT_SHOWN.get(claim, "The design has no stated consequence for this claim.")
    return f"Not shown for {failing}: {rule}"


def write_report(
    results: list[Result], *, claude_version: str, out_md: Path, out_json: Path
) -> None:
    header = {
        "claude_version": claude_version,
        "date": datetime.now().astimezone().strftime("%Y-%m-%d"),
        "platform": f"{platform.system()} {platform.machine()}",
        "python": platform.python_version(),
    }
    rows = [
        {"name": r.name, "claim": r.claim, "outcome": r.outcome, "reason": _clean(r.reason)}
        for r in results
    ]
    out_json.write_text(
        json.dumps({"header": header, "results": rows}, indent=1) + "\n", encoding="utf-8"
    )

    lines = [
        "# Probe results",
        "",
        f"Claude Code {claude_version}, {header['platform']}, {header['date']}.",
        "These are exploratory results from the probe's own recording hook.",
        "Coverage receipts come later, from running the probe against the packaged hooks.",
        "Every run used a local stand-in for the model endpoint and spent no model quota.",
        "",
        "## Outcomes by claim",
        "",
        "| Claim | Scenarios |",
        "| --- | --- |",
    ]
    grouped = _by_claim(results)
    for claim, group in grouped.items():
        cells = "; ".join(f"{r.name}: {r.outcome}" for r in group)
        lines.append(f"| {claim} | {cells} |")
    lines += ["", "## Reasons", ""]
    for row in rows:
        reason = row["reason"].replace("\n", " ")
        lines.append(f"- `{row['name']}` ({row['outcome']}): {reason}")
    unshown = [row for row in rows if row["outcome"] != "shown"]
    if unshown:
        lines += ["", "## Not shown or inconclusive", ""]
        for row in unshown:
            lines += [f"### {row['name']}", "", f"Outcome: `{row['outcome']}`.", ""]
            lines += ["    " + part for part in row["reason"].splitlines()]
            lines.append("")
    lines += ["", "## Consequences for the design", ""]
    for claim, group in grouped.items():
        lines.append(f"- **{claim}.** {_consequence(claim, group)}")
    lines += ["", "## Not probed", ""]
    lines += [f"- {item}" for item in NOT_PROBED]
    text = "\n".join(lines)
    out_md.write_text(re.sub(r"\n{3,}", "\n\n", text).rstrip("\n") + "\n", encoding="utf-8")
