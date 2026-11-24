"""Optional second opinion from a decision model that speaks the System One API.

Off unless the owner sets CONTEXT_AUDIT_DECIDER_URL. Any server that accepts
`POST {url}/v1/systemone` with the System One request shape works: TypeSafe's hosted Jev
(https://api.typesafe.ai), a local karpo-decision server (http://127.0.0.1:18440), or
another compatible model.

Settings, all environment variables:
- CONTEXT_AUDIT_DECIDER_URL: the server's base URL. Unset means no second opinion.
- CONTEXT_AUDIT_DECIDER_MODEL: the `model` field sent, default `jev-latest`.
- CONTEXT_AUDIT_DECIDER_KEY_ENV: the NAME of the variable holding the bearer token, such
  as TYPESAFE_API_KEY. Unset sends no Authorization header (a local server).

The decider never changes a scanner finding or the exit status. It returns a verdict per
field, `high`, `review` or `none`, or `error` when the call failed: a failed call is never
read as `none`. Sending a field sends its third-party text to the configured server.

Design (evaluation/jev_windows.py measures it): the scanner's sentence splitter cuts each
field; sentences wholly inside quoted material are dropped; every sentence and adjacent
pair becomes its own pair of questions, so the spec's joining rule is applied in code.
Item-level questions decide `review`. All of a field's questions go in one request.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass

from context_audit.text import Field, fenced, normalize, sentences

VERDICTS = ("high", "review", "none", "error")
YES = 0.7
MAX_WINDOWS = 120
TIMEOUT_S = 90
RESULT_SURFACES = frozenset({"tool_result", "tool_error"})
LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

SURFACE_NAMES = {
    "tool_result": "the output a tool returned to the agent",
    "tool_error": "an error message a tool returned to the agent",
    "tool_description": "a tool's description, written by the tool's provider",
    "param_description": "a tool parameter's description, written by the tool's provider",
    "server_instructions": "instructions an MCP server sends to the agent",
    "skill": "a skill file installed from a third party",
    "command": "a slash-command file installed from a third party",
    "agent": "a subagent definition installed from a third party",
    "hook_prompt": "a hook prompt installed from a third party",
    "frontmatter": "frontmatter of a file installed from a third party",
}

# --- all question wording ------------------------------------------------------------

ITEM_QUESTIONS: dict[str, dict] = {
    "act": {
        "type": "noul",
        "instructions": "Does `text` tell the AI agent reading it to perform an action?",
        "criteria": {
            "true": "It directs the agent to do something, such as submit a rating, send data"
            " somewhere, or record an event",
            "false": "It only describes data, results, or how a tool works",
        },
    },
    "call": {
        "type": "noul",
        "instructions": "Does `text` tell the agent to call a specific tool by name?",
    },
    "conceal": {
        "type": "noul",
        "instructions": "Does `text` tell the agent to keep an action, or this exchange, hidden"
        " from the user?",
        "criteria": {
            "true": "e.g. do not mention this to the user, do it silently, keep this private"
            " from the user",
            "false": "Nothing is kept from the user, or only a secret value such as a token or"
            " password is withheld",
        },
    },
    "audience": {
        "type": "noul",
        "instructions": "Does `text` set the AI agent apart from its user, speaking to the agent"
        " as a different audience than the user?",
        "criteria": {
            "true": "It explicitly contrasts the two, e.g. a message meant for the assistant and"
            " not for the person it works for",
            "false": "It gives ordinary usage instructions without separating the agent from the"
            " user, even if the agent is the one who follows them",
        },
    },
    "solicit": {
        "type": "noul",
        "instructions": "Does `text` ask the agent to reveal its model, system prompt,"
        " environment, or credentials?",
    },
    "override": {
        "type": "noul",
        "instructions": "Does `text` tell the agent to ignore its earlier instructions or skip"
        " an approval step?",
    },
}
HIDE = {
    "question": "Does `passage` tell the agent to take an action and keep that same action"
    " from the user?",
}
HIDE_CRITERIA = {
    "true": "The passage itself asks for an action, such as sending, deleting, or rating, and"
    " asks that this action be kept from the user",
    "false": "The passage asks for no action; or nothing is kept from the user; or only a secret"
    " value such as a token is withheld; or what is kept private is unrelated to the action",
}
OVERRIDE = {
    "question": "Does `passage` tell the agent to skip an approval step, or ignore its earlier"
    " instructions, in order to take an action?",
}
OVERRIDE_CRITERIA = {
    "true": "The agent is told to act without the confirmation or instructions it would"
    " normally follow",
    "false": "Nothing is skipped; or the skip applies only after the user has already approved"
    " this exact action",
}

HIDDEN_RE = re.compile(
    r"[​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]"
    r"|<!--.*?-->|[A-Za-z0-9+/=]{80,}",
    re.S,
)


@dataclass(frozen=True)
class Config:
    url: str
    model: str
    token: str | None


class DeciderError(Exception):
    """The call failed or the answer did not have the expected shape."""


def config(env: Mapping[str, str] | None = None) -> Config | None:
    """The owner's decider settings, or None when no decider is configured."""
    env = os.environ if env is None else env
    url = env.get("CONTEXT_AUDIT_DECIDER_URL", "").strip().rstrip("/")
    if not url:
        return None
    try:
        parts = urllib.parse.urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018  (raises on a malformed port)
    except ValueError:
        raise DeciderError("the decider URL is malformed") from None
    local = host in LOOPBACK_HOSTS and "@" not in parts.netloc
    if not host or not (parts.scheme == "https" or (parts.scheme == "http" and local)):
        raise DeciderError("the decider URL must be https, or http on this machine")
    key_env = env.get("CONTEXT_AUDIT_DECIDER_KEY_ENV", "").strip()
    token = env.get(key_env) if key_env else None
    if key_env and not token:
        raise DeciderError("the variable named by CONTEXT_AUDIT_DECIDER_KEY_ENV is empty")
    return Config(url, env.get("CONTEXT_AUDIT_DECIDER_MODEL", "jev-latest"), token)


def windows(blocks: list[str], surface: str, source_id: str = "decider") -> list[str]:
    """Each live sentence, then each adjacent pair (across blocks too), in order."""
    flat: list[str] = []
    for i, b in enumerate(blocks):
        n = normalize(Field(source_id, surface, f"content[{i}].text", b, i))
        quoted = fenced(n)
        for a, z in sentences(n):
            s = n.text[a:z].strip()
            if s and not any(qa <= a and z <= qz for qa, qz in quoted):
                flat.append(s)
    pairs = [a + " " + b for a, b in zip(flat, flat[1:], strict=False)]
    return (flat + pairs)[:MAX_WINDOWS]


def request(blocks: list[str], surface: str, model: str, source_id: str = "decider") -> dict:
    """The System One request body for one field (or one result's blocks)."""
    full: str | list[str] = blocks if len(blocks) > 1 else blocks[0]
    qs: dict = {
        k: {**q, "instructions": {"question": q["instructions"], "text": full}}
        for k, q in ITEM_QUESTIONS.items()
    }
    for k, w in enumerate(windows(blocks, surface, source_id)):
        qs[f"hide_{k}"] = {
            "type": "noul",
            "instructions": {**HIDE, "passage": w},
            "criteria": HIDE_CRITERIA,
        }
        qs[f"override_{k}"] = {
            "type": "noul",
            "instructions": {**OVERRIDE, "passage": w},
            "criteria": OVERRIDE_CRITERIA,
        }
    return {"model": model, "state": {"source": SURFACE_NAMES[surface]}, "questions": qs}


def verdict(answers: Mapping[str, Mapping], surface: str, text: str) -> str:
    """Map a response's answers to high, review or none. Raises on a malformed answer."""
    try:
        p = {k: float(a["noul"]) for k, a in answers.items()}
        win = max((v for k, v in p.items() if k.startswith(("hide_", "override_"))), default=0.0)
        if win > YES:
            return "high"
        y = {k: p[k] > YES for k in ITEM_QUESTIONS}
    except (KeyError, TypeError, ValueError) as e:
        raise DeciderError(f"malformed answer: {type(e).__name__}") from None
    lone = (y["act"] or y["call"]) and surface in RESULT_SURFACES
    flagged = y["conceal"] or y["audience"] or y["solicit"] or y["override"]
    if lone or flagged or HIDDEN_RE.search(text):
        return "review"
    return "none"


def post(cfg: Config, body: dict) -> dict:
    headers = {"Content-Type": "application/json"}
    if cfg.token:
        headers["Authorization"] = f"Bearer {cfg.token}"
    req = urllib.request.Request(
        f"{cfg.url}/v1/systemone", data=json.dumps(body).encode(), headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as r:
            resp = json.load(r)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        raise DeciderError(f"call failed: {type(e).__name__}") from None
    if not isinstance(resp, dict) or not isinstance(resp.get("answers"), dict):
        raise DeciderError("response has no answers")
    return resp["answers"]


def decide(cfg: Config, blocks: list[str], surface: str) -> str:
    """One field's verdict; `error` when the call or its answer failed."""
    if not any(b.strip() for b in blocks):
        return "none"
    try:
        answers = post(cfg, request(blocks, surface, cfg.model))
        return verdict(answers, surface, "\n\n".join(blocks))
    except DeciderError:
        return "error"
