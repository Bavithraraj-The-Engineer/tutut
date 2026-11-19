"""
Risk hints for the approval popup (and the audit log).

Two signals, combined pessimistically:

  1. MCP tool annotations the server declared in `tools/list`
     (readOnlyHint / destructiveHint / openWorldHint). Only explicit values
     are used - the spec's defaults would make every tool "destructive".
  2. The tool name ("delete_note" → destructive, "list_notes" → read-only).

Annotations are *hints from the server*, which may be wrong or malicious
(a server can label `delete_everything` read-only), so the more severe of
the two signals wins and the popup says where the label came from.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Ordered by severity.
LEVELS = ("unknown", "low", "medium", "high")
LABELS = {
    "high": "Destructive",
    "medium": "Modifies data",
    "low": "Read-only",
    "unknown": "Unknown effect",
}

_HIGH = {
    "delete", "del", "remove", "rm", "drop", "destroy", "erase", "purge", "truncate", "wipe",
    "kill", "terminate", "revoke", "uninstall", "reset", "overwrite", "shred", "nuke",
}
_MEDIUM = {
    "write", "create", "update", "edit", "set", "send", "post", "put", "patch", "move", "mv",
    "rename", "copy", "cp", "exec", "execute", "run", "install", "deploy", "push", "merge",
    "add", "insert", "upload", "publish", "transfer", "pay", "approve", "commit", "apply",
    "modify", "save", "submit", "invite", "share", "assign", "close", "archive", "start",
    "stop", "restart", "sync", "import", "append", "replace", "change", "comment", "reply",
    "book", "schedule", "cancel", "mkdir", "touch", "chmod", "chown", "eval", "shell", "bash",
}
_LOW = {
    "read", "get", "list", "ls", "search", "find", "fetch", "query", "view", "show", "describe",
    "count", "stat", "info", "status", "head", "tail", "browse", "lookup", "check", "inspect",
    "preview", "tree", "whoami", "ping", "health", "explain", "summarize", "lint", "validate",
}

_WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])|\d+")


@dataclass(frozen=True)
class Risk:
    level: str          # one of LEVELS
    label: str          # short badge text
    reason: str         # one line explaining where the label comes from


def name_words(tool_name: str) -> list[str]:
    """'deleteNote' / 'delete_note' / 'files.delete' → ['delete', 'note']."""
    return [w.lower() for w in _WORD.findall(tool_name or "")]


def _from_name(tool_name: str) -> tuple[str, str]:
    words = name_words(tool_name)
    for level, vocab, what in (("high", _HIGH, "deletes or destroys"),
                               ("medium", _MEDIUM, "changes something"),
                               ("low", _LOW, "only reads")):
        hit = next((w for w in words if w in vocab), None)
        if hit:
            return level, f"its name (“{hit}”) suggests it {what}"
    return "unknown", ""


def _from_annotations(annotations: dict[str, Any] | None) -> tuple[str, str]:
    a = annotations or {}
    if a.get("readOnlyHint") is True:
        return "low", "the server marks it read-only"
    if a.get("destructiveHint") is True:
        return "high", "the server marks it destructive"
    if a.get("destructiveHint") is False or a.get("readOnlyHint") is False:
        return "medium", "the server marks it as making changes"
    return "unknown", ""


def classify(tool_name: str, annotations: dict[str, Any] | None = None) -> Risk:
    """Combine server annotations and the tool name; the worse one wins."""
    ann_level, ann_why = _from_annotations(annotations)
    name_level, name_why = _from_name(tool_name)
    level = max(ann_level, name_level, key=LEVELS.index)

    if level == "unknown":
        reason = "No hints from the server or the name — check the arguments"
    elif ann_level == name_level or name_level == "unknown":
        reason = (ann_why or name_why)
    elif ann_level == "unknown":
        reason = name_why
    elif level == name_level:
        reason = f"{name_why}, although {ann_why}"
    else:
        reason = f"{ann_why}, although {name_why}"
    if (annotations or {}).get("openWorldHint") is True:
        reason += "; reaches external systems"
    return Risk(level, LABELS[level], reason[:1].upper() + reason[1:])


# -- JSON syntax tokens (for highlighting arguments) ------------------------------

_TOKEN = re.compile(
    r'(?P<string>"(?:\\.|[^"\\])*")(?P<colon>\s*:)?'
    r"|(?P<number>-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)"
    r"|(?P<literal>\btrue\b|\bfalse\b|\bnull\b)"
    r"|(?P<punct>[{}\[\],:])"
    r"|(?P<space>\s+)"
    r"|(?P<other>.)",
    re.DOTALL,
)


def json_tokens(text: str) -> list[tuple[str, str]]:
    """
    Split (possibly truncated) pretty-printed JSON into (kind, text) runs:
    key, string, number, literal, punct, space, other. Joining the texts
    gives back the input exactly.
    """
    out: list[tuple[str, str]] = []
    for m in _TOKEN.finditer(text):
        if m.group("string") is not None:
            if m.group("colon") is not None:
                out.append(("key", m.group("string")))
                out.append(("punct", m.group("colon")))
            else:
                out.append(("string", m.group("string")))
        else:
            kind = m.lastgroup or "other"
            out.append((kind, m.group(kind)))
    return out
