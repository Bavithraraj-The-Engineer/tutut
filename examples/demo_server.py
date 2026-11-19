#!/usr/bin/env python3
"""
A tiny remote MCP server (Streamable HTTP, no auth) for testing and demos.

It keeps a few notes in memory and exposes four tools - two harmless reads
and two writes - so a demo can show one request being approved and another
being blocked:

    list_notes   read-only
    read_note    read-only
    add_note     writes
    delete_note  destructive

Run:
    python examples/demo_server.py               # http://127.0.0.1:8931/mcp

Then put tutut in front of it:
    tutut add-remote demo-notes http://127.0.0.1:8931/mcp     # Claude Desktop (path 2)
    tutut web --upstream http://127.0.0.1:8931/mcp --server-name demo-notes   # claude.ai (path 3)

Only needs aiohttp (`pip install aiohttp`, or `pip install tutut[http]`).
It implements just enough of MCP for tools: initialize, ping, tools/list,
tools/call; responses are plain JSON (allowed by the Streamable HTTP spec).
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import uuid
from typing import Any

from aiohttp import web

logger = logging.getLogger("demo_server")

SERVER_INFO = {"name": "tutut-demo-notes", "version": "1.0.0"}
LATEST_PROTOCOL = "2025-06-18"

NOTES: dict[str, str] = {
    "shopping": "milk, eggs, coffee",
    "ideas": "write the tutut demo video script",
    "secrets": "the launch date is a secret - this note should never be deleted",
}

TOOLS = [
    {
        "name": "list_notes",
        "title": "List notes",
        "description": "List the titles of all saved notes.",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "read_note",
        "title": "Read a note",
        "description": "Read the text of one note by its title.",
        "inputSchema": {
            "type": "object",
            "properties": {"title": {"type": "string", "description": "Note title"}},
            "required": ["title"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "add_note",
        "title": "Add a note",
        "description": "Save a new note (or overwrite one with the same title).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "text": {"type": "string"},
            },
            "required": ["title", "text"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": False},
    },
    {
        "name": "delete_note",
        "title": "Delete a note",
        "description": "Permanently delete a note by its title.",
        "inputSchema": {
            "type": "object",
            "properties": {"title": {"type": "string"}},
            "required": ["title"],
        },
        "annotations": {"readOnlyHint": False, "destructiveHint": True},
    },
]


def _text(text: str, is_error: bool = False) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def call_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "list_notes":
        return _text("Notes: " + (", ".join(sorted(NOTES)) or "(none)"))
    if name == "read_note":
        title = str(args.get("title", ""))
        if title not in NOTES:
            return _text(f"No note titled {title!r}.", is_error=True)
        return _text(NOTES[title])
    if name == "add_note":
        title, text = str(args.get("title", "")), str(args.get("text", ""))
        if not title:
            return _text("A title is required.", is_error=True)
        NOTES[title] = text
        return _text(f"Saved note {title!r}.")
    if name == "delete_note":
        title = str(args.get("title", ""))
        if NOTES.pop(title, None) is None:
            return _text(f"No note titled {title!r}.", is_error=True)
        return _text(f"Deleted note {title!r}.")
    raise KeyError(name)


def handle_message(msg: dict[str, Any]) -> dict[str, Any] | None:
    """Answer one JSON-RPC message (None for notifications/responses)."""
    method = msg.get("method")
    if method is None or "id" not in msg:
        return None  # a notification or a response: nothing to answer
    msg_id = msg["id"]
    params = msg.get("params") or {}

    def ok(result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    def err(code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}

    if method == "initialize":
        requested = str(params.get("protocolVersion", ""))
        version = requested if re.fullmatch(r"\d{4}-\d{2}-\d{2}", requested) else LATEST_PROTOCOL
        return ok({
            "protocolVersion": version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
            "instructions": "A demo notes server used to test tutut's interception.",
        })
    if method == "ping":
        return ok({})
    if method == "tools/list":
        return ok({"tools": TOOLS})
    if method == "tools/call":
        name = params.get("name")
        try:
            result = call_tool(str(name), params.get("arguments") or {})
        except KeyError:
            return err(-32602, f"Unknown tool: {name}")
        logger.info("tools/call %s %s -> %s", name, json.dumps(params.get("arguments") or {}),
                    result["content"][0]["text"])
        return ok(result)
    return err(-32601, f"Method not found: {method}")


async def mcp_endpoint(request: web.Request) -> web.StreamResponse:
    if request.method == "GET":
        return web.Response(status=405, text="This server does not offer a GET stream")
    if request.method == "DELETE":
        return web.Response(status=200)
    if request.method != "POST":
        return web.Response(status=405)

    try:
        payload = await request.json()
    except ValueError:
        return _json(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}},
            status=400,
        )

    messages = payload if isinstance(payload, list) else [payload]
    answers = [a for a in (handle_message(m) for m in messages if isinstance(m, dict)) if a]
    if not answers:
        return web.Response(status=202)

    headers = {}
    if any(isinstance(m, dict) and m.get("method") == "initialize" for m in messages):
        headers["Mcp-Session-Id"] = uuid.uuid4().hex
    body = answers if isinstance(payload, list) else answers[0]
    return _json(body, headers=headers)


def _json(data: Any, status: int = 200, headers: dict[str, str] | None = None) -> web.Response:
    # Bare "application/json" like the official MCP SDK servers send;
    # aiohttp's json_response() would add "; charset=utf-8".
    return web.Response(body=json.dumps(data).encode(), status=status,
                        headers=headers, content_type="application/json")


def build_app(path: str = "/mcp") -> web.Application:
    app = web.Application()
    app.router.add_route("*", path, mcp_endpoint)
    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="tutut demo MCP server (notes)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8931)
    parser.add_argument("--path", default="/mcp", help="URL path of the MCP endpoint")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    print(f"Demo MCP server on http://{args.host}:{args.port}{args.path}  (Ctrl+C to stop)")
    web.run_app(build_app(args.path), host=args.host, port=args.port, print=None)


if __name__ == "__main__":
    main()
