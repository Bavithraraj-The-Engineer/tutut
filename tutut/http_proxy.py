"""
HTTP gateway for tutut.

Intercepts MCP Streamable HTTP traffic for a remote MCP server. Used for
claude.ai (and Claude Desktop / mobile account connectors): those clients
call MCP servers from Anthropic's cloud, so the only way to see their
traffic is to *be* the server they call. `tutut web` exposes this gateway
through a tunnel and you register the tunnel URL as a custom connector:

    claude.ai → Anthropic cloud → https://<tunnel>/<secret>/mcp
                                 → tutut gateway (popup, hold) → upstream MCP server

Supports:
  - POST with single or batch JSON-RPC; only tools/call is held for a decision
  - JSON and SSE (text/event-stream) responses, streamed through
  - GET (server-to-client SSE stream) and DELETE (end session) pass-through
  - Mcp-Session-Id and other end-to-end headers forwarded

Security (layered; every tools/call still needs the user's approval):
  - Caller allowlist: `tutut web` only accepts Anthropic's published
    outbound IP ranges (CF-Connecting-IP, trusted only from the local
    tunnel); anyone else gets 403 and can't even list the tools.
  - Optional path secret (`tutut web --path-secret`): only /<secret>/… is
    served, everything else is 404. Off by default because claude.ai's
    connector client refuses URLs with any secret path segment (observed:
    its validator gets 200 on initialize, then its real client never
    connects); fine for other HTTP clients.
  - Static upstream credentials (--upstream-header) are added by the
    gateway, so they never travel through Anthropic's cloud or the tunnel.
  - The request log masks the secret; there is no aiohttp access log.

Usage:
    tutut http --upstream https://my-mcp-server.example.com/mcp --server-name my-remote-server
    tutut web  --upstream https://my-mcp-server.example.com/mcp --server-name my-remote-server
"""

from __future__ import annotations

import asyncio
import hmac
import ipaddress
import json
import logging
import re
import time
from typing import Any
from urllib.parse import urlsplit

from .config import GuardianConfig
from .interceptor import Interceptor, Verdict
from .models import JsonRpcMessage, blocked_response

logger = logging.getLogger(__name__)

# Maximum request body size (10 MB)
MAX_BODY_SIZE = 10 * 1024 * 1024

# Local health endpoint (below the secret), used by `tutut web` to check
# the tunnel end to end without touching the upstream server.
HEALTH_PATH = "/__tutut/health"

# aiohttp is required for HTTP proxy mode
try:
    from aiohttp import ClientSession, ClientTimeout, web

    _AIOHTTP_AVAILABLE = True
    # JSON-RPC method names of a request, for the request log.
    _RPC_KEY: Any = web.RequestKey("tutut_rpc", str) if hasattr(web, "RequestKey") else "tutut_rpc"
except ImportError:
    _AIOHTTP_AVAILABLE = False
    _RPC_KEY = "tutut_rpc"

# Request headers never forwarded upstream: hop-by-hop headers, plus what
# the tunnel/CDN adds (forwarding cdn-loop to an upstream that is itself
# behind Cloudflare makes it reject the request as a loop).
_HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade", "host", "content-length",
    "accept-encoding", "cdn-loop", "true-client-ip", "x-real-ip",
}
_DROP_PREFIXES = ("cf-", "x-forwarded-")
# Response headers never copied back (aiohttp has already decoded the body).
_RESP_SKIP = {"content-length", "transfer-encoding", "content-encoding", "connection", "keep-alive"}

_RESOURCE_METADATA_RE = re.compile(r'resource_metadata="([^"]+)"')


def _json_response(
    data: Any, *, status: int = 200, headers: dict[str, str] | None = None
) -> "web.Response":
    """
    JSON response with a bare `application/json` content type.

    aiohttp's json_response() adds "; charset=utf-8". RFC 8259 defines no
    charset parameter for JSON, and MCP clients that compare the media type
    exactly (as claude.ai's connector client appears to) reject it.
    """
    return web.Response(
        body=json.dumps(data).encode("utf-8"),
        status=status,
        headers=headers,
        content_type="application/json",
    )


def client_ip(request: "web.Request") -> str:
    """
    The real caller's IP.

    Behind a Cloudflare tunnel every connection comes from cloudflared on
    localhost and Cloudflare's edge puts the caller in CF-Connecting-IP
    (overwriting any value the caller sent). The header is only trusted on
    loopback connections, so nobody reaching the gateway directly can fake it.
    """
    remote = request.remote or ""
    forwarded = request.headers.get("CF-Connecting-IP", "").strip()
    if forwarded and _is_loopback(remote):
        return forwarded
    return remote or "?"


def _is_loopback(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_loopback
    except ValueError:
        return False


def parse_networks(cidrs: Any) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """CIDR strings → networks; raises ValueError on a malformed one."""
    return [ipaddress.ip_network(str(c).strip(), strict=False) for c in cidrs]


def _normalize_content_type(value: str) -> str:
    """Drop parameters from JSON / SSE media types (see _json_response)."""
    media = value.split(";", 1)[0].strip().lower()
    return media if media in ("application/json", "text/event-stream") else value


class HttpProxy:
    """
    HTTP reverse proxy that intercepts MCP JSON-RPC tool calls.

    Implements the MCP Streamable HTTP transport:
    - POST: JSON-RPC requests (single or batch)
    - GET: SSE stream for server-initiated messages
    - DELETE: Session termination

    Only tools/call requests are intercepted; all other messages pass through.
    """

    def __init__(
        self,
        upstream_url: str,
        server_name: str,
        config: GuardianConfig,
        *,
        secret: str = "",
        upstream_headers: dict[str, str] | None = None,
        source: str | None = None,
        interceptor: Interceptor | None = None,
        buffer_sse: bool = False,
        allowed_networks: Any = None,
    ) -> None:
        self._upstream = upstream_url.rstrip("/")
        # Caller IP allowlist (CIDRs); None = anyone may call.
        self._allowed = parse_networks(allowed_networks) if allowed_networks is not None else None
        parts = urlsplit(self._upstream)
        self._upstream_origin = f"{parts.scheme}://{parts.netloc}"
        self._upstream_path = parts.path or "/"
        self._server_name = server_name
        self._config = config
        self._secret = secret
        self._mount = f"/{secret}" if secret else ""
        self._upstream_headers = dict(upstream_headers or {})
        # Answer POSTs with plain JSON even if the upstream streams SSE:
        # Cloudflare quick tunnels don't carry SSE, and clients must accept
        # either form for a POST.
        self._buffer_sse = buffer_sse
        self._source = source or (
            "claude.ai / Anthropic cloud (via tunnel)" if secret else "HTTP client"
        )
        self._interceptor = interceptor or Interceptor(
            config, server_name=server_name, transport="http", source=self._source
        )
        self._session: ClientSession | None = None

    # Kept for callers/tests that toggle these directly.
    @property
    def _gui_available(self) -> bool:
        return self._interceptor.gui_available

    @_gui_available.setter
    def _gui_available(self, value: bool) -> None:
        self._interceptor.gui_available = value

    @property
    def mount(self) -> str:
        """Path prefix this gateway serves ("/<secret>" or "")."""
        return self._mount

    def ip_allowed(self, ip: str) -> bool:
        if self._allowed is None:
            return True
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self._allowed)

    async def _get_session(self) -> ClientSession:
        """Get or create the upstream HTTP session."""
        if self._session is None or self._session.closed:
            # No total timeout: tool calls can be slow and GET streams are
            # long-lived. Only connecting is bounded.
            self._session = ClientSession(
                timeout=ClientTimeout(total=None, sock_connect=30),
                auto_decompress=True,
            )
        return self._session

    # -- routing -------------------------------------------------------------------

    def _route(self, path: str) -> str | None:
        """
        Map an incoming path to the upstream URL, or None (→ 404).

          <mount>, <mount>/, <mount>/mcp   → the upstream URL itself
          <mount>/.well-known/…            → upstream origin (OAuth discovery)
          other <mount>/…                  → upstream origin + path (no-secret mode only)
        """
        if self._mount:
            first, _, rest = path.lstrip("/").partition("/")
            if not hmac.compare_digest(first.encode(), self._secret.encode()):
                return None
            rest = "/" + rest
        else:
            rest = path or "/"

        if rest in ("/", "/mcp", self._upstream_path):
            return self._upstream
        if rest.startswith("/.well-known/") or not self._mount:
            return f"{self._upstream_origin}{rest}"
        return None

    async def handle_request(self, request: web.Request) -> web.StreamResponse:
        """
        Route incoming requests based on HTTP method, logging each one
        (with the secret masked) so the whole MCP exchange can be followed.
        """
        start = time.monotonic()
        status: Any = "error"
        try:
            response = await self._dispatch(request)
            status = response.status
            return response
        except asyncio.CancelledError:
            status = "client-gone"
            raise
        finally:
            logger.info(
                "%s %s -> %s in %dms | from=%s rpc=%s ua=%r accept=%r ctype=%r session=%s proto=%s",
                request.method,
                self._mask(request.path),
                status,
                int((time.monotonic() - start) * 1000),
                client_ip(request),
                request.get(_RPC_KEY, "-"),
                request.headers.get("User-Agent", "")[:80],
                request.headers.get("Accept", ""),
                request.headers.get("Content-Type", ""),
                "yes" if request.headers.get("Mcp-Session-Id") else "no",
                request.headers.get("MCP-Protocol-Version", "-"),
            )

    def _mask(self, path: str) -> str:
        return path.replace(self._secret, "<secret>") if self._secret else path

    async def _dispatch(self, request: web.Request) -> web.StreamResponse:
        """
        POST: JSON-RPC messages (may contain tools/call to intercept)
        GET:  SSE stream (pass through)
        DELETE: Session termination (pass through)
        """
        if request.path == self._mount + HEALTH_PATH:
            # Exempt from the allowlist: `tutut web` checks the tunnel from
            # this machine's own public IP. Reveals nothing about the upstream.
            return _json_response({"ok": True})

        if not self.ip_allowed(client_ip(request)):
            return web.Response(status=403, text="Forbidden")

        target = self._route(request.path)
        if target is None:
            return web.Response(status=404, text="Not Found")

        if request.method == "POST":
            return await self._handle_post(request, target)
        if request.method in ("GET", "DELETE"):
            return await self._forward_passthrough(request, target)
        return _json_response(
            {"error": f"Method {request.method} not supported"}, status=405
        )

    # -- POST: JSON-RPC ------------------------------------------------------------

    async def _handle_post(self, request: web.Request, target: str | None = None) -> web.StreamResponse:
        """Handle POST requests containing JSON-RPC messages."""
        try:
            if request.content_length and request.content_length > MAX_BODY_SIZE:
                return _json_response(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32600, "message": "Request body too large"},
                    },
                    status=413,
                )

            body = await request.read()

            try:
                payload = json.loads(body)
            except (json.JSONDecodeError, ValueError):
                return await self._forward_raw(request, body, target)  # not JSON

            items = payload if isinstance(payload, list) else [payload]
            request[_RPC_KEY] = ",".join(
                str(m.get("method") or ("response" if "id" in m else "?"))
                for m in items if isinstance(m, dict)
            ) or "-"

            if isinstance(payload, list):
                return await self._handle_batch(request, payload, body, target)
            if isinstance(payload, dict):
                return await self._handle_single(request, payload, body, target)
            return await self._forward_raw(request, body, target)

        except asyncio.CancelledError:
            raise  # client disconnected: let aiohttp clean up
        except Exception:
            logger.exception("Error handling POST request")
            return _json_response(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": "Internal proxy error"},
                },
                status=500,
            )

    async def _handle_single(
        self,
        request: web.Request,
        payload: dict[str, Any],
        raw_body: bytes,
        target: str | None = None,
    ) -> web.StreamResponse:
        """Handle a single JSON-RPC request."""
        msg = JsonRpcMessage(raw=payload)

        if msg.is_tool_call:
            verdict = await self._decide(msg, request)
            if not verdict.allowed:
                if msg.id is None:
                    return web.Response(status=202)  # notification: no answer
                return _json_response(
                    blocked_response(msg.id, msg.tool_name, self._server_name, verdict.decided_by)
                )

        return await self._forward_raw(request, raw_body, target)

    async def _handle_batch(
        self,
        request: web.Request,
        batch: list[Any],
        raw_body: bytes,
        target: str | None = None,
    ) -> web.StreamResponse:
        """
        Handle a batch JSON-RPC request.

        Each tools/call in the batch is decided independently. Blocked items
        get a blocked response; the rest are forwarded to the upstream server.
        """
        to_forward: list[Any] = []
        blocked_responses: list[dict[str, Any]] = []

        for item in batch:
            if not isinstance(item, dict):
                to_forward.append(item)
                continue

            msg = JsonRpcMessage(raw=item)
            if msg.is_tool_call:
                verdict = await self._decide(msg, request)
                if not verdict.allowed:
                    if msg.id is not None:
                        blocked_responses.append(
                            blocked_response(msg.id, msg.tool_name, self._server_name, verdict.decided_by)
                        )
                    continue

            to_forward.append(item)

        if not to_forward:
            return _json_response(blocked_responses)

        forward_body = json.dumps(to_forward).encode("utf-8")
        upstream_response = await self._forward_raw(request, forward_body, target)

        # Merge blocked responses into a JSON (non-streamed) upstream answer.
        if blocked_responses and isinstance(upstream_response, web.Response):
            try:
                upstream_results = json.loads(upstream_response.body)
                if isinstance(upstream_results, list):
                    return _json_response(upstream_results + blocked_responses)
            except Exception:
                pass

        return upstream_response

    async def _decide(self, msg: JsonRpcMessage, request: web.Request | None = None) -> Verdict:
        """Run the shared decision engine; errors fail closed."""
        extra = None
        if request is not None:
            ua = request.headers.get("User-Agent")
            if ua:
                extra = {"user_agent": ua[:200]}
        try:
            return await self._interceptor.decide(msg, extra=extra)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Decision failed; blocking %s", msg.tool_name)
            return Verdict(False, "error")

    async def _check_tool_call(self, msg: JsonRpcMessage) -> bool:
        """Whether a tool call may be forwarded (True) or must be blocked."""
        return (await self._decide(msg)).allowed

    # -- forwarding ----------------------------------------------------------------

    def _upstream_request_headers(self, request: web.Request) -> dict[str, str]:
        injected = {k.lower() for k in self._upstream_headers}
        headers: dict[str, str] = {}
        for key, value in request.headers.items():
            low = key.lower()
            if low in _HOP_BY_HOP or low.startswith(_DROP_PREFIXES):
                continue
            if low in injected:
                continue  # ours win
            if self._upstream_headers and low == "authorization":
                continue  # static upstream credentials replace the client's
            headers[key] = value
        headers.update(self._upstream_headers)
        headers["Accept-Encoding"] = "identity"
        return headers

    def _target(self, request: web.Request, target: str | None) -> str:
        if target is not None:
            return target
        return self._route(request.path) or self._upstream

    async def _forward_raw(
        self, request: web.Request, body: bytes, target: str | None = None
    ) -> web.StreamResponse:
        """Forward a POST body to the upstream server, preserving headers."""
        return await self._send_upstream(request, self._target(request, target), body)

    async def _forward_passthrough(
        self, request: web.Request, target: str | None = None
    ) -> web.StreamResponse:
        """Forward GET/DELETE requests transparently."""
        return await self._send_upstream(request, self._target(request, target), None)

    async def _send_upstream(
        self, request: web.Request, url: str, body: bytes | None
    ) -> web.StreamResponse:
        session = await self._get_session()
        try:
            async with session.request(
                method=request.method,
                url=url,
                headers=self._upstream_request_headers(request),
                data=body if request.method == "POST" else None,
                params=request.query,
                allow_redirects=False,
            ) as upstream_resp:
                content_type = upstream_resp.headers.get("Content-Type", "")
                if "text/event-stream" in content_type:
                    if self._buffer_sse and request.method == "POST":
                        return await self._collect_sse(request, upstream_resp)
                    return await self._stream_sse(request, upstream_resp)
                return await self._return_body(request, upstream_resp)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Error forwarding %s to upstream %s", request.method, url)
            return _json_response(
                {"error": "Failed to reach upstream MCP server"}, status=502
            )

    def _response_headers(self, request: web.Request, upstream_resp: Any) -> dict[str, str]:
        headers = {
            k: (_normalize_content_type(v) if k.lower() == "content-type" else v)
            for k, v in upstream_resp.headers.items()
            if k.lower() not in _RESP_SKIP
        }
        www = headers.get("WWW-Authenticate")
        if www:
            headers["WWW-Authenticate"] = self._rewrite_resource_metadata(request, www)
        return headers

    def _public_base(self, request: web.Request) -> str:
        """Our public origin as the client sees it (tunnel host over https)."""
        proto = request.headers.get("X-Forwarded-Proto", request.scheme)
        host = request.headers.get("X-Forwarded-Host", request.host)
        return f"{proto}://{host}"

    def _rewrite_resource_metadata(self, request: web.Request, www: str) -> str:
        """
        OAuth (best effort): point the client at *our* copy of the upstream's
        protected-resource metadata, so discovery goes through the gateway.
        """
        def swap(match: re.Match[str]) -> str:
            url = match.group(1)
            if not url.startswith(self._upstream_origin):
                return match.group(0)
            path = url[len(self._upstream_origin):]
            return f'resource_metadata="{self._public_base(request)}{self._mount}{path}"'

        return _RESOURCE_METADATA_RE.sub(swap, www)

    async def _stream_sse(self, request: web.Request, upstream_resp: Any) -> web.StreamResponse:
        """Stream an SSE response from upstream to client."""
        response = web.StreamResponse(
            status=upstream_resp.status,
            headers=self._response_headers(request, upstream_resp),
        )
        await response.prepare(request)
        try:
            async for chunk in upstream_resp.content.iter_any():
                await response.write(chunk)
            await response.write_eof()
        except (ConnectionResetError, ConnectionError):
            logger.debug("Client went away during an SSE stream")
        return response

    async def _collect_sse(self, request: web.Request, upstream_resp: Any) -> web.Response:
        """
        Read a POST's SSE answer to the end and return its JSON-RPC
        response(s) as one JSON body. Progress notifications in the stream
        are dropped.
        """
        text = (await upstream_resp.read()).decode("utf-8", errors="replace")
        responses = [
            m for m in parse_sse_messages(text)
            if isinstance(m, dict) and "id" in m and ("result" in m or "error" in m)
        ]
        headers = {
            k: v for k, v in self._response_headers(request, upstream_resp).items()
            if k.lower() != "content-type"
        }
        if not responses:
            return web.Response(status=202, headers=headers)
        self._learn_tools(request, responses)
        body = responses[0] if len(responses) == 1 else responses
        return _json_response(body, status=upstream_resp.status, headers=headers)

    def _learn_tools(self, request: web.Request, payload: Any) -> None:
        """Pick up tool annotations (risk hints) from tools/list answers."""
        if "tools/list" not in str(request.get(_RPC_KEY, "")):
            return
        for item in payload if isinstance(payload, list) else [payload]:
            if isinstance(item, dict):
                self._interceptor.learn_tools(item.get("result"))

    async def _return_body(self, request: web.Request, upstream_resp: Any) -> web.Response:
        """Return a full body response from upstream."""
        resp_body = await upstream_resp.read()
        if (
            request.path.startswith(f"{self._mount}/.well-known/oauth-protected-resource")
            and upstream_resp.status == 200
        ):
            resp_body = self._rewrite_protected_resource(request, resp_body)
        if "tools/list" in str(request.get(_RPC_KEY, "")):
            try:
                self._learn_tools(request, json.loads(resp_body))
            except ValueError:
                pass
        return web.Response(
            status=upstream_resp.status,
            headers=self._response_headers(request, upstream_resp),
            body=resp_body,
        )

    def _rewrite_protected_resource(self, request: web.Request, body: bytes) -> bytes:
        """OAuth (best effort): the protected resource is now our URL."""
        try:
            meta = json.loads(body)
        except ValueError:
            return body
        if isinstance(meta, dict) and "resource" in meta:
            meta["resource"] = f"{self._public_base(request)}{self._mount}/mcp"
            return json.dumps(meta).encode("utf-8")
        return body

    async def cleanup(self, app: web.Application) -> None:
        """Clean up resources on shutdown."""
        if self._session and not self._session.closed:
            await self._session.close()


def parse_sse_messages(text: str) -> list[Any]:
    """JSON payloads of the `data:` fields of an SSE stream, in order."""
    messages: list[Any] = []
    data: list[str] = []

    def flush() -> None:
        if data:
            try:
                messages.append(json.loads("\n".join(data)))
            except ValueError:
                pass
            data.clear()

    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if not line:
            flush()
        elif line.startswith("data:"):
            value = line[5:]
            data.append(value[1:] if value.startswith(" ") else value)
    flush()
    return messages


def build_app(proxy: HttpProxy) -> "web.Application":
    app = web.Application(client_max_size=MAX_BODY_SIZE)
    app.router.add_route("*", "/{path_info:.*}", proxy.handle_request)
    app.on_cleanup.append(proxy.cleanup)
    return app


async def start_http_proxy(
    proxy: HttpProxy, host: str, port: int
) -> "web.AppRunner":
    """Start serving `proxy` on host:port; returns the runner to clean up."""
    if not _AIOHTTP_AVAILABLE:
        logger.error(
            "aiohttp is required for HTTP proxy mode. Install it with: pip install tutut[http]"
        )
        raise SystemExit(1)
    # access_log=None: request paths contain the secret.
    # handler_cancellation: if the client disconnects while a popup is open,
    # the handler is cancelled and the popup withdrawn.
    runner = web.AppRunner(build_app(proxy), access_log=None, handler_cancellation=True)
    await runner.setup()
    await web.TCPSite(runner, host=host, port=port).start()
    logger.info("HTTP gateway listening on %s:%d -> %s", host, port, proxy._upstream)
    return runner


async def run_http_proxy(
    upstream_url: str,
    server_name: str,
    config: GuardianConfig,
    *,
    upstream_headers: dict[str, str] | None = None,
) -> None:
    """Start the HTTP proxy server (local use, no secret) and run forever."""
    proxy = HttpProxy(upstream_url, server_name, config, upstream_headers=upstream_headers)
    runner = await start_http_proxy(proxy, config.http_proxy_host, config.http_proxy_port)
    print(
        f"tutut HTTP proxy running on "
        f"http://{config.http_proxy_host}:{config.http_proxy_port}/mcp\n"
        f"Forwarding to: {upstream_url}\n"
        f"Press Ctrl+C to stop.",
        file=__import__("sys").stderr,
    )
    try:
        await asyncio.Event().wait()
    except asyncio.CancelledError:
        pass
    finally:
        await runner.cleanup()
