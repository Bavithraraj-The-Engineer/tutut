"""
tutut — Monitor and control MCP tool calls with user confirmation.

A security proxy that sits between Claude (Desktop or Web) and MCP servers,
intercepting every tool call and giving the user control over whether each
request is allowed or blocked.

Three interception paths, one decision engine:
  - Stdio proxy:  wraps Claude Desktop's local MCP servers
  - mcp-remote:   remote servers used from Claude Desktop, run locally via
                  `tutut add-remote` and wrapped like local ones
  - Web gateway:  `tutut web` - claude.ai connectors via a tunnel to tutut
"""

__version__ = "1.0.0"
