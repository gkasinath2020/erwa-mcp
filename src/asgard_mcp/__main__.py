import sys

from asgard_mcp.server import mcp

transport = "stdio" if "--stdio" in sys.argv else "streamable-http"
mcp.run(transport=transport)
