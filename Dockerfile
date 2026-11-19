FROM python:3.12-slim

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
RUN pip install --no-cache-dir .

# Import the server at BUILD time so a bad dependency resolution can never be
# pushed. Dependencies here are resolved at build, not pinned in a lockfile, so
# a new major of a floating dep silently changes what ships. That is exactly how
# v0.5.0 shipped: it was built one day after mcp 2.0.0 moved mcp.server.fastmcp,
# and crash-looped on import from the moment it was pushed — for 25 days, while
# the test suite stayed green because the dev venv had an older mcp installed.
# The build now fails instead of producing a broken artifact.
RUN python -c "import asgard_mcp.server" \
 && python -c "import importlib.metadata as m; v=m.version('mcp'); \
assert int(v.split('.')[0]) < 2, f'mcp {v} moved mcp.server.fastmcp'; print('mcp', v, 'OK')"

ENV DNEY_API_URL=http://localhost:8000
ENV MCP_PORT=3001
# Auth0 OAuth (optional). When AUTH0_ISSUER and MCP_AUDIENCE are both set, the
# server enforces Bearer-JWT auth for keyless /mcp requests and resolves the
# caller's org by email via MCP_SERVICE_TOKEN. Left unset => legacy path-key mode.
# ENV AUTH0_ISSUER=https://YOUR-TENANT.us.auth0.com/
# ENV MCP_AUDIENCE=https://mcp.dney.dev
# ENV AUTH0_EMAIL_CLAIM=https://dney.dev/email
# ENV MCP_PUBLIC_URL=https://mcp.dney.dev
# ENV MCP_SERVICE_TOKEN=<shared-secret-with-backend>
EXPOSE 3001

# Serve the wrapped ASGI app (FastMCP + path-based auth + /health).
# --timeout-keep-alive must outlast the ALB idle timeout (300 s). At uvicorn's
# default 5 s the app closes idle sockets first, and the ALB can send the next
# request down a dead one (13 Nov 2026: an MCP call failed with ECONNRESET after
# 36 ms and never reached the app; Baton #2395). Same fix as asgard-services !346.
# scripts/check_alb_keepalive.sh (asgard-services) reads this line.
CMD ["sh", "-c", "exec uvicorn asgard_mcp.server:app --host ${MCP_HOST:-0.0.0.0} --port ${MCP_PORT:-3001} --timeout-keep-alive 310"]
