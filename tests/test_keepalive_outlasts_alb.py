"""The image's HTTP keep-alive must outlast the ALB's idle timeout.

If the app closes an idle connection first, the ALB can send the next request down
the dead socket; the caller sees a 502 or a reset and the app logs nothing. On
13 Nov 2026 an MCP call failed with ECONNRESET after 36 ms and never reached the
app (Baton #2395); the image ran uvicorn's default 5 s keep-alive.

ALB_IDLE_TIMEOUT_S is the live value (the production ALB's
idle_timeout.timeout_seconds, read 13 Nov 2026 by the backend's deploy-time
keep-alive check). That script reads the live value at deploy; this
copy keeps a local change from regressing it.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ALB_IDLE_TIMEOUT_S = 300


def _cmd() -> str:
    return next(
        line for line in (ROOT / "Dockerfile").read_text().splitlines() if line.startswith("CMD")
    )


def test_the_image_sets_a_keep_alive_above_the_alb_idle_timeout():
    m = re.search(r"--timeout-keep-alive\s+(\d+)", _cmd())
    assert m, "the CMD must set --timeout-keep-alive (uvicorn's default is 5 s)"
    assert int(m.group(1)) > ALB_IDLE_TIMEOUT_S


def test_the_image_serves_the_wrapped_app_on_the_configured_port():
    cmd = _cmd()
    assert "exec uvicorn asgard_mcp.server:app" in cmd
    assert "${MCP_PORT:-3001}" in cmd and "${MCP_HOST:-0.0.0.0}" in cmd

