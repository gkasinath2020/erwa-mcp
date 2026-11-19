"""Tests for the contract between this package and the `mcp` library.

These exist because of a 25-day production outage that the rest of the suite
could not see. mcp 2.0.0 moved ``mcp.server.fastmcp``; the shipped image
resolves dependencies at build time from a floating spec, so it baked in mcp 2.0
and crash-looped on import from the moment it was pushed — while all 95 tests
stayed green, because the dev venv had mcp 1.27.2 installed.

That is the shape of a test that is not a true test: it asserted things about
our source while silently assuming a dependency version nothing checked. Every
test here asserts against the *installed* library, so it fails wherever the
resolution is wrong — dev venv, CI, or image.
"""

from __future__ import annotations

import ast
import importlib
import importlib.metadata
import pathlib

import pytest

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "asgard_mcp"


def _mcp_imports() -> list[tuple[str, str, str]]:
    """(file, module, name) for every ``from mcp... import name`` in the package.

    Derived from the source rather than hardcoded, so a new import is covered
    the moment it is written — the failure mode here was an import nobody had a
    test for.
    """
    found = []
    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module == "mcp" or node.module.startswith("mcp."):
                    for alias in node.names:
                        found.append((path.name, node.module, alias.name))
    return found


def test_the_package_actually_imports_something_from_mcp():
    """Guard against this file becoming vacuous if the imports move."""
    assert _mcp_imports(), "no `from mcp... import` found; update this test"


@pytest.mark.parametrize("where,module,name", _mcp_imports())
def test_every_mcp_import_resolves_against_the_installed_library(where, module, name):
    """The exact assertion the outage needed.

    ``from mcp.server.fastmcp import Context, FastMCP`` raised
    ModuleNotFoundError in production for 25 days. Nothing failed, because no
    test ever performed that import against the resolved dependency.
    """
    try:
        mod = importlib.import_module(module)
    except ModuleNotFoundError as exc:  # pragma: no cover - the failure we guard
        pytest.fail(
            f"{where} imports `{name}` from `{module}`, which the installed "
            f"mcp {importlib.metadata.version('mcp')} does not provide: {exc}"
        )
    assert hasattr(mod, name), (
        f"{where} imports `{name}` from `{module}`, but the installed "
        f"mcp {importlib.metadata.version('mcp')} does not expose it"
    )


def test_installed_mcp_major_is_below_2():
    """The pin, asserted where it is actually observable.

    pyproject declares <2.0.0, but a declaration is not an installation: the
    broken image satisfied its own spec at the time it was built. This checks
    what is really present.
    """
    version = importlib.metadata.version("mcp")
    major = int(version.split(".")[0])
    assert major < 2, (
        f"installed mcp is {version}; 2.x moved mcp.server.fastmcp. "
        "Either restore the <2.0.0 pin or migrate server.py to the 2.x API."
    )
