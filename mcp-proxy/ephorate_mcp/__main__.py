"""CLI entrypoint: `ephorate-mcp --config ephorate-mcp.yaml`."""

from __future__ import annotations

import argparse
import sys

from ephorate_mcp.config import load_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ephorate-mcp",
        description="Policy-gate MCP tool calls through Ephorate.",
    )
    parser.add_argument(
        "--config",
        "-c",
        default="ephorate-mcp.yaml",
        help="path to the proxy config (default: ephorate-mcp.yaml)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="validate the config and exit (no MCP runtime needed)",
    )
    args = parser.parse_args(argv)

    try:
        config = load_config(args.config)
    except (OSError, ValueError) as exc:
        print(f"config error: {exc}", file=sys.stderr)
        return 2

    if args.check:
        print(
            f"ok: {len(config.upstreams)} upstream(s), "
            f"transport={config.listen_transport}, on_error={config.enforcement.on_error}"
        )
        return 0

    # The MCP runtime (optional dep) lives in server.py. Route by listen
    # transport: stdio sidecar (event loop) vs streamable-HTTP (ASGI + uvicorn).
    if config.listen_transport == "stdio":  # pragma: no cover
        import asyncio

        from ephorate_mcp.server import run_proxy

        asyncio.run(run_proxy(config))
    else:  # pragma: no cover
        from ephorate_mcp.server import run_http

        run_http(config)
    return 0  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
