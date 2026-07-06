"""CLI entrypoint: `praetor-mcp --config praetor-mcp.yaml`."""

from __future__ import annotations

import argparse
import sys

from praetor_mcp.config import load_config


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="praetor-mcp",
        description="Policy-gate MCP tool calls through Praetor.",
    )
    parser.add_argument(
        "--config",
        "-c",
        default="praetor-mcp.yaml",
        help="path to the proxy config (default: praetor-mcp.yaml)",
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

    # The event loop + MCP runtime live in server.run_proxy (optional dep).
    import asyncio  # pragma: no cover

    from praetor_mcp.server import run_proxy  # pragma: no cover

    asyncio.run(run_proxy(config))  # pragma: no cover
    return 0  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
