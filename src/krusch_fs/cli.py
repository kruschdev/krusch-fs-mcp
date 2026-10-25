"""
KruschFS Unified CLI (cli.py)
=============================
Commands:
- `krusch-fs sync-fleet [--nodes workstation,compute-node-01]`
- `krusch-fs scan <path> [--workspace ...] [--node ...]`
- `krusch-fs search "<query>" [--workspace ...] [--node ...]`
- `krusch-fs tree <file_path> [--node ...]`
- `krusch-fs page <file_path> [--page 1] [--node ...]`
- `krusch-fs remember <file_path> --page 1 --quote "..." --memory "..." [--node ...]`
- `krusch-fs locate [--pattern ...] [--ext ...] [--node ...]`
- `krusch-fs status`
- `krusch-fs mcp`
"""

import sys
import re
import json
import argparse
from .client import KruschFSClient
from .config import validate_nodes
from .mcp import main as run_mcp

_NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_WORKSPACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_SHELL_META_RE = re.compile(r"[;&|`$\r\n\x00]")


def validate_path(val: str) -> str:
    """Validate filesystem path argument against empty values, option injection, or shell metacharacters."""
    if not isinstance(val, str) or not val.strip():
        raise argparse.ArgumentTypeError("Path cannot be empty.")
    cleaned = val.strip()
    if cleaned.startswith("-"):
        raise argparse.ArgumentTypeError(f"Invalid path starting with '-': {val!r}")
    if _SHELL_META_RE.search(cleaned):
        raise argparse.ArgumentTypeError(f"Invalid shell metacharacters in path: {val!r}")
    return cleaned


def validate_workspace(val: str) -> str:
    """Validate workspace name against empty or invalid/shell-metacharacter values."""
    if not isinstance(val, str) or not val.strip():
        raise argparse.ArgumentTypeError("Workspace cannot be empty.")
    cleaned = val.strip()
    if cleaned.startswith("-") or _SHELL_META_RE.search(cleaned) or not _WORKSPACE_RE.match(cleaned):
        raise argparse.ArgumentTypeError(f"Invalid workspace name: {val!r}")
    return cleaned


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="krusch-fs",
        description="KruschFS: Standalone Opt-In OS Filesystem & KruschNexus Page-Anchored Memory Engine",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_fleet = sub.add_parser("sync-fleet", help="Synchronize configured computers across the fleet over SSH")
    p_fleet.add_argument("--nodes", type=validate_nodes, default=None, help="Comma-separated node names (default: all configured fleet nodes)")

    p_scan = sub.add_parser("scan", help="Scan a directory or file into KruschFS")
    p_scan.add_argument("path", type=validate_path, help="Target directory or file path")
    p_scan.add_argument("--workspace", type=validate_workspace, default=None, help="Optional workspace override (user_docs, system_config)")
    p_scan.add_argument("--node", type=validate_nodes, default=None, help="Target fleet host_node (default: local)")

    p_search = sub.add_parser("search", help="Hybrid search across OS files, pages, and page memories")
    p_search.add_argument("query", help="Search query")
    p_search.add_argument("--workspace", type=validate_workspace, default=None, help="Filter by workspace")
    p_search.add_argument("--node", type=validate_nodes, default=None, help="Filter by fleet host_node (or 'all')")
    p_search.add_argument("--limit", type=int, default=5, help="Max results")

    p_tree = sub.add_parser("tree", help="Show PageIndex Table of Contents and memory counts per page")
    p_tree.add_argument("file_path", type=validate_path, help="Target file path")
    p_tree.add_argument("--node", type=validate_nodes, default=None, help="Target fleet host_node")

    p_page = sub.add_parser("page", help="Read a specific 1-based page and its attached memories")
    p_page.add_argument("file_path", type=validate_path, help="Target file path")
    p_page.add_argument("--page", type=int, default=1, help="1-based page number")
    p_page.add_argument("--node", type=validate_nodes, default=None, help="Target fleet host_node")

    p_rem = sub.add_parser("remember", help="Pin a verified memory directly to a specific page")
    p_rem.add_argument("file_path", type=validate_path, help="Target file path")
    p_rem.add_argument("--page", type=int, required=True, help="1-based page number")
    p_rem.add_argument("--quote", required=True, help="Verbatim sentence on that page proving the memory")
    p_rem.add_argument("--memory", required=True, help="Synthesized memory statement")
    p_rem.add_argument("--category", default="fact", help="Memory category (fact, slot, decision, config_rule)")
    p_rem.add_argument("--key", default=None, help="Optional structured slot key")
    p_rem.add_argument("--node", type=validate_nodes, default=None, help="Target fleet host_node")

    p_loc = sub.add_parser("locate", help="Fast Tier-A metadata & duplicate locator")
    p_loc.add_argument("--pattern", default=None, help="Filename or path pattern")
    p_loc.add_argument("--ext", default=None, help="File extension filter")
    p_loc.add_argument("--node", type=validate_nodes, default=None, help="Filter by fleet host_node")
    p_loc.add_argument("--duplicates", action="store_true", help="Only return files with duplicate hashes")

    sub.add_parser("status", help="Show KruschFS index statistics across all fleet nodes")
    sub.add_parser("mcp", help="Launch KruschFS stdio MCP server")

    args = parser.parse_args(argv)
    if args.cmd == "mcp":
        run_mcp()
        return 0

    client = KruschFSClient.from_env()
    if args.cmd == "sync-fleet":
        nodes_list = [n.strip() for n in args.nodes.split(",") if n.strip()] if args.nodes else None
        rep = client.sync_fleet(nodes=nodes_list)
        print(json.dumps(rep.model_dump(), indent=2))
    elif args.cmd == "scan":
        rep = client.scan_path(args.path, workspace=args.workspace, host_node=args.node)
        print(json.dumps(rep.model_dump(), indent=2))
    elif args.cmd == "search":
        hits = client.search(args.query, workspace=args.workspace, host_node=args.node, limit=args.limit)
        print(json.dumps([h.model_dump() for h in hits], indent=2))
    elif args.cmd == "tree":
        tree = client.get_page_tree(args.file_path, host_node=args.node)
        print(json.dumps(tree.model_dump(), indent=2))
    elif args.cmd == "page":
        view = client.read_page(args.file_path, page_number=args.page, host_node=args.node)
        print(json.dumps(view.model_dump() if not isinstance(view, list) else [v.model_dump() for v in view], indent=2))
    elif args.cmd == "remember":
        mem = client.remember_on_page(
            file_path=args.file_path,
            page_number=args.page,
            memory_content=args.memory,
            quoted_sentence=args.quote,
            category=args.category,
            memory_key=args.key,
            host_node=args.node,
        )
        print(json.dumps(mem.model_dump(), indent=2))
    elif args.cmd == "locate":
        res = client.locate(
            pattern=args.pattern,
            extension=args.ext,
            find_duplicates=args.duplicates,
            host_node=args.node,
        )
        print(json.dumps([r.model_dump() for r in res], indent=2))
    elif args.cmd == "status":
        print(json.dumps(client.status(), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
