"""
KruschFS Standalone MCP Server (mcp.py)
=======================================
Exposes the 6 canonical OS Filesystem & KruschNexus Page-Anchored Memory tools
across local workstations and multi-node SSH fleets.
Explicitly declares all 4 boolean MCP behavioral annotations
(`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`)
on every registered tool.
"""

import json
import sys
import threading
from typing import Optional, List

try:
    from mcp.server.mcpserver import MCPServer as _MCPServerClass
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP as _MCPServerClass  # type: ignore
    except ImportError:
        class _MCPServerClass:  # type: ignore
            def __init__(self, name: str = "KruschFSMCP", *args, **kwargs):
                self.name = name
                self._tools = {}

            def tool(self, *args, **kwargs):
                def decorator(f):
                    self._tools[f.__name__] = f
                    return f
                return decorator

            def run(self, *args, **kwargs):
                raise RuntimeError("The 'mcp' package is required to run KruschFS MCP Server.")

try:
    from mcp.types import ToolAnnotations
except ImportError:
    def ToolAnnotations(**kwargs):  # type: ignore
        return kwargs

from .client import KruschFSClient

_mcp_lock = threading.Lock()
_mcp_instance = None


def get_mcp():
    """Return the thread-safe singleton MCPServer instance."""
    global _mcp_instance
    if _mcp_instance is None:
        with _mcp_lock:
            if _mcp_instance is None:
                _mcp_instance = _MCPServerClass("krusch-fs")
    return _mcp_instance


mcp = get_mcp()


class _ClientRegistry:
    """Thread-safe holder for KruschFSClient without module-level global mutation."""

    def __init__(self) -> None:
        self._instance: Optional[KruschFSClient] = None
        self._lock = threading.Lock()

    def set(self, client: KruschFSClient) -> None:
        with self._lock:
            self._instance = client

    def get(self, explicit_client: Optional[KruschFSClient] = None) -> KruschFSClient:
        if explicit_client is not None:
            return explicit_client
        if self._instance is None:
            with self._lock:
                if self._instance is None:
                    self._instance = KruschFSClient.from_env()
        return self._instance


_registry = _ClientRegistry()


def set_client(client: KruschFSClient) -> None:
    _registry.set(client)


def get_client(client: Optional[KruschFSClient] = None) -> KruschFSClient:
    return _registry.get(client)


READ_ONLY_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)

WRITE_IDEMPOTENT_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=False,
    destructiveHint=False,
    idempotentHint=True,
    openWorldHint=False,
)


@mcp.tool(
    name="krusch_fs_search",
    description=(
        "Hybrid OS & Page-Anchored RAG search across local and fleet computers (`host_node`), KruschNexus pages, "
        "and page_memories. Returns ranked hits grounded to an exact (host_node, file_path, page_number, citation, bbox) "
        "along with all memories pinned to that specific page."
    ),
    annotations=READ_ONLY_ANNOTATIONS,
)
def krusch_fs_search(
    query: str,
    workspace: Optional[str] = None,
    path_prefix: Optional[str] = None,
    category: Optional[str] = None,
    host_node: Optional[str] = None,
    node: Optional[str] = None,
    include_memories: bool = True,
    limit: int = 5,
    top_k: Optional[int] = None,
) -> str:
    """Search OS files and page-bound memories across the fleet with Dual-Clock temporal decay."""
    try:
        hits = get_client().search(
            query=query,
            workspace=workspace,
            path_prefix=path_prefix,
            category=category,
            host_node=host_node or node,
            include_memories=include_memories,
            limit=top_k if top_k is not None else limit,
        )
        return json.dumps(
            {
                "status": "success",
                "count": len(hits),
                "hits": [h.model_dump() for h in hits],
            },
            indent=2,
        )
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})


@mcp.tool(
    name="krusch_fs_page_tree",
    description=(
        "Extract a PageIndex-style Table of Contents tree for an OS file on any fleet computer, listing every "
        "1-based page, section header, page_hash, and the count and list of memories tied to each page."
    ),
    annotations=READ_ONLY_ANNOTATIONS,
)
def krusch_fs_page_tree(
    file_path: Optional[str] = None,
    host_node: Optional[str] = None,
    path: Optional[str] = None,
    node: Optional[str] = None,
) -> str:
    """Inspect the page hierarchy and page-bound memory map of a file."""
    try:
        target_path = file_path or path
        if not target_path:
            return json.dumps({"status": "error", "error": "file_path (or path) is required."})
        tree = get_client().get_page_tree(file_path=target_path, host_node=host_node or node)
        return json.dumps(
            {
                "status": "success",
                "page_tree": tree.model_dump(),
            },
            indent=2,
        )
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})


@mcp.tool(
    name="krusch_fs_read_page",
    description=(
        "Hydrate a single 1-based page (or page range) of an OS file on any fleet computer, "
        "returning the exact page text, bounding boxes, and all page_memories anchored to that page "
        "without loading the rest of the file into context."
    ),
    annotations=READ_ONLY_ANNOTATIONS,
)
def krusch_fs_read_page(
    file_path: Optional[str] = None,
    page_number: int = 1,
    end_page: Optional[int] = None,
    host_node: Optional[str] = None,
    path: Optional[str] = None,
    node: Optional[str] = None,
) -> str:
    """Read a specific page and its attached memories."""
    try:
        target_path = file_path or path
        if not target_path:
            return json.dumps({"status": "error", "error": "file_path (or path) is required."})
        res = get_client().read_page(
            file_path=target_path,
            page_number=page_number,
            end_page=end_page,
            host_node=host_node or node,
        )
        if isinstance(res, list):
            payload = {"status": "success", "pages": [p.model_dump() for p in res]}
        else:
            payload = {"status": "success", "page": res.model_dump()}
        return json.dumps(payload, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})


@mcp.tool(
    name="krusch_fs_remember_on_page",
    description=(
        "Write-through Page Memory Anchor: Pin a semantic fact, extracted slot, decision, or config rule "
        "directly to a specific (host_node, file_path, page_number). Verifies quoted_sentence appears verbatim on "
        "that page (INV-12) and locks anchor_page_hash for per-page drift tracking."
    ),
    annotations=WRITE_IDEMPOTENT_ANNOTATIONS,
)
def krusch_fs_remember_on_page(
    file_path: Optional[str] = None,
    page_number: int = 1,
    memory_content: Optional[str] = None,
    quoted_sentence: Optional[str] = None,
    category: str = "fact",
    memory_key: Optional[str] = None,
    host_node: Optional[str] = None,
    path: Optional[str] = None,
    note: Optional[str] = None,
    node: Optional[str] = None,
) -> str:
    """Anchor a verified memory directly to a specific page of a file."""
    try:
        target_path = file_path or path
        target_content = memory_content or note
        target_node = host_node or node
        if not target_path or not target_content:
            return json.dumps({"status": "error", "error": "file_path (or path) and memory_content (or note) are required."})
        target_quote = quoted_sentence
        if not target_quote:
            page_view = get_client().read_page(
                file_path=target_path,
                page_number=page_number,
                host_node=target_node,
            )
            p_text = getattr(page_view, "text", "") or ""
            non_empty = [ln.strip() for ln in p_text.splitlines() if ln.strip()]
            target_quote = non_empty[0] if non_empty else target_content
        item = get_client().remember_on_page(
            file_path=target_path,
            page_number=page_number,
            memory_content=target_content,
            quoted_sentence=target_quote,
            category=category,
            memory_key=memory_key,
            host_node=target_node,
        )
        return json.dumps(
            {
                "status": "success",
                "page_memory": item.model_dump(),
            },
            indent=2,
        )
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})


@mcp.tool(
    name="krusch_fs_locate",
    description=(
        "Fast Tier-A OS file & inode locator across the fleet: Find files by filename/path pattern, extension, "
        "workspace zone, host_node, minimum size in MB, recent modification window, or duplicate SHA-256 content hashes."
    ),
    annotations=READ_ONLY_ANNOTATIONS,
)
def krusch_fs_locate(
    pattern: Optional[str] = None,
    workspace: Optional[str] = None,
    extension: Optional[str] = None,
    min_size_mb: Optional[float] = None,
    min_size_bytes: Optional[int] = None,
    modified_within_hours: Optional[float] = None,
    find_duplicates: bool = False,
    host_node: Optional[str] = None,
    node: Optional[str] = None,
    category: Optional[str] = None,
    limit: int = 25,
) -> str:
    """Locate files across the OS fleet by metadata predicates or duplicate hash."""
    try:
        hits = get_client().locate(
            pattern=pattern,
            workspace=workspace,
            extension=extension,
            min_size_mb=min_size_mb,
            min_size_bytes=min_size_bytes,
            modified_within_hours=modified_within_hours,
            find_duplicates=find_duplicates,
            host_node=host_node or node,
            category=category,
            limit=limit,
        )
        return json.dumps(
            {
                "status": "success",
                "count": len(hits),
                "files": [h.model_dump() for h in hits],
            },
            indent=2,
        )
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})


@mcp.tool(
    name="krusch_fs_sync",
    description=(
        "Synchronize local paths or all computers across the homelab fleet (`action='sync_fleet' | 'scan' | 'status'`). "
        "Correlates O(1) inode moves, hands off .git repositories to krusch-git, redacts .env values before SSH transfer, "
        "re-indexes only pages whose page_hash changed, and flags drifted page_memories."
    ),
    annotations=WRITE_IDEMPOTENT_ANNOTATIONS,
)
def krusch_fs_sync(
    action: str = "status",
    path: Optional[str] = None,
    paths: Optional[List[str]] = None,
    workspace: Optional[str] = None,
    host_node: Optional[str] = None,
    node: Optional[str] = None,
    force: bool = False,
) -> str:
    """Run an incremental directory/file scan, fleet-wide sync, or inspect index status."""
    try:
        raw_node = (host_node or node or "").strip()
        target_node = None if raw_node.lower() in ("", "all") else raw_node
        act = (action or "status").strip().lower()
        scan_targets: List[str] = []
        if paths:
            if isinstance(paths, str):
                scan_targets = [paths]
            else:
                scan_targets = [p for p in paths if p]
        elif path:
            scan_targets = [path]

        if scan_targets and act == "status":
            act = "scan"
        if act == "status":
            return json.dumps({"status": "success", "index": get_client().status()}, indent=2)
        if act == "sync_fleet":
            nodes_list: Optional[List[str]] = None
            if target_node:
                nodes_list = [n.strip() for n in target_node.split(",") if n.strip() and n.strip().lower() != "all"]
            rep = get_client().sync_fleet(nodes=nodes_list, force=force)
            return json.dumps({"status": "success", "fleet_sync_report": rep.model_dump()}, indent=2)
        if act in ("scan", "add_root"):
            if not scan_targets:
                return json.dumps({"status": "error", "error": "path (or paths) is required when action='scan' or 'add_root'."})
            reports = []
            for p in scan_targets:
                rep = get_client().scan_path(
                    target_path=p,
                    workspace=workspace,
                    register_watch_root=True,
                    host_node=target_node,
                    force=force,
                )
                reports.append(rep.model_dump())
            return json.dumps(
                {"status": "success", "sync_report": reports[0] if len(reports) == 1 else reports},
                indent=2,
            )
        return json.dumps(
            {
                "status": "error",
                "error": f"Unknown action '{action}'. Use 'status', 'scan', 'add_root', or 'sync_fleet'.",
            }
        )
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})


def main(argv: Optional[List[str]] = None) -> int:
    """Console script entrypoint for krusch-fs-mcp."""
    _ = argv
    mcp.run(transport="stdio")
    return 0


if __name__ == "__main__":
    sys.exit(main())
