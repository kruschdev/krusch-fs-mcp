"""
KruschFS (`krusch-fs`)
======================
Standalone, opt-in OS Filesystem & KruschNexus Page-Anchored Memory MCP Server
across all computers on the homelab fleet.
"""

__version__ = "0.3.1"

from .models import (
    WorkspaceZone,
    PrivacyLevel,
    MemoryCategory,
    KruschFSConfig,
    PageMemoryItem,
    PageView,
    PageTreeNode,
    FilePageTree,
    PageSearchHit,
    FileLocationHit,
    SyncReport,
    FleetNodeSyncResult,
    FleetSyncReport,
)
from .fleet import FLEET_NODES
from .client import KruschFSClient
from .mcp import get_mcp

__all__ = [
    "__version__",
    "FLEET_NODES",
    "KruschFSClient",
    "get_mcp",
    "KruschFSConfig",
    "WorkspaceZone",
    "PrivacyLevel",
    "MemoryCategory",
    "PageMemoryItem",
    "PageView",
    "PageTreeNode",
    "FilePageTree",
    "PageSearchHit",
    "FileLocationHit",
    "SyncReport",
    "FleetNodeSyncResult",
    "FleetSyncReport",
]
