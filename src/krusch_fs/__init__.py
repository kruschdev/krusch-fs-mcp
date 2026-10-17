"""
KruschFS (`krusch-fs`)
======================
Standalone, opt-in OS Filesystem & KruschNexus Page-Anchored Memory MCP Server
across all computers on the homelab fleet.
"""

__version__ = "0.1.0"

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

__all__ = [
    "__version__",
    "FLEET_NODES",
    "KruschFSClient",
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
