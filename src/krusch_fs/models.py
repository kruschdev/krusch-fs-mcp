"""
KruschFS Frozen Data Contracts & Configuration (models.py)
==========================================================
Pydantic v2 models for the standalone opt-in OS Filesystem & KruschNexus
Page-Anchored Memory MCP server across all homelab fleet nodes.
"""

import os
import socket
from pathlib import Path
from enum import Enum
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


def _default_host_node() -> str:
    env_val = os.getenv("KRUSCH_FS_NODE", "").strip()
    if env_val:
        return env_val
    try:
        return socket.gethostname().split(".")[0].strip() or "local"
    except Exception:
        return "local"


class WorkspaceZone(str, Enum):
    """3-Zone Default Workspace Isolation Model (INV-4)."""
    USER_DOCS = "user_docs"
    SYSTEM_CONFIG = "system_config"
    REPO_BOUNDARIES = "repo_boundaries"


class PrivacyLevel(str, Enum):
    """Zero-Trust OS Privacy & Secret Redaction Levels."""
    STANDARD = "standard"            # Full KruschNexus page-faithful extraction
    KEYS_ONLY = "keys_only"          # .env / credential files: variable keys indexed, values redacted
    METADATA_ONLY = "metadata_only"  # Large binaries / archives: stat + sampled hash + manifest only
    VAULT_LOCKED = "vault_locked"    # Private keys (.ssh/id_*, .pem, .kdbx, shadow): path only, zero content read


class MemoryCategory(str, Enum):
    """Taxonomy of memories tied directly to a specific file page."""
    FACT = "fact"
    SLOT = "slot"
    DECISION = "decision"
    CONFIG_RULE = "config_rule"
    ANNOTATION = "annotation"


class KruschFSConfig(BaseModel):
    """Runtime configuration for KruschFS."""
    db_url: str = Field(
        default_factory=lambda: os.getenv(
            "KRUSCH_FS_DB_URL",
            f"sqlite:///{Path.home() / '.krusch-fs' / 'fs_memory.db'}"
        )
    )
    host_node: str = Field(default_factory=_default_host_node)
    embed_backend: str = Field(default_factory=lambda: os.getenv("KRUSCH_FS_EMBED_BACKEND", "deterministic"))
    ollama_url: str = Field(default_factory=lambda: os.getenv("OLLAMA_URL", "http://127.0.0.1:11434"))
    embed_model: str = Field(default_factory=lambda: os.getenv("KRUSCH_FS_EMBED_MODEL", "bge-large"))
    embed_dim: int = 1024
    max_parse_bytes: int = 50 * 1024 * 1024  # 50MB threshold before switching to metadata_only


class PageMemoryItem(BaseModel):
    """A semantic, episodic, or slot memory directly anchored to a specific page of a file."""
    id: int
    host_node: str = "local"
    file_id: int
    file_path: str
    workspace: str
    page_number: int
    printed_page: Optional[str] = None
    category: str
    memory_key: Optional[str] = None
    memory_content: str
    quoted_sentence: str
    citation: str
    locator: Optional[str] = None
    bbox: Optional[List[float]] = None
    char_start: Optional[int] = None
    char_end: Optional[int] = None
    anchor_page_hash: str
    current_page_hash: Optional[str] = None
    is_drifted: bool = False
    created_at: Optional[str] = None


class PageView(BaseModel):
    """Hydrated single-page view combining KruschNexus PageData with page-bound memories."""
    host_node: str = "local"
    file_id: int
    file_path: str
    file_name: str
    workspace: str
    page_number: int
    total_pages: int
    printed_page: Optional[str] = None
    page_hash: str
    section_header: Optional[str] = None
    locator: Optional[str] = None
    citation: str
    text: str
    ocr_applied: bool = False
    ocr_confidence: Optional[float] = None
    blocks: List[Dict[str, Any]] = Field(default_factory=list)
    memories: List[PageMemoryItem] = Field(default_factory=list)
    privacy_level: str = "standard"
    handoff_repo: Optional[str] = None


class PageTreeNode(BaseModel):
    """Single node in a file's PageIndex Table of Contents tree."""
    page_number: int
    printed_page: Optional[str] = None
    section_header: str
    locator: Optional[str] = None
    page_hash: str
    char_count: int
    memory_count: int = 0
    drifted_memory_count: int = 0
    preview: str = ""
    memories: List[PageMemoryItem] = Field(default_factory=list)


class FilePageTree(BaseModel):
    """PageIndex-style structural outline of an OS file and its page-bound memories."""
    host_node: str = "local"
    file_id: int
    file_path: str
    file_name: str
    workspace: str
    mime_type: str
    total_pages: int
    total_memories: int
    privacy_level: str
    handoff_repo: Optional[str] = None
    pages: List[PageTreeNode] = Field(default_factory=list)


class PageSearchHit(BaseModel):
    """Hybrid RRF search result grounded to an exact OS file and KruschNexus page."""
    host_node: str = "local"
    file_id: int
    file_path: str
    file_name: str
    workspace: str
    page_number: int
    printed_page: Optional[str] = None
    citation: str
    header: Optional[str] = None
    locator: Optional[str] = None
    score: float
    match_source: str  # "page_memory", "page_chunk", "hybrid_page_and_memory"
    match_reasons: List[str] = Field(default_factory=list)
    snippet: str
    bbox: Optional[List[float]] = None
    char_start: Optional[int] = None
    char_end: Optional[int] = None
    page_hash: str
    page_memories: List[PageMemoryItem] = Field(default_factory=list)
    handoff_repo: Optional[str] = None


class FileLocationHit(BaseModel):
    """Tier-A fast metadata/inode locator result."""
    host_node: str = "local"
    file_id: int
    file_path: str
    file_name: str
    workspace: str
    extension: str
    mime_type: str
    size_bytes: int
    inode: int
    mtime: float
    file_hash: str
    total_pages: int
    memory_count: int = 0
    privacy_level: str = "standard"
    handoff_repo: Optional[str] = None


class SyncReport(BaseModel):
    """Summary of an OS directory scan / delta index run."""
    host_node: str = "local"
    scanned_paths: List[str]
    files_discovered: int = 0
    files_indexed: int = 0
    files_moved_in_place: int = 0
    files_unchanged: int = 0
    pages_indexed: int = 0
    pages_unchanged_skipped: int = 0
    memories_auto_extracted: int = 0
    memories_flagged_drifted: int = 0
    repo_boundaries_handed_off: int = 0
    vault_locked_skipped: int = 0
    duration_ms: float = 0.0


class FleetNodeSyncResult(BaseModel):
    """Sync result for a single fleet computer."""
    host_node: str
    role: str
    status: str  # "indexed", "offline_skipped", "error"
    ssh_target: Optional[str] = None
    report: Optional[SyncReport] = None
    error: Optional[str] = None


class FleetSyncReport(BaseModel):
    """Summary of a fleet-wide multi-node synchronization run."""
    total_nodes_configured: int
    nodes_online_indexed: int
    nodes_offline_skipped: int
    total_files_indexed: int
    total_pages_indexed: int
    total_memories_extracted: int
    duration_ms: float
    nodes: List[FleetNodeSyncResult] = Field(default_factory=list)
