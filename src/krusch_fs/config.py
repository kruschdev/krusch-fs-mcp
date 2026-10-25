"""
KruschFS Centralized Configuration & Node Validation (config.py)
================================================================
Provides centralized environment access and node-name validation across CLI and Client.
"""

import argparse
import os
import re
from typing import Any, Optional

_NODE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_SHELL_META_RE = re.compile(r"[;&|`$\r\n\x00]")


def validate_nodes(val: str) -> str:
    """Validate comma-separated fleet node names against empty or shell-metacharacter inputs."""
    if not isinstance(val, str) or not val.strip():
        raise argparse.ArgumentTypeError("Node name cannot be empty.")
    if _SHELL_META_RE.search(val):
        raise argparse.ArgumentTypeError(f"Invalid characters in node specification: {val!r}")
    parts = [p.strip() for p in val.split(",")]
    if any(not p for p in parts):
        raise argparse.ArgumentTypeError(f"Empty node segment in: {val!r}")
    for part in parts:
        if part.startswith("-") or not _NODE_NAME_RE.match(part):
            raise argparse.ArgumentTypeError(f"Invalid node name: {part!r}")
    return ",".join(parts)


def get_host_node(mem: Optional[Any] = None, explicit: Optional[str] = None) -> str:
    """
    Resolve and validate the host node identifier from explicit parameter,
    PageMemory attribute, KRUSCH_FS_NODE / HOST_NODE environment variables, or 'krusch'.
    """
    if explicit is not None:
        candidate = explicit
    elif mem is not None and getattr(mem, "host_node", None) is not None:
        candidate = getattr(mem, "host_node")
    elif os.getenv("KRUSCH_FS_NODE") is not None:
        candidate = os.getenv("KRUSCH_FS_NODE", "")
    elif os.getenv("HOST_NODE") is not None:
        candidate = os.getenv("HOST_NODE", "")
    else:
        candidate = "krusch"
    return validate_nodes(candidate)
