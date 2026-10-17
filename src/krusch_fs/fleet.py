"""
KruschFS Multi-Node Fleet Topology & Zero-Dependency SSH Streamer (fleet.py)
============================================================================
Indexes files across the local computer and optional remote SSH fleet nodes
from a central workstation without requiring any daemon or heavy dependencies
to be installed on remote/edge machines.

Configuration:
- Reads multi-node topology from `KRUSCH_FS_FLEET_CONFIG` or `~/.krusch-fs/fleet.json`.
- If no external fleet configuration file exists, defaults to indexing the local
  workstation (`KRUSCH_FS_NODE` or system hostname).
- See `fleet.example.json` for a sample multi-node SSH configuration.

Security & Performance Guarantees:
1. Secret values in `.env` / credential files are redacted ON THE REMOTE NODE
   before crossing the SSH pipe.
2. Vault-locked files (`~/.ssh/id_*`, `*.pem`, `*.key`, `shadow`) never have their
   contents read on the remote node.
3. Unchanged files (matching `known_hashes` by `file_path`) skip content transfer.
4. Offline/sleeping nodes time out cleanly in <2s (`status="offline_skipped"`).
"""

import os
import json
import socket
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any


def get_default_local_node_name() -> str:
    """Return the configured node identifier or the local system short hostname."""
    env_node = os.getenv("KRUSCH_FS_NODE", "").strip()
    if env_node:
        return env_node
    try:
        host = socket.gethostname().split(".")[0].strip()
        return host or "local"
    except Exception:
        return "local"


def _build_default_local_fleet() -> Dict[str, Dict[str, Any]]:
    """Construct a safe, portable single-node default for out-of-the-box local usage."""
    node_name = get_default_local_node_name()
    home = Path.home()
    return {
        node_name: {
            "local": True,
            "role": "Local Workstation",
            "ssh_targets": [],
            "default_roots": [
                "/etc/systemd/system",
                "/etc/fstab",
                "/etc/hosts",
                str(home / "Documents"),
                str(home / "Downloads"),
            ],
        }
    }


def load_fleet_nodes(config_path: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """
    Load multi-node fleet topology from `KRUSCH_FS_FLEET_CONFIG` or `~/.krusch-fs/fleet.json`.
    Falls back to a single local workstation entry when no external config file is present.
    """
    target_path = config_path or os.getenv(
        "KRUSCH_FS_FLEET_CONFIG",
        str(Path.home() / ".krusch-fs" / "fleet.json"),
    )
    if target_path and os.path.isfile(target_path):
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict) and data:
                return data
        except Exception:
            pass
    return _build_default_local_fleet()


# Loaded dynamically at import time; refreshed on demand via `load_fleet_nodes()`.
FLEET_NODES: Dict[str, Dict[str, Any]] = load_fleet_nodes()

# Self-contained Python 3 stdlib agent executed over SSH stdin (`python3 -`) on remote fleet nodes.
REMOTE_SCANNER_SCRIPT_TEMPLATE = r'''
import os, sys, json, hashlib, re

payload = __PAYLOAD_JSON__
roots = payload.get("roots", [])
known_hashes = payload.get("known_hashes", {})
max_depth = int(payload.get("max_depth", 3))
max_files = int(payload.get("max_files", 400))

IGNORED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "mcp_env",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".next", ".nuxt", ".cache", ".ingested", "overlay2", "Trash", ".Trash",
    ".local", ".mozilla", ".config", ".npm", ".cargo", ".rustup", ".ollama",
    ".docker", "snap", ".vscode", ".cursor", ".gemini"
}
VAULT_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "shadow", "gshadow", "master.key", "Cookies", "Login Data"}
VAULT_EXTS = {".pem", ".key", ".p12", ".pfx", ".kdbx", ".keystore"}
TEXT_EXTS = {
    ".md", ".txt", ".rst", ".service", ".timer", ".target", ".mount",
    ".conf", ".ini", ".toml", ".yaml", ".yml", ".json", ".sh", ".csv",
    ".py", ".js", ".sql"
}
ENV_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")

def classify_privacy(fpath, size_b):
    name = os.path.basename(fpath)
    low = name.lower()
    ext = os.path.splitext(low)[1]
    if name in VAULT_NAMES or ext in VAULT_EXTS:
        return "vault_locked"
    if "/.ssh/" in fpath and not low.endswith(("config", ".pub", "known_hosts")):
        return "vault_locked"
    if "/.gnupg/" in fpath:
        return "vault_locked"
    if low == ".env" or low.startswith(".env.") or low.endswith(".env") or "credentials" in low or "secret" in low:
        return "keys_only"
    if size_b > 256 * 1024 or (ext not in TEXT_EXTS and name not in ("fstab", "hosts", "hostname", "crontab")):
        return "metadata_only"
    return "standard"

def fast_hash(fpath, size_b, privacy, st_ino, st_mtime):
    if privacy == "vault_locked":
        return f"vault_locked:{st_ino}:{size_b}:{int(st_mtime)}"
    h = hashlib.sha256()
    try:
        if size_b <= 2 * 1024 * 1024:
            with open(fpath, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()
        h.update(f"sampled:{size_b}:".encode())
        with open(fpath, "rb") as f:
            h.update(f.read(65536))
            f.seek(size_b // 2)
            h.update(f.read(65536))
    except Exception:
        return f"stat:{st_ino}:{size_b}:{int(st_mtime)}"
    return h.hexdigest()

def redact_env(fpath):
    lines = []
    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            for idx, ln in enumerate(f.read().splitlines(), 1):
                m = ENV_RE.match(ln)
                if m:
                    lines.append(f"{m.group(1)}=[REDACTED]")
                elif ln.strip().startswith("#") or not ln.strip():
                    lines.append(ln)
                else:
                    lines.append(f"# [REDACTED_LINE_{idx}]")
    except Exception:
        pass
    return "\n".join(lines)

emitted = 0
for r in roots:
    if emitted >= max_files:
        break
    if not os.path.exists(r):
        continue
    if os.path.isfile(r):
        try:
            st = os.stat(r)
            priv = classify_privacy(r, st.st_size)
            fhash = fast_hash(r, st.st_size, priv, st.st_ino, st.st_mtime)
            unchanged = (known_hashes.get(r) == fhash)
            text_content = None
            if not unchanged:
                if priv == "keys_only":
                    text_content = redact_env(r)
                elif priv == "standard":
                    with open(r, "r", encoding="utf-8", errors="replace") as f:
                        text_content = f.read(256 * 1024)
            print(json.dumps({
                "file_path": r,
                "device_id": str(st.st_dev),
                "inode": int(st.st_ino),
                "size_bytes": int(st.st_size),
                "mtime": float(st.st_mtime),
                "atime": float(st.st_atime),
                "privacy_level": priv,
                "file_hash": fhash,
                "unchanged": unchanged,
                "handoff_repo": None,
                "text_content": text_content,
            }))
            emitted += 1
        except Exception:
            pass
        continue

    base_depth = r.rstrip("/").count("/")
    for cur_dir, dirnames, filenames in os.walk(r, topdown=True):
        if emitted >= max_files:
            break
        cur_depth = cur_dir.rstrip("/").count("/") - base_depth
        if cur_depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [
                d for d in sorted(dirnames)
                if d not in IGNORED_DIRS and not d.startswith(".Trash")
            ]

        if os.path.exists(os.path.join(cur_dir, ".git")):
            repo_name = os.path.basename(cur_dir)
            for doc in ("README.md", "AGENTS.md"):
                cand = os.path.join(cur_dir, doc)
                if os.path.isfile(cand):
                    try:
                        st = os.stat(cand)
                        fhash = fast_hash(cand, st.st_size, "standard", st.st_ino, st.st_mtime)
                        unchanged = (known_hashes.get(cand) == fhash)
                        t_content = None
                        if not unchanged:
                            with open(cand, "r", encoding="utf-8", errors="replace") as f:
                                t_content = f.read(256 * 1024)
                        print(json.dumps({
                            "file_path": cand,
                            "device_id": str(st.st_dev),
                            "inode": int(st.st_ino),
                            "size_bytes": int(st.st_size),
                            "mtime": float(st.st_mtime),
                            "atime": float(st.st_atime),
                            "privacy_level": "standard",
                            "file_hash": fhash,
                            "unchanged": unchanged,
                            "handoff_repo": repo_name,
                            "text_content": t_content,
                        }))
                        emitted += 1
                    except Exception:
                        pass
            dirnames[:] = []
            continue

        for fname in sorted(filenames):
            if emitted >= max_files:
                break
            fpath = os.path.join(cur_dir, fname)
            if os.path.islink(fpath):
                continue
            try:
                st = os.stat(fpath)
                priv = classify_privacy(fpath, st.st_size)
                fhash = fast_hash(fpath, st.st_size, priv, st.st_ino, st.st_mtime)
                unchanged = (known_hashes.get(fpath) == fhash)
                t_content = None
                if not unchanged:
                    if priv == "keys_only":
                        t_content = redact_env(fpath)
                    elif priv == "standard":
                        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                            t_content = f.read(256 * 1024)
                print(json.dumps({
                    "file_path": fpath,
                    "device_id": str(st.st_dev),
                    "inode": int(st.st_ino),
                    "size_bytes": int(st.st_size),
                    "mtime": float(st.st_mtime),
                    "atime": float(st.st_atime),
                    "privacy_level": priv,
                    "file_hash": fhash,
                    "unchanged": unchanged,
                    "handoff_repo": None,
                    "text_content": t_content,
                }))
                emitted += 1
            except Exception:
                continue
'''


def probe_node_ssh(node_name: str, timeout_sec: int = 2, fleet_map: Optional[Dict[str, Dict[str, Any]]] = None) -> Optional[str]:
    """Return the first responsive SSH target for a fleet node, or None if unreachable."""
    nodes = fleet_map if fleet_map is not None else load_fleet_nodes()
    node_cfg = nodes.get(node_name)
    if not node_cfg or node_cfg.get("local"):
        return None
    for target in node_cfg.get("ssh_targets", []):
        try:
            res = subprocess.run(
                [
                    "ssh",
                    "-o", "BatchMode=yes",
                    "-o", f"ConnectTimeout={timeout_sec}",
                    "-o", "StrictHostKeyChecking=accept-new",
                    target,
                    "true",
                ],
                capture_output=True,
                timeout=timeout_sec + 2,
            )
            if res.returncode == 0:
                return target
        except Exception:
            continue
    return None


def stream_remote_node_entries(
    ssh_target: str,
    roots: List[str],
    known_hashes: Dict[str, str],
    max_depth: int = 3,
    max_files: int = 400,
    timeout_sec: int = 25,
) -> List[Dict[str, Any]]:
    """Execute the zero-dependency scanner over SSH stdin (`python3 -`) and return streamed file entries."""
    payload_str = json.dumps({
        "roots": roots,
        "known_hashes": known_hashes,
        "max_depth": max_depth,
        "max_files": max_files,
    })
    script_code = REMOTE_SCANNER_SCRIPT_TEMPLATE.replace("__PAYLOAD_JSON__", payload_str)
    res = subprocess.run(
        [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=3",
            ssh_target,
            "python3",
            "-",
        ],
        input=script_code,
        text=True,
        capture_output=True,
        timeout=timeout_sec,
    )
    entries: List[Dict[str, Any]] = []
    for line in (res.stdout or "").splitlines():
        line_s = line.strip()
        if not line_s.startswith("{"):
            continue
        try:
            entries.append(json.loads(line_s))
        except Exception:
            continue
    return entries
