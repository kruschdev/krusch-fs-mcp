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

import inspect
import os
import json
import logging
import socket
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


def get_default_local_node_name() -> str:
    """Return the configured node identifier or the local system short hostname."""
    env_node = os.getenv("KRUSCH_FS_NODE", "").strip()
    if env_node:
        return env_node
    try:
        host = socket.gethostname().split(".")[0].strip()
        return host or "local"
    except Exception as exc:
        logger.debug("Falling back to default node name 'local': %s", exc)
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


def get_fleet_config_path() -> str:
    """Resolve the fleet configuration file path from environment or default home path."""
    return os.getenv(
        "KRUSCH_FS_FLEET_CONFIG",
        str(Path.home() / ".krusch-fs" / "fleet.json"),
    )


def validate_fleet_topology(data: Any) -> bool:
    """Validate that loaded fleet JSON conforms to expected node topology structure."""
    if not isinstance(data, dict) or not data:
        return False
    for node_name, spec in data.items():
        if not isinstance(node_name, str) or not node_name.strip():
            return False
        if not isinstance(spec, dict):
            return False
        if "ssh_targets" in spec and not isinstance(spec["ssh_targets"], list):
            return False
        if "default_roots" in spec and not isinstance(spec["default_roots"], list):
            return False
    return True


def load_fleet_nodes(config_path: Optional[str] = None) -> Dict[str, Dict[str, Any]]:
    """
    Load multi-node fleet topology from `KRUSCH_FS_FLEET_CONFIG` or `~/.krusch-fs/fleet.json`.
    Falls back to a single local workstation entry when no external config file is present.
    """
    target_path = config_path or get_fleet_config_path()
    if target_path and os.path.isfile(target_path):
        try:
            with open(target_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if validate_fleet_topology(data):
                return data
            logger.warning("Invalid fleet topology schema in %s; falling back to local default", target_path)
        except Exception as exc:
            logger.warning("Failed to load fleet topology from %s: %s", target_path, exc)
    return _build_default_local_fleet()


# Loaded dynamically at import time; refreshed on demand via `load_fleet_nodes()`.
FLEET_NODES: Dict[str, Dict[str, Any]] = load_fleet_nodes()

# Self-contained Python 3 stdlib agent executed over SSH stdin (`python3 -`) on remote fleet nodes.
_REMOTE_SCANNER_SCRIPT_BODY = r'''
import os, sys, json, hashlib, re
from pathlib import Path

payload = json.loads(__PAYLOAD_JSON_STR__)
roots = payload.get("roots", [])
known_hashes = payload.get("known_hashes", {})
max_depth = int(payload.get("max_depth", 3))
max_files = int(payload.get("max_files", 400))

IGNORED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "mcp_env",
    "site-packages", "dist-packages",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".next", ".nuxt", ".cache", ".ingested", "overlay2", "Trash", ".Trash",
    ".local", ".mozilla", ".config", ".npm", ".cargo", ".rustup", ".ollama",
    ".docker", "snap", ".vscode", ".cursor", ".gemini"
}
IGNORED_PATH_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/var/lib/docker")
VAULT_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "shadow", "gshadow", "master.key", "Cookies", "Login Data"}
VAULT_EXTS = {".pem", ".key", ".p12", ".pfx", ".kdbx", ".keystore"}
TEXT_EXTS = {
    ".md", ".txt", ".rst", ".service", ".timer", ".target", ".mount",
    ".conf", ".ini", ".toml", ".yaml", ".yml", ".json", ".sh", ".csv",
    ".py", ".js", ".sql"
}
ENV_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
PRIV_RANK = {"standard": 0, "metadata_only": 1, "keys_only": 2, "vault_locked": 3}

__SCANNER_HELPERS__

def most_restrictive_privacy(p1, p2):
    return p1 if PRIV_RANK.get(p1, 0) >= PRIV_RANK.get(p2, 0) else p2

def _has_unescaped_delim(text, delim):
    i = 0
    n = len(text)
    bs = chr(92)
    while i < n:
        if text[i] == bs:
            i += 2
            continue
        if text.startswith(delim, i):
            return True
        i += 1
    return False

def _detect_unclosed_quote_delim(raw_val):
    val = raw_val.lstrip()
    for delim in ('"' * 3, "'" * 3, '"', "'"):
        if val.startswith(delim):
            rest = val[len(delim):]
            if not _has_unescaped_delim(rest, delim):
                return delim
            return None
    return None

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
    in_multiline_quote = None
    try:
        with open(fpath, "r", encoding="utf-8", errors="replace") as f:
            for idx, ln in enumerate(f.read().splitlines(), 1):
                if in_multiline_quote is not None:
                    lines.append("# [REDACTED_MULTILINE]")
                    if _has_unescaped_delim(ln, in_multiline_quote):
                        in_multiline_quote = None
                    continue
                m = ENV_RE.match(ln)
                if m:
                    in_multiline_quote = _detect_unclosed_quote_delim(m.group(2))
                    lines.append(f"{m.group(1)}=[REDACTED]")
                elif ln.strip().startswith("#") or not ln.strip():
                    lines.append(ln)
                else:
                    lines.append(f"# [REDACTED_LINE_{idx}]")
    except Exception:
        pass
    return "\n".join(lines)

emitted = 0
for raw_r in roots:
    if emitted >= max_files:
        break
    r = os.path.expanduser(raw_r)
    if os.path.islink(r) or not os.path.exists(r):
        continue
    abs_r = os.path.abspath(r)
    real_r = os.path.realpath(abs_r)
    if os.path.islink(abs_r) or should_ignore_path(abs_r) or should_ignore_path(real_r):
        continue
    if os.path.isfile(abs_r):
        try:
            st = os.stat(abs_r)
            priv = most_restrictive_privacy(
                classify_privacy(abs_r, st.st_size),
                classify_privacy(real_r, st.st_size),
            )
            fhash = fast_hash(abs_r, st.st_size, priv, st.st_ino, st.st_mtime)
            unchanged = (known_hashes.get(abs_r) == fhash)
            text_content = None
            if not unchanged:
                if priv == "keys_only":
                    text_content = redact_env(abs_r)
                elif priv == "standard":
                    with open(abs_r, "r", encoding="utf-8", errors="replace") as f:
                        text_content = f.read(256 * 1024)
            print(json.dumps({
                "file_path": abs_r,
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

    base_depth = abs_r.rstrip("/").count("/")
    for cur_dir, dirnames, filenames in os.walk(abs_r, topdown=True):
        if emitted >= max_files:
            break
        cur_depth = cur_dir.rstrip("/").count("/") - base_depth
        if cur_depth >= max_depth:
            dirnames[:] = []
        else:
            dirnames[:] = [
                d for d in sorted(dirnames)
                if d not in IGNORED_DIRS
                and not d.startswith(".Trash")
                and not os.path.islink(os.path.join(cur_dir, d))
                and not should_ignore_path(os.path.join(cur_dir, d))
                and not should_ignore_path(os.path.realpath(os.path.join(cur_dir, d)))
            ]

        if os.path.exists(os.path.join(cur_dir, ".git")):
            repo_name = os.path.basename(cur_dir)
            for doc in ("README.md", "AGENTS.md"):
                cand = os.path.join(cur_dir, doc)
                if os.path.isfile(cand) and not os.path.islink(cand):
                    real_cand = os.path.realpath(cand)
                    if should_ignore_path(cand) or should_ignore_path(real_cand):
                        continue
                    try:
                        st = os.stat(cand)
                        priv = most_restrictive_privacy(
                            classify_privacy(cand, st.st_size),
                            classify_privacy(real_cand, st.st_size),
                        )
                        fhash = fast_hash(cand, st.st_size, priv, st.st_ino, st.st_mtime)
                        unchanged = (known_hashes.get(cand) == fhash)
                        t_content = None
                        if not unchanged:
                            if priv == "keys_only":
                                t_content = redact_env(cand)
                            elif priv == "standard":
                                with open(cand, "r", encoding="utf-8", errors="replace") as f:
                                    t_content = f.read(256 * 1024)
                        print(json.dumps({
                            "file_path": cand,
                            "device_id": str(st.st_dev),
                            "inode": int(st.st_ino),
                            "size_bytes": int(st.st_size),
                            "mtime": float(st.st_mtime),
                            "atime": float(st.st_atime),
                            "privacy_level": priv,
                            "file_hash": fhash,
                            "unchanged": unchanged,
                            "handoff_repo": repo_name,
                            "text_content": t_content,
                        }))
                        emitted += 1
                    except Exception:
                        pass
            env_dirs = [cur_dir]
            proj_sub = os.path.join(cur_dir, "projects")
            if os.path.isdir(proj_sub) and not os.path.islink(proj_sub):
                try:
                    for sub in sorted(os.listdir(proj_sub)):
                        sp = os.path.join(proj_sub, sub)
                        if os.path.isdir(sp) and not os.path.islink(sp):
                            env_dirs.append(sp)
                except Exception:
                    pass
            for ed in env_dirs:
                if emitted >= max_files:
                    break
                try:
                    for fn in sorted(os.listdir(ed)):
                        low = fn.lower()
                        if low == ".env" or low.startswith(".env.") or low.endswith(".env"):
                            ep = os.path.join(ed, fn)
                            if os.path.isfile(ep) and not os.path.islink(ep):
                                real_ep = os.path.realpath(ep)
                                if should_ignore_path(ep) or should_ignore_path(real_ep):
                                    continue
                                st = os.stat(ep)
                                priv = most_restrictive_privacy(
                                    classify_privacy(ep, st.st_size),
                                    classify_privacy(real_ep, st.st_size),
                                )
                                fhash = fast_hash(ep, st.st_size, priv, st.st_ino, st.st_mtime)
                                unchanged = (known_hashes.get(ep) == fhash)
                                t_content = None
                                if not unchanged and priv == "keys_only":
                                    t_content = redact_env(ep)
                                print(json.dumps({
                                    "file_path": ep,
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
                    pass
            dirnames[:] = []
            continue

        for fname in sorted(filenames):
            if emitted >= max_files:
                break
            fpath = os.path.join(cur_dir, fname)
            if os.path.islink(fpath):
                continue
            abs_fpath = os.path.abspath(fpath)
            real_fpath = os.path.realpath(abs_fpath)
            if should_ignore_path(abs_fpath) or should_ignore_path(real_fpath):
                continue
            try:
                st = os.stat(abs_fpath)
                priv = most_restrictive_privacy(
                    classify_privacy(abs_fpath, st.st_size),
                    classify_privacy(real_fpath, st.st_size),
                )
                fhash = fast_hash(abs_fpath, st.st_size, priv, st.st_ino, st.st_mtime)
                unchanged = (known_hashes.get(abs_fpath) == fhash)
                t_content = None
                if not unchanged:
                    if priv == "keys_only":
                        t_content = redact_env(abs_fpath)
                    elif priv == "standard":
                        with open(abs_fpath, "r", encoding="utf-8", errors="replace") as f:
                            t_content = f.read(256 * 1024)
                print(json.dumps({
                    "file_path": abs_fpath,
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

IGNORED_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "mcp_env",
    "site-packages", "dist-packages",
    "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
    ".next", ".nuxt", ".cache", ".ingested", "overlay2", "Trash", ".Trash",
    ".local", ".mozilla", ".config", ".npm", ".cargo", ".rustup", ".ollama",
    ".docker", "snap", ".vscode", ".cursor", ".gemini"
}
IGNORED_PATH_PREFIXES = ("/proc", "/sys", "/dev", "/run", "/var/lib/docker")
VAULT_NAMES = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "shadow", "gshadow", "master.key", "Cookies", "Login Data"}
VAULT_EXTS = {".pem", ".key", ".p12", ".pfx", ".kdbx", ".keystore"}
TEXT_EXTS = {
    ".md", ".txt", ".rst", ".service", ".timer", ".target", ".mount",
    ".conf", ".ini", ".toml", ".yaml", ".yml", ".json", ".sh", ".csv",
    ".py", ".js", ".sql"
}

_SCANNER_IGNORED_DIRS = IGNORED_DIRS
_SCANNER_IGNORED_PREFIXES = IGNORED_PATH_PREFIXES
_SCANNER_VAULT_NAMES = VAULT_NAMES
_SCANNER_VAULT_EXTS = VAULT_EXTS
_SCANNER_TEXT_EXTS = TEXT_EXTS


def should_ignore_path(path_str: str) -> bool:
    """Validate and check whether a filesystem path should be ignored by the fleet scanner."""
    if not isinstance(path_str, str) or not path_str.strip():
        raise ValueError("path_str must be a non-empty string")
    norm = os.path.abspath(path_str)
    bname = os.path.basename(norm)
    if (
        bname.startswith((".lock.", ".~lock.", "~$"))
        or bname.endswith((".swp", ".tmp", ".part", ".crdownload"))
        or bname in (".DS_Store", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "Cargo.lock", "poetry.lock", "uv.lock", "bun.lockb")
    ):
        return True
    for prefix in IGNORED_PATH_PREFIXES:
        if norm == prefix or norm.startswith(prefix + "/"):
            return True
    for part in Path(norm).parts:
        if part in IGNORED_DIRS or part.endswith(("_venv", "-venv", "_env", "-env")):
            return True
    if os.path.isdir(norm) and os.path.isfile(os.path.join(norm, "pyvenv.cfg")):
        return True
    return False


def classify_privacy(fpath: str, size_b: int) -> str:
    """Validate inputs and classify a file path into its 3-Zone Privacy Shield tier."""
    if not isinstance(fpath, str) or not fpath.strip():
        raise ValueError("fpath must be a string")
    if isinstance(size_b, bool) or not isinstance(size_b, (int, float)) or size_b < 0:
        raise ValueError("size_b must be numeric")
    size_b = int(size_b)
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


REMOTE_SCANNER_SCRIPT_TEMPLATE = _REMOTE_SCANNER_SCRIPT_BODY.replace(
    "__SCANNER_HELPERS__",
    f"{inspect.getsource(should_ignore_path)}\n{inspect.getsource(classify_privacy)}",
)


def probe_node_ssh(node_name: str, timeout_sec: int = 2, fleet_map: Optional[Dict[str, Dict[str, Any]]] = None) -> Optional[str]:
    """Return the first responsive SSH target for a fleet node, or None if unreachable."""
    nodes = fleet_map if fleet_map is not None else load_fleet_nodes()
    node_cfg = nodes.get(node_name)
    if not node_cfg or node_cfg.get("local"):
        return None
    for target in node_cfg.get("ssh_targets", []):
        if not target or not isinstance(target, str):
            continue
        clean_target = target.strip()
        if not clean_target or clean_target.startswith("-"):
            continue
        try:
            res = subprocess.run(
                [
                    "ssh",
                    "-o", "BatchMode=yes",
                    "-o", f"ConnectTimeout={timeout_sec}",
                    "-o", "StrictHostKeyChecking=accept-new",
                    "--",
                    clean_target,
                    "true",
                ],
                capture_output=True,
                timeout=timeout_sec + 2,
            )
            if res.returncode == 0:
                return clean_target
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
    if not ssh_target or not isinstance(ssh_target, str) or ssh_target.strip().startswith("-"):
        raise ValueError(f"Invalid ssh_target: {ssh_target!r}")
    clean_target = ssh_target.strip()
    payload_obj = {
        "roots": roots,
        "known_hashes": known_hashes,
        "max_depth": max_depth,
        "max_files": max_files,
    }
    payload_json_literal = json.dumps(json.dumps(payload_obj))
    script_code = REMOTE_SCANNER_SCRIPT_TEMPLATE.replace("__PAYLOAD_JSON_STR__", payload_json_literal)
    res = subprocess.run(
        [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=3",
            "--",
            clean_target,
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
