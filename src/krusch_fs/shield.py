"""
KruschFS Privacy Shield, .git Boundary Detector & Universal Page Framer (shield.py)
===================================================================================
Enforces:
1. OS noise and pseudo-filesystem exclusions (/proc, /sys, node_modules, .venv, overlay2).
2. Smart .git repository boundary handoff to krusch-git (prevents double-indexing code).
3. Zero-Trust secret value redaction for .env and credential files (KEYS_ONLY mode).
4. Vault lock for SSH keys, PEM certificates, and password databases (VAULT_LOCKED mode).
5. Universal 1-based Page Framing via KruschNexus so every OS file has addressable pages.
"""

import os
import re
import hashlib
from pathlib import Path
from typing import List, Tuple, Optional, Dict, Any

import sys

try:
    from krusch_nexus import (
        PageData,
        ContentBlock,
        StructuredLocator,
        ParserResult,
        parse_file,
        format_citation,
    )
except ImportError:
    _nexus_candidates = [
        os.getenv("KRUSCH_NEXUS_PATH"),
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), "krusch-nexus", "src"),
        "/home/agent/homelab/projects/krusch-nexus/src",
        os.path.expanduser("~/homelab/projects/krusch-nexus/src"),
    ]
    for _cand in _nexus_candidates:
        if _cand and os.path.isdir(_cand) and _cand not in sys.path:
            sys.path.insert(0, _cand)
            break
    try:
        from krusch_nexus import (
            PageData,
            ContentBlock,
            StructuredLocator,
            ParserResult,
            parse_file,
            format_citation,
        )
    except ImportError as _exc:
        raise RuntimeError(
            "krusch_nexus is required for client operations; install with "
            "'pip install krusch-nexus' or enable the 'krusch_nexus' extra."
        ) from _exc

from .models import WorkspaceZone, PrivacyLevel

# Directories that must never be traversed during OS scans
IGNORED_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "mcp_env",
    "site-packages",
    "dist-packages",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".next",
    ".nuxt",
    ".cache",
    ".ingested",
    "overlay2",
    "Trash",
    ".Trash",
}

IGNORED_PATH_PREFIXES = (
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/var/lib/docker",
)

VAULT_LOCKED_FILENAMES = {
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    "shadow",
    "gshadow",
    "master.key",
    "Cookies",
    "Login Data",
}

VAULT_LOCKED_EXTENSIONS = {
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".kdbx",
    ".keystore",
}

METADATA_ONLY_EXTENSIONS = {
    ".iso",
    ".img",
    ".qcow2",
    ".vmdk",
    ".mp4",
    ".mkv",
    ".mov",
    ".avi",
    ".mp3",
    ".wav",
    ".flac",
    ".zip",
    ".tar",
    ".gz",
    ".zst",
    ".7z",
    ".whl",
    ".so",
    ".dylib",
    ".dll",
    ".exe",
    ".bin",
    ".o",
    ".a",
    ".pyc",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".webp",
    ".heic",
    ".bmp",
    ".ico",
    ".tiff",
    ".tif",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".wasm",
    ".deb",
    ".rpm",
    ".dmg",
    ".apk",
    ".ttf",
    ".otf",
    ".woff",
    ".woff2",
}

ENV_KEY_LINE_RE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$")
CONFIG_STANZA_RE = re.compile(r"^\s*\[([^\]]+)\]\s*$")
MD_HEADING_RE = re.compile(r"^(#{1,3})\s+(.+?)\s*$")
SYSTEMD_DIRECTIVE_RE = re.compile(
    r"^\s*(ExecStart|ExecStartPre|WorkingDirectory|EnvironmentFile|ListenStream|Port)\s*=\s*(.+)$"
)
SYSTEMD_ENV_DIRECTIVE_RE = re.compile(r"^(\s*Environment\s*=\s*)(.+)$")

PRIVACY_RESTRICTIVENESS = {
    PrivacyLevel.STANDARD: 0,
    PrivacyLevel.METADATA_ONLY: 1,
    PrivacyLevel.KEYS_ONLY: 2,
    PrivacyLevel.VAULT_LOCKED: 3,
}


def most_restrictive_privacy_level(p1: PrivacyLevel, p2: PrivacyLevel) -> PrivacyLevel:
    """Return the more restrictive PrivacyLevel between two classifications."""
    return p1 if PRIVACY_RESTRICTIVENESS.get(p1, 0) >= PRIVACY_RESTRICTIVENESS.get(p2, 0) else p2


def _has_unescaped_delim(text: str, delim: str) -> bool:
    i = 0
    n = len(text)
    while i < n:
        if text[i] == "\\":
            i += 2
            continue
        if text.startswith(delim, i):
            return True
        i += 1
    return False


def _detect_unclosed_quote_delim(raw_val: str) -> Optional[str]:
    val = raw_val.lstrip()
    for delim in ('"""', "'''", '"', "'"):
        if val.startswith(delim):
            rest = val[len(delim):]
            if not _has_unescaped_delim(rest, delim):
                return delim
            return None
    return None


def _redact_systemd_env_line(line: str) -> str:
    m = SYSTEMD_ENV_DIRECTIVE_RE.match(line)
    if not m:
        return line
    prefix, rhs = m.group(1), m.group(2)
    redacted_rhs = re.sub(
        r'(["\'])([A-Za-z_][A-Za-z0-9_]*)=(?:(?!\1).)*\1',
        r"\1\2=[REDACTED]\1",
        rhs,
    )
    redacted_rhs = re.sub(
        r'(?<![A-Za-z0-9_"\'=])([A-Za-z_][A-Za-z0-9_]*)=([^\s"\']+)',
        lambda match: f"{match.group(1)}=[REDACTED]" if match.group(2) != "[REDACTED]" else match.group(0),
        redacted_rhs,
    )
    return f"{prefix}{redacted_rhs}"


_SECRET_LEAK_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PRIVATE |[A-Z0-9]+ )?PRIVATE KEY-----"),
        "PEM private key",
    ),
    (
        re.compile(r"(?<![A-Za-z0-9_-])sk-ant-[A-Za-z0-9_-]{16,}"),
        "Anthropic API secret key (sk-ant-...)",
    ),
    (
        re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9_-]{20,}"),
        "API secret key (sk-...)",
    ),
    (
        re.compile(r"(?<![A-Za-z0-9_-])xai-[A-Za-z0-9_-]{20,}"),
        "xAI API secret key (xai-...)",
    ),
    (
        re.compile(r"(?<![A-Za-z0-9_-])(?:sk|rk)_live_[A-Za-z0-9_-]{16,}"),
        "Stripe live secret key (sk_live_/rk_live_)",
    ),
    (
        re.compile(
            r"(?<![A-Za-z0-9_-])(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{22,})"
        ),
        "GitHub Personal Access Token",
    ),
    (
        re.compile(r"(?<![A-Za-z0-9_-])xox[baprs]-[A-Za-z0-9-]{16,}"),
        "Slack API token (xox...)",
    ),
    (
        re.compile(r"(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])"),
        "Google API key (AIza...)",
    ),
    (
        re.compile(r"(?<![A-Za-z0-9_-])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Za-z0-9])"),
        "AWS Access Key ID (AKIA...)",
    ),
]
_INLINE_URL_SECRET_RE = re.compile(r"://([^/\s:@]+):([^/\s:@]{6,})@")


def scan_for_secret_leak(text: str) -> Optional[str]:
    """
    Inspect text for high-confidence raw secret literals prior to DB persistence (`INV-FS-BUDGET-04`).
    Returns a descriptive reason string if a raw credential is found, or `None` if clean.
    """
    if not text or not isinstance(text, str):
        return None

    for pattern, reason in _SECRET_LEAK_PATTERNS:
        for match in pattern.finditer(text):
            token = match.group(0)
            if "REDACTED" in token.upper():
                continue
            return reason

    for url_match in _INLINE_URL_SECRET_RE.finditer(text):
        pwd = url_match.group(2)
        if (
            "REDACTED" in pwd.upper()
            or "***" in pwd
            or "<" in pwd
            or (pwd.startswith("${") and pwd.endswith("}"))
        ):
            continue
        return "Inline URL password"

    return None


def compute_fast_file_hash(file_path: str, size_bytes: Optional[int] = None) -> str:
    """
    Compute full SHA-256 for files <= 20MB, or a deterministic sampled SHA-256
    (head 64KB + middle 64KB + tail 64KB + size) for large binary files.
    """
    if size_bytes is None:
        size_bytes = os.path.getsize(file_path)
    hasher = hashlib.sha256()
    if size_bytes <= 20 * 1024 * 1024:
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
        return hasher.hexdigest()

    hasher.update(f"sampled:{size_bytes}:".encode("utf-8"))
    with open(file_path, "rb") as f:
        hasher.update(f.read(65536))
        f.seek(size_bytes // 2)
        hasher.update(f.read(65536))
        f.seek(max(0, size_bytes - 65536))
        hasher.update(f.read(65536))
    return hasher.hexdigest()


def compute_page_hash(text: str) -> str:
    """Compute canonical SHA-256 hash of normalized page text for per-page drift tracking."""
    normalized = "\n".join(line.rstrip() for line in (text or "").strip().splitlines())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def should_ignore_path(path_str: str) -> bool:
    """Return True if a path belongs to OS pseudo-filesystems, lockfiles, or noisy build/cache trees."""
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
    parts = Path(norm).parts
    for part in parts:
        if part in IGNORED_DIR_NAMES or part.endswith(("_venv", "-venv", "_env", "-env")):
            return True
    if os.path.isdir(norm) and os.path.isfile(os.path.join(norm, "pyvenv.cfg")):
        return True
    return False


def is_git_repo_root(dir_path: str) -> bool:
    """Return True if dir_path contains a .git directory or file (worktree)."""
    return os.path.exists(os.path.join(dir_path, ".git"))


def classify_workspace_zone(file_path: str, explicit_workspace: Optional[str] = None) -> str:
    """Map an OS path to one of the 3 canonical isolated workspaces (or explicit override)."""
    if explicit_workspace:
        return explicit_workspace
    norm = os.path.abspath(file_path)
    if norm.startswith("/etc/") or "/.config/" in norm or norm.endswith(".service") or ".env" in os.path.basename(norm):
        return WorkspaceZone.SYSTEM_CONFIG.value
    return WorkspaceZone.USER_DOCS.value


def classify_privacy_level(file_path: str, size_bytes: int, max_parse_bytes: int = 50 * 1024 * 1024) -> PrivacyLevel:
    """Determine Zero-Trust privacy handling level for a file on the OS."""
    name = os.path.basename(file_path)
    lower_name = name.lower()
    ext = os.path.splitext(lower_name)[1]

    if name in VAULT_LOCKED_FILENAMES or ext in VAULT_LOCKED_EXTENSIONS:
        return PrivacyLevel.VAULT_LOCKED
    if "/.ssh/" in file_path and not lower_name.endswith(("config", ".pub", "known_hosts")):
        return PrivacyLevel.VAULT_LOCKED
    if "/.gnupg/" in file_path:
        return PrivacyLevel.VAULT_LOCKED

    if (
        lower_name == ".env"
        or lower_name.startswith(".env.")
        or lower_name.endswith(".env")
        or "credentials" in lower_name
        or "secret" in lower_name
    ):
        # Note: .env.example files are safe, still redact values to be 100% air-gap safe
        return PrivacyLevel.KEYS_ONLY

    if size_bytes > max_parse_bytes or ext in METADATA_ONLY_EXTENSIONS:
        return PrivacyLevel.METADATA_ONLY

    return PrivacyLevel.STANDARD


def redact_env_content_to_pages(file_path: str, filename: str, file_hash: str) -> Tuple[ParserResult, List[Dict[str, Any]]]:
    """
    Parse a .env or credential file in KEYS_ONLY mode:
    Every secret value is replaced with [REDACTED], preserving 1-based line numbers
    and extracting deterministic slot records so agents can find which file/page defines a key.
    """
    raw_lines: List[str] = []
    for enc in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            with open(file_path, "r", encoding=enc) as f:
                raw_lines = f.read().splitlines()
            break
        except Exception:
            continue

    redacted_lines: List[str] = []
    extracted_slots: List[Dict[str, Any]] = []
    in_multiline_quote: Optional[str] = None

    for line_idx, line in enumerate(raw_lines, start=1):
        if in_multiline_quote is not None:
            redacted_lines.append("# [REDACTED_MULTILINE]")
            if _has_unescaped_delim(line, in_multiline_quote):
                in_multiline_quote = None
            continue

        m = ENV_KEY_LINE_RE.match(line)
        if m:
            key_name = m.group(1)
            raw_val = m.group(2)
            in_multiline_quote = _detect_unclosed_quote_delim(raw_val)
            redacted_line = f"{key_name}=[REDACTED]"
            extracted_slots.append({
                "page_number": 1,
                "category": "config_rule",
                "memory_key": key_name,
                "memory_content": f"Environment variable '{key_name}' is defined in {filename} (line {line_idx}).",
                "quoted_sentence": redacted_line,
                "locator": f"Environment Keys > Line {line_idx}",
                "char_start": 0,
                "char_end": len(redacted_line),
            })
            redacted_lines.append(redacted_line)
        elif line.strip().startswith("#") or not line.strip():
            redacted_lines.append(line)
        else:
            redacted_line = f"# [REDACTED_LINE_{line_idx}]"
            redacted_lines.append(redacted_line)

    full_text = "\n".join(redacted_lines).strip() or f"# Empty env file: {filename}"
    search_from = 0
    for slot in extracted_slots:
        q = slot["quoted_sentence"]
        pos = full_text.find(q, search_from)
        if pos < 0:
            pos = full_text.find(q)
        if pos >= 0:
            slot["char_start"] = pos
            slot["char_end"] = pos + len(q)
            search_from = pos + len(q)

    locator = "Environment Keys (Values Redacted)"
    struct_loc = StructuredLocator.from_raw(
        page=1,
        pdf_page=1,
        locator_str=locator,
        header=locator,
        char_span=(0, len(full_text)),
    )
    page = PageData(
        index=1,
        pdf_page=1,
        printed_page="1",
        locator=locator,
        structured_locator=struct_loc,
        text=full_text,
        digital_text=full_text,
        blocks=[
            ContentBlock(
                text=full_text,
                block_type="paragraph",
                char_start=0,
                char_end=len(full_text),
            )
        ],
        char_count=len(full_text),
    )
    result = ParserResult(
        filename=filename,
        mime="text/plain",
        detected_mime="text/x-env-redacted",
        file_hash=file_hash,
        parser_name="env-redactor",
        parser_version="env-redactor@1.0",
        pages=[page],
    )
    return result, extracted_slots


def _segment_unpaged_text_into_pages(
    text: str,
    filename: str,
    lines_per_fallback_page: int = 80
) -> Tuple[List[PageData], List[Dict[str, Any]]]:
    """
    Segment unpaged Markdown, systemd units, config files, or logs into deterministic
    1-based logical pages so every memory on the OS is tied to a specific page_number.
    Also extracts deterministic config/systemd slots where present.
    """
    raw_lines = (text or "").splitlines()
    if filename.lower().endswith((".service", ".timer", ".socket", ".mount")) or "[Service]" in (text or ""):
        lines = [_redact_systemd_env_line(ln) for ln in raw_lines]
    else:
        lines = raw_lines
    if not lines:
        empty_text = f"[Empty file: {filename}]"
        loc = StructuredLocator.from_raw(page=1, pdf_page=1, header="Page 1", locator_str="Page 1")
        return [
            PageData(
                index=1,
                pdf_page=1,
                printed_page="1",
                locator="Page 1",
                structured_locator=loc,
                text=empty_text,
                digital_text=empty_text,
                char_count=len(empty_text),
            )
        ], []

    sections: List[Tuple[str, List[Tuple[int, str]]]] = []
    current_header = "Header / Preamble"
    current_lines: List[Tuple[int, str]] = []

    is_markdown_like = filename.lower().endswith((".md", ".markdown", ".txt"))
    for line_num, line in enumerate(lines, start=1):
        md_m = MD_HEADING_RE.match(line) if is_markdown_like else None
        stanza_m = CONFIG_STANZA_RE.match(line)
        if md_m:
            if current_lines:
                sections.append((current_header, current_lines))
                current_lines = []
            current_header = md_m.group(2).strip()
            current_lines.append((line_num, line))
        elif stanza_m:
            if current_lines:
                sections.append((current_header, current_lines))
                current_lines = []
            current_header = f"[{stanza_m.group(1).strip()}]"
            current_lines.append((line_num, line))
        else:
            current_lines.append((line_num, line))
            if len(current_lines) >= lines_per_fallback_page and current_header == "Header / Preamble":
                sections.append((f"Lines {current_lines[0][0]}-{current_lines[-1][0]}", current_lines))
                current_lines = []

    if current_lines:
        if len(sections) == 0 and current_header == "Header / Preamble":
            current_header = f"Lines {current_lines[0][0]}-{current_lines[-1][0]}"
        sections.append((current_header, current_lines))

    pages: List[PageData] = []
    auto_slots: List[Dict[str, Any]] = []

    for page_idx, (sec_header, sec_lines) in enumerate(sections, start=1):
        page_text = "\n".join(ln for _, ln in sec_lines).strip()
        if not page_text:
            continue
        first_line = sec_lines[0][0]
        last_line = sec_lines[-1][0]
        printed_label = f"lines {first_line}-{last_line}"
        struct_loc = StructuredLocator.from_raw(
            page=page_idx,
            pdf_page=page_idx,
            printed_page=printed_label,
            locator_str=sec_header,
            header=sec_header,
            char_span=(0, len(page_text)),
        )
        pages.append(
            PageData(
                index=page_idx,
                pdf_page=page_idx,
                printed_page=printed_label,
                locator=sec_header,
                structured_locator=struct_loc,
                text=page_text,
                digital_text=page_text,
                blocks=[
                    ContentBlock(
                        text=page_text,
                        block_type="paragraph",
                        char_start=0,
                        char_end=len(page_text),
                    )
                ],
                char_count=len(page_text),
            )
        )

        # Extract deterministic systemd/config directives on this page
        for _, raw_ln in sec_lines:
            dm = SYSTEMD_DIRECTIVE_RE.match(raw_ln)
            if dm:
                directive_key = dm.group(1)
                directive_val = dm.group(2).strip()
                quoted = raw_ln.strip()
                pos = page_text.find(quoted)
                auto_slots.append({
                    "page_number": page_idx,
                    "category": "config_rule",
                    "memory_key": directive_key,
                    "memory_content": f"{filename} ({sec_header}) sets {directive_key}={directive_val}",
                    "quoted_sentence": quoted,
                    "locator": sec_header,
                    "char_start": pos if pos >= 0 else 0,
                    "char_end": (pos + len(quoted)) if pos >= 0 else len(quoted),
                })

    if not pages:
        loc = StructuredLocator.from_raw(page=1, pdf_page=1, header="Page 1", locator_str="Page 1")
        pages.append(
            PageData(
                index=1,
                pdf_page=1,
                printed_page="1",
                locator="Page 1",
                structured_locator=loc,
                text=text.strip(),
                digital_text=text.strip(),
                char_count=len(text.strip()),
            )
        )

    return pages, auto_slots


def parse_os_file_with_nexus(
    file_path: str,
    privacy_level: PrivacyLevel,
    file_hash: str
) -> Tuple[ParserResult, List[Dict[str, Any]]]:
    """
    Parse an OS file using KruschNexus Library Mode while enforcing:
    1. Secret value redaction for KEYS_ONLY files (.env).
    2. 1-based page assignment for every page (converting unpaged sections/markdown into 1-based logical pages).
    """
    filename = os.path.basename(file_path)

    if privacy_level == PrivacyLevel.KEYS_ONLY:
        return redact_env_content_to_pages(file_path, filename, file_hash)

    if privacy_level in (PrivacyLevel.METADATA_ONLY, PrivacyLevel.VAULT_LOCKED):
        summary_text = f"[{privacy_level.value.upper()}] {filename} ({os.path.getsize(file_path)} bytes)"
        loc = StructuredLocator.from_raw(page=1, pdf_page=1, header=privacy_level.value, locator_str=privacy_level.value)
        page = PageData(
            index=1,
            pdf_page=1,
            printed_page="1",
            locator=privacy_level.value,
            structured_locator=loc,
            text=summary_text,
            digital_text=summary_text,
            char_count=len(summary_text),
        )
        return (
            ParserResult(
                filename=filename,
                mime="application/octet-stream",
                detected_mime="application/octet-stream",
                file_hash=file_hash,
                parser_name="metadata-pointer",
                parser_version="metadata-pointer@1.0",
                pages=[page],
            ),
            [],
        )

    ext = os.path.splitext(filename)[1].lower()
    # For markdown, systemd units, config files, and logs, use our heading/stanza pager
    if ext in (".md", ".service", ".timer", ".conf", ".ini", ".toml", ".yaml", ".yml", ".log"):
        raw_text = ""
        for enc in ("utf-8", "utf-8-sig", "latin-1"):
            try:
                with open(file_path, "r", encoding=enc) as f:
                    raw_text = f.read()
                break
            except Exception:
                continue
        pages, auto_slots = _segment_unpaged_text_into_pages(raw_text, filename)
        return (
            ParserResult(
                filename=filename,
                mime="text/markdown" if ext == ".md" else "text/plain",
                detected_mime="text/markdown" if ext == ".md" else "text/plain",
                file_hash=file_hash,
                parser_name="nexus-os-pager",
                parser_version="nexus-os-pager@1.0",
                pages=pages,
            ),
            auto_slots,
        )

    # Delegate directly to KruschNexus zero-config parse_file() for PDF, DOCX, CSV, HTML, EML, TXT
    try:
        res = parse_file(file_path, ocr_threshold=0, timeout=5.0)
    except Exception as exc:
        summary_text = f"[UNPARSABLE_OR_ENCRYPTED] {filename}: {type(exc).__name__}"
        loc = StructuredLocator.from_raw(page=1, pdf_page=1, header="Unparsable", locator_str="Unparsable")
        page = PageData(
            index=1,
            pdf_page=1,
            printed_page="1",
            locator="Unparsable",
            structured_locator=loc,
            text=summary_text,
            digital_text=summary_text,
            char_count=len(summary_text),
        )
        return (
            ParserResult(
                filename=filename,
                mime="application/octet-stream",
                detected_mime="application/octet-stream",
                file_hash=file_hash,
                parser_name="fallback-pointer",
                parser_version="fallback-pointer@1.0",
                pages=[page],
            ),
            [],
        )
    auto_slots: List[Dict[str, Any]] = []

    # Ensure every PageData has a 1-based page number (`index` and `pdf_page`)
    if len(res.pages) == 1 and (res.pages[0].index is None or ext == ".txt") and "\n#" in res.pages[0].text:
        paged_list, auto_slots = _segment_unpaged_text_into_pages(res.pages[0].text, filename)
        res.pages = paged_list
    else:
        for idx, p in enumerate(res.pages, start=1):
            if p.index is None:
                p.index = idx
            if p.pdf_page is None:
                p.pdf_page = p.index
            if p.structured_locator is None:
                p.structured_locator = StructuredLocator.from_raw(
                    page=p.index,
                    pdf_page=p.pdf_page,
                    printed_page=p.printed_page,
                    locator_str=p.locator,
                    header=p.locator,
                )

    return res, auto_slots


def parse_remote_text_with_nexus(
    file_path: str,
    text_content: Optional[str],
    privacy_level: PrivacyLevel,
    file_hash: str,
    size_bytes: int = 0,
) -> Tuple[ParserResult, List[Dict[str, Any]]]:
    """
    Parse a remotely streamed fleet file into 1-based KruschNexus pages and deterministic slots.
    Note: For KEYS_ONLY (.env) files, values are already redacted on the remote node before streaming.
    """
    filename = os.path.basename(file_path)

    if privacy_level in (PrivacyLevel.METADATA_ONLY, PrivacyLevel.VAULT_LOCKED) or text_content is None:
        summary_text = f"[{privacy_level.value.upper()}] {filename} ({size_bytes} bytes)"
        loc = StructuredLocator.from_raw(page=1, pdf_page=1, header=privacy_level.value, locator_str=privacy_level.value)
        page = PageData(
            index=1,
            pdf_page=1,
            printed_page="1",
            locator=privacy_level.value,
            structured_locator=loc,
            text=summary_text,
            digital_text=summary_text,
            char_count=len(summary_text),
        )
        return (
            ParserResult(
                filename=filename,
                mime="application/octet-stream",
                detected_mime="application/octet-stream",
                file_hash=file_hash,
                parser_name="remote-metadata-pointer",
                parser_version="remote-metadata-pointer@1.0",
                pages=[page],
            ),
            [],
        )

    if privacy_level == PrivacyLevel.KEYS_ONLY:
        # Extract key slots from already-redacted KEY=[REDACTED] lines (and redact if unredacted)
        slots: List[Dict[str, Any]] = []
        redacted_lines: List[str] = []
        in_multiline_quote: Optional[str] = None
        for line_idx, line in enumerate(text_content.splitlines(), start=1):
            if in_multiline_quote is not None:
                redacted_lines.append("# [REDACTED_MULTILINE]")
                if _has_unescaped_delim(line, in_multiline_quote):
                    in_multiline_quote = None
                continue
            m = ENV_KEY_LINE_RE.match(line)
            if m:
                key_name = m.group(1)
                raw_val = m.group(2)
                in_multiline_quote = _detect_unclosed_quote_delim(raw_val)
                redacted_line = f"{key_name}=[REDACTED]"
                slots.append({
                    "page_number": 1,
                    "category": "config_rule",
                    "memory_key": key_name,
                    "memory_content": f"Environment variable '{key_name}' is defined in {filename} (line {line_idx}).",
                    "quoted_sentence": redacted_line,
                    "locator": f"Environment Keys > Line {line_idx}",
                    "char_start": 0,
                    "char_end": len(redacted_line),
                })
                redacted_lines.append(redacted_line)
            elif line.strip().startswith("#") or not line.strip():
                redacted_lines.append(line)
            else:
                redacted_lines.append(f"# [REDACTED_LINE_{line_idx}]")
        full_text = "\n".join(redacted_lines).strip() or f"# Empty env file: {filename}"
        search_from = 0
        for slot in slots:
            q = slot["quoted_sentence"]
            pos = full_text.find(q, search_from)
            if pos < 0:
                pos = full_text.find(q)
            if pos >= 0:
                slot["char_start"] = pos
                slot["char_end"] = pos + len(q)
                search_from = pos + len(q)
        loc = "Environment Keys (Values Redacted)"
        struct_loc = StructuredLocator.from_raw(
            page=1, pdf_page=1, locator_str=loc, header=loc, char_span=(0, len(full_text))
        )
        page = PageData(
            index=1,
            pdf_page=1,
            printed_page="1",
            locator=loc,
            structured_locator=struct_loc,
            text=full_text,
            digital_text=full_text,
            blocks=[ContentBlock(text=full_text, block_type="paragraph", char_start=0, char_end=len(full_text))],
            char_count=len(full_text),
        )
        return (
            ParserResult(
                filename=filename,
                mime="text/plain",
                detected_mime="text/x-env-redacted",
                file_hash=file_hash,
                parser_name="remote-env-redactor",
                parser_version="remote-env-redactor@1.0",
                pages=[page],
            ),
            slots,
        )

    pages, auto_slots = _segment_unpaged_text_into_pages(text_content, filename)
    return (
        ParserResult(
            filename=filename,
            mime="text/plain",
            detected_mime="text/plain",
            file_hash=file_hash,
            parser_name="remote-nexus-pager",
            parser_version="remote-nexus-pager@1.0",
            pages=pages,
        ),
        auto_slots,
    )

