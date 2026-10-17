# KruschFS MCP (`krusch-fs`)

> **PGit + KruschNexus for Your Operating System & Multi-Node Fleet** — Standalone, opt-in OS Filesystem & Page-Anchored Memory MCP Server (`v0.3.0-alpha`).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB.svg)](pyproject.toml)
[![MCP Behavioral Annotations](https://img.shields.io/badge/MCP-Annotated-success.svg)](src/krusch_fs/mcp.py)

`krusch-fs` is a lightweight, opt-in Model Context Protocol (MCP) server that indexes files across your local operating system and optional remote SSH fleet nodes **in-place** (zero file duplication) and binds every semantic memory, configuration rule, and retrieved snippet directly to a **1-based `KruschNexus` page** (`(host_node, file_id, page_number, anchor_page_hash)`).

---

## ✨ Core Architectural Pillars

### 1. Universal 1-Based `KruschNexus` Page Spine
- Consumes `krusch_nexus` in **Zero-Config Library Mode** (`parse_file`, `chunk_document_pages`, `format_citation`) without running duplicate OCR workers or copying files into a staging vault.
- Every indexed file (PDF, DOCX, CSV, HTML, Markdown, systemd `.service`, `.conf`, `/etc/fstab`, and redacted `.env`) is segmented into deterministic 1-based pages (`fs_pages`) with a per-page SHA-256 `page_hash`.
- **Single-Page Delta Re-Indexing**: Editing page 42 of a 120-page PDF or section 3 of a Markdown runbook only re-embeds page 42 and only flags memories anchored to page 42 as `is_drifted=True`, leaving pages `1..41` and `43..120` untouched.
- **Inode Move & Rename Resilience**: Moving or renaming a file on the same filesystem updates `file_path` and citations in-place via `(host_node, device_id, inode, file_hash)` without re-parsing or losing page-anchored memories.

### 2. 3-Zone Workspace Isolation & Zero-Trust Privacy Shield
- **`user_docs`**: PDFs, DOCX contracts, spreadsheets, notes, and manuals in `~/Documents`, `~/Downloads`, and project `docs/`.
- **`system_config`**: `/etc/systemd/system`, `/etc/fstab`, `/etc/hosts`, `.conf`, and `.env` files.
  - **`.env` Value Redaction (`KEYS_ONLY`)**: Secret values are replaced with `KEY=[REDACTED]` (on the remote node *before* crossing SSH) while indexing variable names as `config_rule` page memories so agents can ask *"Where is `DATABASE_URL` configured?"* without ever exposing secret values.
  - **Private Key Vault Lock (`VAULT_LOCKED`)**: SSH keys (`id_rsa`, `id_ed25519`), `.pem`/`.key`/`.kdbx` files, and browser cookie DBs are never read or embedded.
- **`repo_boundaries`**: Any directory containing `.git` is automatically recorded as a lightweight boundary pointer (`handoff_repo="krusch-git:<repo>"`) and skipped so `krusch-git` remains the single source of truth for source code.

### 3. Multi-Node SSH Fleet Indexing
- Works out of the box on a single workstation, or indexes an entire fleet of Linux/macOS machines via `~/.krusch-fs/fleet.json` (see [`fleet.example.json`](fleet.example.json)) using agentless SSH stdlib streaming (`stream_remote_node_entries`).
- Sleeping or offline machines are probed in `<2s` (`probe_node_ssh`) and cleanly skipped (`status="offline_skipped"`) until powered on.

---

## 🛠️ 6 Canonical MCP Tools

All 6 tools declare explicit MCP behavioral annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`):

| Tool | Purpose | Annotations |
| :--- | :--- | :--- |
| `krusch_fs_search` | Hybrid RRF search across OS page chunks & page-anchored memories (`host_node`, `workspace`, `category`) | `readOnlyHint=True` |
| `krusch_fs_page_tree` | Return the 1-based Page Spine (`1..N` pages, `page_hash`, memory counts, drift status) for a file | `readOnlyHint=True` |
| `krusch_fs_read_page` | Hydrate exact text, bounding boxes, and attached memories for `page_number` (or `end_page` range) | `readOnlyHint=True` |
| `krusch_fs_remember_on_page` | Anchor a verified fact/rule (`INV-12` verbatim `quoted_sentence`) onto `(host_node, file_path, page_number)` | `idempotentHint=True` |
| `krusch_fs_locate` | Fast metadata/inode search by filename, extension, size, mtime window, or SHA-256 duplicates | `readOnlyHint=True` |
| `krusch_fs_sync` | Scan a local path, a specific remote `host_node`, or synchronize the entire fleet (`action="sync_fleet"`) | `idempotentHint=True` |

---

## ⚙️ MCP Server Configuration

Add `krusch-fs` to your `mcp_config.json` (Claude Desktop, Cursor, Windsurf, or Antigravity):

```json
{
  "mcpServers": {
    "krusch-fs": {
      "command": "krusch-fs-mcp",
      "env": {
        "KRUSCH_FS_DB_URL": "sqlite:////home/your-user/.krusch-fs/fs_memory.db",
        "KRUSCH_FS_FLEET_CONFIG": "/home/your-user/.krusch-fs/fleet.json"
      }
    }
  }
}
```

---

## 🚀 Quickstart & CLI

```bash
# Install in editable mode
pip install -e .

# (Optional) Configure multi-node SSH targets outside the repo
mkdir -p ~/.krusch-fs
cp fleet.example.json ~/.krusch-fs/fleet.json

# Synchronize local workstation and all online fleet nodes
krusch-fs sync-fleet

# Inspect fleet-wide index statistics
krusch-fs status

# Search across all fleet nodes (or pass --node compute-node-01)
krusch-fs search "ExecStart" --workspace system_config

# Inspect the 1-based page tree of any indexed file
krusch-fs tree /etc/fstab --node compute-node-01

# Run the MCP server over stdio
krusch-fs-mcp
```

## 🧪 Testing

```bash
pytest tests/ -v
```
