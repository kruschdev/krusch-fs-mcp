# KruschFS (`krusch-fs`) — Agent Operating Protocol (v0.3.1)

> **Package**: `krusch-fs` (v0.3.1 — Pointer-Slice Chunk Deduplication & Multi-Node Fleet Page Memory)  
> **Role**: Tier 2B OS Filesystem & Multi-Node Fleet Page Memory MCP Server  
> **Storage**: SQLite (`~/.krusch-fs/fs_memory.db`) via KruschNexus Library Mode; optional Postgres `kdcode:5432`  
> **Tests**: 9 Passing (`pytest`)

---

## 1. Overview & Architecture

`krusch-fs` provides coding and SRE agents with structured, SHA-256 drift-verified page trees and page-anchored operational memory across the local OS filesystem (`~/Documents`, `~/Downloads`, `/etc/systemd/system`, `/etc/fstab`, `/etc/hosts`, `.env` variable keys) and all 8 homelab nodes (`krusch`, `kruschdev`, `kruschserv`, `crush0`, `kr1yoga`, `kruschgame`, `kruschmedia`, `kruschsandbox`).

### Key Capabilities
- **Pointer-Slice Chunk Deduplication**: Stores `[char_start, char_end]` offsets into `FSPage.page_text` (`[POINTER_SLICE]`), eliminating duplicate chunk text storage in SQLite.
- **Secret Redaction**: Indexes `.env` variable key names across the fleet while strictly redacting secret values (`<REDACTED>`).
- **Agentless Tailscale SSH Sync**: Collects remote node configs and metadata over Tailscale SSH via `krusch-fs-fleet-sync.timer` (every 30 minutes) or on-demand `krusch_fs_sync`.

---

## 2. The 6-Verb MCP Contract

1. `krusch_fs_search({ query, node: "all", category: "all", top_k: 10 })`: Hybrid BM25 + semantic search across OS pages and co-located `PageMemory` annotations.
2. `krusch_fs_locate({ pattern, node: "all", category: "all", min_size_bytes: 0 })`: Fast metadata/glob lookup across all fleet nodes without reading file contents.
3. `krusch_fs_page_tree({ path, node })`: Inspect a file's structural Table of Contents (`page_number`, `section_title`, `[start_line, end_line]`, `page_hash`, `memory_count`).
4. `krusch_fs_read_page({ path, page_number, node })`: Read a bounded page with co-located `page_memories` and live SHA-256 drift status (`VALID` vs `STALE_DRIFT`).
5. `krusch_fs_remember_on_page({ path, page_number, note, category, node })`: Pin durable operational notes or warnings directly to `(node, path, page_number, page_hash)`.
6. `krusch_fs_sync({ paths, node: "all", force: false })`: Trigger incremental SHA-256 delta indexing locally or across the Tailscale fleet.
