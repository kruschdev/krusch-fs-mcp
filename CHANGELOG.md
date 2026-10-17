# Changelog

All notable changes to `krusch-fs` (`krusch-fs-mcp`) are documented in this file.

## [0.3.0-alpha] - 2026-10-17

### Added
- **Universal 1-Based `KruschNexus` Page Spine**: In-place OS pointer indexing (`FSFile`, `FSPage`, `FSChunk`) consuming `krusch_nexus` in Zero-Config Library Mode with per-page SHA-256 `page_hash` delta re-indexing.
- **Write-Through Agent Page Memory (`PageMemory`)**: `krusch_fs_remember_on_page` tool verifying verbatim `quoted_sentence` (`INV-12`) and flagging `is_drifted=True` only when the anchored page mutates.
- **3-Zone Workspace Isolation & Privacy Shield**: Automatic classification into `user_docs`, `system_config` (`.env` value redaction `KEY=[REDACTED]` in `KEYS_ONLY` mode and SSH/private key `VAULT_LOCKED` mode), and `repo_boundaries` (`.git` repository boundary handoff to `krusch-git`).
- **Multi-Node SSH Fleet Indexing**: Agentless stdlib SSH scanner (`stream_remote_node_entries`) configured via `~/.krusch-fs/fleet.json` (`KRUSCH_FS_FLEET_CONFIG`) with `<2s` offline node skip (`probe_node_ssh`).
- **6 Canonical MCP Tools**: `krusch_fs_search`, `krusch_fs_page_tree`, `krusch_fs_read_page`, `krusch_fs_remember_on_page`, `krusch_fs_locate`, and `krusch_fs_sync` with all 4 boolean MCP behavioral annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`).
