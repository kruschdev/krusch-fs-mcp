# KruschFS Architectural Invariants (`docs/INVARIANTS.md`)

| ID | Invariant | Enforcement Mechanism | Verification Test |
| :--- | :--- | :--- | :--- |
| **INV-FS-1** | **In-Place OS Pointer Mode (Zero File Duplication)** | `FSFile` stores `(host_node, device_id, inode, file_path, file_hash)` without copying files into `.ingested/`. | `test_multi_page_indexing_and_write_through_page_memory` |
| **INV-FS-2** | **Universal 1-Based `KruschNexus` Page Spine** | Every indexed file has 1-based `FSPage` rows (`page_number >= 1`) with SHA-256 `page_hash` and `StructuredLocator`. | `test_real_pdf_and_docx_nexus_page_memory_grounding` |
| **INV-FS-3** | **Single-Page Delta Re-Indexing & Granular Drift** | Editing page $k$ only re-indexes page $k$ and only sets `is_drifted=True` on memories anchored to page $k$ whose `quoted_sentence` was altered. | `test_per_page_delta_reindexing_and_granular_memory_drift` |
| **INV-FS-4** | **Verbatim Quote Grounding (`INV-12`)** | `krusch_fs_remember_on_page` verifies `quoted_sentence` exists on `(host_node, file_path, page_number)` before persisting `PageMemory`. | `test_multi_page_indexing_and_write_through_page_memory` |
| **INV-FS-5** | **Inode Move & Rename Preservation** | Moving/renaming a file with matching `(host_node, device_id, inode, file_hash)` updates `file_path` and citations in-place while preserving all page memories. | `test_inode_move_and_rename_preserves_page_memories` |
| **INV-FS-6** | **Zero-Trust `.env` Redaction & Key Vault Lock** | `.env` values are replaced with `KEY=[REDACTED]` (remotely before SSH transport) and SSH/private keys are locked (`VAULT_LOCKED`). | `test_env_secret_redaction_and_systemd_config_extraction` |
| **INV-FS-7** | **Smart `.git` Boundary Handoff** | Directories containing `.git` record a single `repo_boundaries` pointer (`handoff_repo="krusch-git:<repo>"`) and skip internal source tree walks. | `test_git_repo_boundary_handoff_to_krusch_git` |
| **INV-FS-8** | **Multi-Node Fleet Partitioning & MCP Behavioral Annotations** | All tables and tools partition by `host_node` and declare `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`. | `test_multi_node_fleet_indexing_and_host_filtering`, `test_mcp_tools_and_behavioral_annotations` |
