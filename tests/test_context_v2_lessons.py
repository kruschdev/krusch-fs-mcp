"""
Regression & Formal Invariant Verification Suite for KruschFS v0.4.0 (`spec.md`).
Covers:
- `INV-FS-VEC-01`: Model tag canonicalization, asymmetric query prefixes, fail-null Ollama isolation,
  isotropic cosine calibration, and environment-aware backend selection.
- `INV-FS-BLOB-02`: IEEE-754 Float32 `embedding_blob` (`4096` bytes), `embedding=None` on SQLite,
  idempotent legacy `ALTER TABLE` migration, and strict cross-model vector rejection.
- `INV-FS-FTS5-03`: External-content Porter FTS5 tables/triggers/backfill, morphological search,
  and lazy Top-K `FSPage` hydration (zero full-table `FSPage.page_text`/`blocks_json` scan).
- `INV-FS-BUDGET-04`: Pre-write Secret Shield (`scan_for_secret_leak`), bounded `page_memories`
  (all pinned + Top-3 `auto_extracted`), `limit_tokens`, and `unattested_query_terms`.
"""

import io
import json
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path

import pytest
from sqlalchemy import event, text

from krusch_fs.client import KruschFSClient, compute_unattested_query_terms
from krusch_fs.embeddings import (
    calibrate_query_similarity,
    canonical_embed_model_tag,
    clear_embed_cache,
    embed_batch,
    embed_text,
    fast_unit_dot,
    format_embedding_input,
)
from krusch_fs.mcp import (
    get_mcp,
    krusch_fs_search,
    set_client,
)
from krusch_fs.models import KruschFSConfig, _default_embed_backend
from krusch_fs.shield import scan_for_secret_leak
from krusch_fs.store import (
    FSChunk,
    PageMemory,
    create_db_session_factory,
    pack_float32_vector,
    resolve_stored_vector,
    unpack_float32_vector,
)


def test_inv_fs_vec_01_canonical_tags_prefixes_and_calibration(monkeypatch):
    # 1. Model tag canonicalization (:latest equivalence)
    assert canonical_embed_model_tag("deterministic", "snowflake-arctic-embed2:latest") == "deterministic:blake2b-v1"
    assert canonical_embed_model_tag("ollama", "snowflake-arctic-embed2") == "ollama:snowflake-arctic-embed2"
    assert canonical_embed_model_tag("ollama", "snowflake-arctic-embed2:latest") == "ollama:snowflake-arctic-embed2"
    assert canonical_embed_model_tag("ollama", "ollama/SNOWFLAKE-ARCTIC-EMBED2:latest") == "ollama:snowflake-arctic-embed2"
    assert canonical_embed_model_tag("ollama", "models/qwen3-embedding:4b") == "ollama:qwen3-embedding:4b"

    # 2. Asymmetric query formatting (documents untouched, queries prefixed without double-prefixing)
    doc = "Mount NVMe PostgreSQL volume at /mnt/database"
    assert format_embedding_input(doc, model="snowflake-arctic-embed2:latest", mode="document") == doc
    q_sf = format_embedding_input("nvme mount", model="snowflake-arctic-embed2:latest", mode="query")
    assert q_sf == "query: nvme mount"
    assert format_embedding_input(q_sf, model="snowflake-arctic-embed2", mode="query") == q_sf

    q_bge = format_embedding_input("nvme mount", model="bge-large:latest", mode="query")
    assert q_bge == "Represent this sentence for searching relevant passages: nvme mount"

    q_nomic = format_embedding_input("nvme mount", model="nomic-embed-text:latest", mode="query")
    assert q_nomic == "search_query: nvme mount"

    q_qwen = format_embedding_input("nvme mount", model="qwen3-embedding:4b", mode="query", domain="fs")
    assert q_qwen.startswith("Instruct: ")
    assert "\nQuery:nvme mount" in q_qwen

    # 3. Isotropic cosine calibration vs deterministic/sparse passthrough
    dense_query = [0.05] * 64 + [0.0] * (1024 - 64)
    sparse_query = [1.0] + [0.0] * 1023
    assert calibrate_query_similarity(0.25, model="snowflake-arctic-embed2", backend="deterministic", query_vec=dense_query) == pytest.approx(0.25)
    assert calibrate_query_similarity(0.25, model="snowflake-arctic-embed2", backend="ollama", query_vec=sparse_query) == pytest.approx(0.25)
    cal = calibrate_query_similarity(0.25, model="snowflake-arctic-embed2:latest", backend="ollama", query_vec=dense_query)
    assert cal == pytest.approx(0.52)

    # 4. Environment-aware _default_embed_backend()
    monkeypatch.delenv("KRUSCH_FS_EMBED_BACKEND", raising=False)
    monkeypatch.setenv("PYTEST_CURRENT_TEST", "active")
    monkeypatch.setenv("EMBED_MODEL", "snowflake-arctic-embed2:latest")
    assert _default_embed_backend() == "deterministic"

    monkeypatch.delenv("PYTEST_CURRENT_TEST", raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("MOCK_EMBEDDINGS", raising=False)
    assert _default_embed_backend() == "ollama"

    cfg = KruschFSConfig()
    assert cfg.embed_backend == "ollama"
    assert cfg.embed_model == "snowflake-arctic-embed2:latest"


def test_inv_fs_vec_01_fail_null_ollama_isolation_and_mrl_payload(tmp_path, monkeypatch):
    clear_embed_cache()
    captured_payloads = []

    def fake_urlopen_fail(req, timeout=8.0):
        raise urllib.error.URLError("ollama daemon offline")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen_fail)
    assert embed_text("test text", backend="ollama", dim=1024) is None
    assert embed_batch(["one", "two"], backend="ollama", dim=1024) == [None, None]

    # Partial batch HTTPError (500 on batch + toxic item, 200 on clean sibling) rescues clean sibling without hash poisoning
    class OkSingleResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return json.dumps({"embeddings": [[1.0 / 32.0] * 1024]}).encode("utf-8")

    def fake_urlopen_partial_500(req, timeout=8.0):
        body = json.loads(req.data.decode("utf-8"))
        inp = body.get("input")
        if isinstance(inp, list) or inp == "toxic\x00blob":
            raise urllib.error.HTTPError(req.full_url, 500, "Internal Server Error", hdrs=None, fp=io.BytesIO(b""))
        return OkSingleResp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen_partial_500)
    partial_vecs = embed_batch(["clean sibling", "toxic\x00blob"], backend="ollama", dim=1024)
    assert partial_vecs[0] is not None and len(partial_vecs[0]) == 1024
    assert partial_vecs[1] is None

    # Non-finite NaN vector from daemon must also fail-null (never poison)
    class BadNanResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            return b'{"embeddings": [[' + b",".join([b"0.1"] * 1023 + [b"NaN"]) + b"]]}"

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=8.0: BadNanResp())
    assert embed_text("nan check", backend="ollama", dim=1024) is None

    # Verify MRL dimensions parameter sent for nomic-embed-text and valid unit vector returned
    class GoodNomicResp:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self):
            vec = [1.0 / 32.0] * 1024
            return json.dumps({"embeddings": [vec]}).encode("utf-8")

    def fake_urlopen_nomic(req, timeout=8.0):
        captured_payloads.append(json.loads(req.data.decode("utf-8")))
        return GoodNomicResp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen_nomic)
    res_vec = embed_text("nomic query", backend="ollama", model="nomic-embed-text:latest", dim=1024, mode="query")
    assert res_vec is not None and len(res_vec) == 1024
    assert captured_payloads[-1]["dimensions"] == 1024
    assert captured_payloads[-1]["input"] == "search_query: nomic query"

    # End-to-end client indexing while Ollama is offline: stores None vectors (zero hash poisoning)
    # and still retrieves via SQLite FTS5!
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen_fail)
    db_file = tmp_path / "offline_ollama.db"
    doc = tmp_path / "ups_runbook.md"
    doc.write_text("# UPS Battery\nCyberPower UPS runtime threshold is 25 minutes.\n", encoding="utf-8")

    client = KruschFSClient(
        KruschFSConfig(
            db_url=f"sqlite:///{db_file}",
            host_node="krusch",
            embed_backend="ollama",
            embed_model="snowflake-arctic-embed2:latest",
        )
    )
    client.scan_path(str(doc))

    db = client.SessionLocal()
    try:
        chk = db.query(FSChunk).first()
        assert chk is not None
        assert chk.embedding is None
        assert chk.embedding_blob is None
        assert chk.embed_model is None
    finally:
        db.close()

    hits = client.search("CyberPower UPS runtime")
    assert len(hits) == 1
    assert hits[0].file_name == "ups_runbook.md"


def test_inv_fs_blob_02_float32_packing_migration_and_isolation(tmp_path):
    # 1. Pack / unpack roundtrip & invalid rejection
    orig = [((i % 17) - 8) * 0.01 for i in range(1024)]
    blob = pack_float32_vector(orig, dim=1024)
    assert blob is not None and len(blob) == 4096
    unpacked = unpack_float32_vector(blob, dim=1024)
    assert unpacked is not None and len(unpacked) == 1024
    assert fast_unit_dot(orig, unpacked) >= 0.0
    assert pack_float32_vector([1.0, 2.0], dim=1024) is None
    assert pack_float32_vector([float("nan")] * 1024, dim=1024) is None

    # 2. Vector-space isolation in resolve_stored_vector
    assert (
        resolve_stored_vector(
            embedding_blob=blob,
            legacy_embedding=None,
            row_embed_model="deterministic:blake2b-v1",
            expected_model_tag="ollama:snowflake-arctic-embed2",
            dim=1024,
        )
        is None
    )
    assert (
        resolve_stored_vector(
            embedding_blob=blob,
            legacy_embedding=None,
            row_embed_model="ollama:snowflake-arctic-embed2",
            expected_model_tag="ollama:snowflake-arctic-embed2",
            dim=1024,
        )
        is not None
    )

    # 3. Legacy SQLite DB idempotent ALTER TABLE + FTS5 backfill migration
    legacy_db = tmp_path / "legacy_v03.db"
    raw_conn = sqlite3.connect(str(legacy_db))
    raw_conn.executescript(
        """
        CREATE TABLE fs_files (
            id INTEGER PRIMARY KEY,
            host_node VARCHAR(64) NOT NULL DEFAULT 'krusch',
            workspace VARCHAR(64) NOT NULL DEFAULT 'user_docs',
            device_id VARCHAR(64) NOT NULL DEFAULT '0',
            inode INTEGER NOT NULL DEFAULT 1,
            file_path VARCHAR(1024) NOT NULL,
            parent_path VARCHAR(1024) NOT NULL,
            file_name VARCHAR(512) NOT NULL,
            extension VARCHAR(32) NOT NULL DEFAULT '.md',
            mime_type VARCHAR(128) NOT NULL DEFAULT 'text/markdown',
            size_bytes INTEGER NOT NULL DEFAULT 42,
            mtime FLOAT NOT NULL DEFAULT 1760000000.0,
            atime FLOAT NOT NULL DEFAULT 1760000000.0,
            file_hash VARCHAR(64) NOT NULL DEFAULT 'abc',
            total_pages INTEGER NOT NULL DEFAULT 1,
            privacy_level VARCHAR(32) NOT NULL DEFAULT 'standard',
            handoff_repo VARCHAR(255),
            is_deleted BOOLEAN NOT NULL DEFAULT 0,
            updated_at DATETIME,
            created_at DATETIME
        );
        CREATE TABLE fs_pages (
            id INTEGER PRIMARY KEY,
            file_id INTEGER NOT NULL,
            workspace VARCHAR(64) NOT NULL DEFAULT 'user_docs',
            page_number INTEGER NOT NULL DEFAULT 1,
            printed_page VARCHAR(64),
            page_hash VARCHAR(64) NOT NULL DEFAULT 'ph1',
            section_header VARCHAR(512),
            locator VARCHAR(512),
            citation VARCHAR(512) NOT NULL DEFAULT 'legacy.md p.1',
            page_text TEXT NOT NULL,
            blocks_json TEXT,
            char_count INTEGER NOT NULL DEFAULT 30,
            ocr_applied BOOLEAN NOT NULL DEFAULT 0,
            ocr_confidence FLOAT,
            updated_at DATETIME
        );
        CREATE TABLE fs_chunks (
            id INTEGER PRIMARY KEY,
            file_id INTEGER NOT NULL,
            page_id INTEGER NOT NULL,
            workspace VARCHAR(64) NOT NULL DEFAULT 'user_docs',
            page_number INTEGER NOT NULL DEFAULT 1,
            printed_page VARCHAR(64),
            chunk_index INTEGER NOT NULL DEFAULT 0,
            citation VARCHAR(512) NOT NULL DEFAULT 'legacy.md p.1',
            header VARCHAR(512),
            locator VARCHAR(512),
            content TEXT NOT NULL DEFAULT '',
            source_hash VARCHAR(64),
            char_start INTEGER,
            char_end INTEGER,
            bbox TEXT,
            embedding TEXT,
            created_at DATETIME
        );
        CREATE TABLE page_memories (
            id INTEGER PRIMARY KEY,
            file_id INTEGER NOT NULL,
            page_id INTEGER,
            workspace VARCHAR(64) NOT NULL DEFAULT 'user_docs',
            page_number INTEGER NOT NULL DEFAULT 1,
            printed_page VARCHAR(64),
            category VARCHAR(64) NOT NULL DEFAULT 'fact',
            memory_key VARCHAR(255),
            memory_content TEXT NOT NULL,
            quoted_sentence TEXT NOT NULL,
            citation VARCHAR(512) NOT NULL,
            locator VARCHAR(512),
            bbox TEXT,
            char_start INTEGER NOT NULL DEFAULT 0,
            char_end INTEGER NOT NULL DEFAULT 10,
            anchor_page_hash VARCHAR(64) NOT NULL DEFAULT 'ph1',
            is_drifted BOOLEAN NOT NULL DEFAULT 0,
            auto_extracted BOOLEAN NOT NULL DEFAULT 0,
            embedding TEXT,
            updated_at DATETIME,
            created_at DATETIME
        );
        INSERT INTO fs_files (id, file_path, parent_path, file_name) VALUES (1, '/tmp/legacy.md', '/tmp', 'legacy.md');
        INSERT INTO fs_pages (id, file_id, section_header, page_text) VALUES (1, 1, 'Storage', 'Legacy RAIDz2 scrub schedule runs Sunday.');
        INSERT INTO fs_chunks (id, file_id, page_id, content) VALUES (1, 1, 1, 'Legacy RAIDz2 scrub schedule runs Sunday.');
        """
    )
    raw_conn.commit()
    raw_conn.close()

    engine, SessionLocal = create_db_session_factory(f"sqlite:///{legacy_db}")
    with engine.connect() as conn:
        chunk_cols = {r[1] for r in conn.execute(text("PRAGMA table_info(fs_chunks)")).fetchall()}
        mem_cols = {r[1] for r in conn.execute(text("PRAGMA table_info(page_memories)")).fetchall()}
        assert "embedding_blob" in chunk_cols and "embed_model" in chunk_cols
        assert "embedding_blob" in mem_cols and "embed_model" in mem_cols
        fts_hits = conn.execute(
            text("SELECT rowid FROM fs_pages_fts WHERE fs_pages_fts MATCH '\"schedules\"'")
        ).fetchall()
        assert len(fts_hits) == 1 and fts_hits[0][0] == 1

    # 4. Verify new SQLite writes set embedding=None and 4096-byte embedding_blob
    fresh_db = tmp_path / "fresh_blob.db"
    fresh_doc = tmp_path / "fresh.md"
    fresh_doc.write_text("# Fresh\nCompact binary vector check.\n", encoding="utf-8")
    client = KruschFSClient(KruschFSConfig(db_url=f"sqlite:///{fresh_db}", embed_backend="deterministic"))
    client.scan_path(str(fresh_doc))
    client.remember_on_page(
        file_path=str(fresh_doc),
        page_number=1,
        memory_content="Binary float32 vector check",
        quoted_sentence="Compact binary vector check.",
    )
    db = SessionLocal()
    db.close()
    s2 = client.SessionLocal()
    try:
        c_row = s2.query(FSChunk).first()
        m_row = s2.query(PageMemory).first()
        assert c_row.embedding is None
        assert len(c_row.embedding_blob) == 4096
        assert c_row.embed_model == "deterministic:blake2b-v1"
        assert m_row.embedding is None
        assert len(m_row.embedding_blob) == 4096
        assert m_row.embed_model == "deterministic:blake2b-v1"
    finally:
        s2.close()


def test_inv_fs_fts5_03_porter_stemming_and_lazy_topk_hydration(tmp_path):
    db_file = tmp_path / "lazy_fts.db"
    docs_dir = tmp_path / "docs"
    docs_dir.mkdir()

    # Create 12 distinct multi-section files (node_guide_07.md has 4 distinct pages)
    for i in range(12):
        p = docs_dir / f"node_guide_{i:02d}.md"
        if i == 7:
            p.write_text(
                "# ZFS Pool Maintenance\n"
                "The storage server mounts archival snapshots onto encrypted datasets.\n\n"
                "# Telemetry\n"
                "SMART temperature polling runs hourly.\n\n"
                "# Replication Schedule\n"
                "Offsite replication runs nightly at 02:00 UTC.\n\n"
                "# Scrubbing Policy\n"
                "Monthly scrub verifies checksums across vdevs.\n",
                encoding="utf-8",
            )
        else:
            p.write_text(
                f"# Generic Worker {i}\n"
                f"Background queue consumer number {i} processes routine tasks.\n\n"
                f"# Appendix {i}\n"
                f"Standard operating notes for worker {i}.\n",
                encoding="utf-8",
            )

    client = KruschFSClient(KruschFSConfig(db_url=f"sqlite:///{db_file}", embed_backend="deterministic"))
    rep = client.scan_path(str(docs_dir))
    assert rep.files_indexed == 12
    assert client.get_page_tree(str(docs_dir / "node_guide_07.md")).total_pages == 4

    executed_sql = []

    def _capture_sql(conn, cursor, statement, parameters, context, executemany):
        executed_sql.append((statement, parameters))

    event.listen(client.engine, "before_cursor_execute", _capture_sql)
    try:
        # Query uses morphological variants ("mounted", "snapshot") resolved via Porter FTS5
        hits = client.search("mounted archival snapshot", limit=2)
    finally:
        event.remove(client.engine, "before_cursor_execute", _capture_sql)

    assert len(hits) >= 1
    assert hits[0].file_name == "node_guide_07.md"
    assert hits[0].page_number == 1
    assert "mounts archival snapshots" in hits[0].snippet

    # Verify FSPage.blocks_json was NEVER selected and FSPage hydration was scoped strictly to Top-K (file_id, page_number) pairs
    fspage_selects = [
        (stmt, params)
        for stmt, params in executed_sql
        if "FROM fs_pages" in stmt and "fs_pages_fts" not in stmt
    ]
    assert len(fspage_selects) == 1
    stmt, params = fspage_selects[0]
    assert "blocks_json" not in stmt
    assert "file_id" in stmt and "page_number" in stmt
    if isinstance(params, (list, tuple)):
        assert len(params) <= 4  # <= 2 * limit scalar parameters for composite (file_id, page_number) pairs
    elif isinstance(params, dict):
        assert len(params) <= 4

    # Verify raw execution of the hydration SQL returns <= 2 rows (excluding sibling pages 2..4 of node_guide_07.md)
    raw_conn = sqlite3.connect(str(db_file))
    try:
        hydrated_count = len(raw_conn.execute(stmt, params).fetchall())
        assert hydrated_count <= 2
    finally:
        raw_conn.close()

    # Verify queries with no >=2-char alphanumeric FTS5 token (e.g. "?") NEVER trigger a full-table FSPage.page_text scan
    punct_sql = []

    def _capture_punct_sql(conn, cursor, statement, parameters, context, executemany):
        punct_sql.append((statement, parameters))

    event.listen(client.engine, "before_cursor_execute", _capture_punct_sql)
    try:
        _ = client.search("?", limit=2)
    finally:
        event.remove(client.engine, "before_cursor_execute", _capture_punct_sql)

    unfiltered_fspage_scans = [
        stmt
        for stmt, _ in punct_sql
        if "FROM fs_pages" in stmt and "fs_pages_fts" not in stmt and "page_number" not in stmt
    ]
    assert unfiltered_fspage_scans == []


def test_inv_fs_budget_04_secret_shield_bounded_memories_and_token_budget(tmp_path):
    # 1. Direct scan_for_secret_leak checks
    assert scan_for_secret_leak("OPENAI_API_KEY=[REDACTED]") is None
    assert scan_for_secret_leak("postgresql://user:[REDACTED]@localhost:5432/db") is None
    assert scan_for_secret_leak("sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456") is not None
    assert scan_for_secret_leak("sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ1234") is not None
    assert scan_for_secret_leak("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456") is not None
    assert scan_for_secret_leak("AKIAIOSFODNN7EXAMPLE") is not None
    assert scan_for_secret_leak("-----BEGIN OPENSSH PRIVATE KEY-----") is not None
    assert scan_for_secret_leak("postgresql://admin:SuperSecretPass99@db.example.internal:5432/prod") is not None

    db_file = tmp_path / "budget.db"
    env_path = tmp_path / ".env.fleet"
    env_lines = ["# Fleet Variables"] + [f"SERVICE_VAR_{i:02d}=secret_value_{i}" for i in range(15)]
    env_path.write_text("\n".join(env_lines) + "\n", encoding="utf-8")

    small_env = tmp_path / ".env.small"
    small_env.write_text(
        "# Small Env\nSMALL_ALPHA=val_a\nSMALL_OMEGA=val_b\n",
        encoding="utf-8",
    )

    other_doc = tmp_path / "secondary_notes.md"
    other_doc.write_text(
        "# Secondary Notes\nSERVICE_VAR_01 is referenced by the secondary worker daemon.\n",
        encoding="utf-8",
    )

    client = KruschFSClient(KruschFSConfig(db_url=f"sqlite:///{db_file}", embed_backend="deterministic"))
    set_client(client)
    client.scan_path(str(tmp_path))

    # 2. Pre-write Secret Shield blocks raw credential persistence in remember_on_page
    with pytest.raises(ValueError, match="Secret Shield blocked"):
        client.remember_on_page(
            file_path=str(other_doc),
            page_number=1,
            memory_content="Backup API token is sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
            quoted_sentence="SERVICE_VAR_01 is referenced by the secondary worker daemon.",
        )

    # Safe redacted note succeeds; pin 2 manual notes on .env.fleet
    client.remember_on_page(
        file_path=str(env_path),
        page_number=1,
        memory_content="Pinned note A: SERVICE_VAR_01=[REDACTED] controls primary worker.",
        quoted_sentence="SERVICE_VAR_01=[REDACTED]",
        category="annotation",
        memory_key="pinned_note_a",
    )
    client.remember_on_page(
        file_path=str(env_path),
        page_number=1,
        memory_content="Pinned note B: rotate SERVICE_VAR_02 quarterly.",
        quoted_sentence="SERVICE_VAR_02=[REDACTED]",
        category="annotation",
        memory_key="pinned_note_b",
    )

    # 3. read_page and get_page_tree return ALL 17 memories (15 auto + 2 pinned)
    full_page = client.read_page(str(env_path), page_number=1)
    assert len(full_page.memories) == 17
    full_tree = client.get_page_tree(str(env_path))
    assert full_tree.total_memories == 17

    # 4. search() bounds PageSearchHit.page_memories to ALL pinned (2) + at most Top-3 auto_extracted (<= 5 total)
    hits = client.search("SERVICE_VAR_01", limit=5)
    env_hit = next(h for h in hits if h.file_name == ".env.fleet")
    assert len(env_hit.page_memories) == 5
    mem_keys = {m.memory_key for m in env_hit.page_memories}
    assert "pinned_note_a" in mem_keys and "pinned_note_b" in mem_keys
    assert "SERVICE_VAR_01" in mem_keys

    # Also verify relevance sorting when 2 <= len(auto_mems) <= 3 (.env.small has 2 auto_extracted memories)
    small_hits = client.search("SMALL_OMEGA", limit=5)
    small_hit = next(h for h in small_hits if h.file_name == ".env.small")
    assert len(small_hit.page_memories) == 2
    assert small_hit.page_memories[0].memory_key == "SMALL_OMEGA"

    # 5. limit_tokens caps multi-hit payload while always returning >= 1 hit
    all_hits = client.search("SERVICE_VAR_01 secondary worker", limit=5)
    assert len(all_hits) >= 2
    tight_hits = client.search("SERVICE_VAR_01 secondary worker", limit=5, limit_tokens=50)
    assert len(tight_hits) == 1

    # 6. MCP krusch_fs_search exposes limit_tokens & unattested_query_terms, and MCP tool count == 6
    mcp_srv = get_mcp()
    tool_map = getattr(mcp_srv, "_tool_manager", None)
    if tool_map is not None and hasattr(tool_map, "_tools"):
        assert len(tool_map._tools) == 6

    mcp_res = json.loads(
        krusch_fs_search(
            query="SERVICE_VAR_01 nonexistent_quantum_token_xyz",
            limit=5,
            limit_tokens=500,
        )
    )
    assert mcp_res["status"] == "success"
    assert mcp_res["count"] >= 1
    assert "nonexistent_quantum_token_xyz" in mcp_res["unattested_query_terms"]
    assert "SERVICE_VAR_01" not in mcp_res["unattested_query_terms"]
    assert compute_unattested_query_terms("SERVICE_VAR_01", hits) == []
