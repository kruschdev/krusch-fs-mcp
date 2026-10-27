"""
KruschFS Dual-Engine Relational & Page-Memory Store (store.py)
==============================================================
Supports SQLite WAL (zero-setup default) and PostgreSQL 16 + pgvector (`INV-8`).
Stores:
- `fs_watch_roots`: Configured OS watch directories mapped to 3-Zone Workspaces
- `fs_files`: Physical OS file pointers (inode, device_uuid, path, mtime, privacy_level, handoff_repo)
- `fs_pages`: 1-based KruschNexus pages with per-page SHA-256 (`page_hash`)
- `fs_chunks`: Page-grounded structural chunks with citations and vectors
- `page_memories`: Semantic/episodic/slot memories tied directly to `(file_id, page_number, anchor_page_hash)`
"""

import array
import json
import logging
import math
import os
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    Float,
    String,
    Boolean,
    DateTime,
    Text,
    LargeBinary,
    ForeignKey,
    UniqueConstraint,
    Index,
    event,
    text,
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

try:
    from krusch_nexus.store import UniversalVector
except ImportError:
    _nexus_candidates = [
        os.getenv("KRUSCH_NEXUS_PATH"),
        os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
            "krusch-nexus",
            "src",
        ),
        "/home/agent/homelab/projects/krusch-nexus/src",
        os.path.expanduser("~/homelab/projects/krusch-nexus/src"),
    ]
    for _cand in _nexus_candidates:
        if _cand and os.path.isdir(_cand) and _cand not in sys.path:
            sys.path.insert(0, _cand)
            break
    from krusch_nexus.store import UniversalVector

logger = logging.getLogger("krusch_fs.store")

Base = declarative_base()

_STRUCT_CACHE: Dict[int, struct.Struct] = {1024: struct.Struct("<1024f")}
_FTS5_TOKEN_RE = re.compile(r"[A-Za-z0-9_]{2,}")


def _get_float32_struct(dim: int) -> struct.Struct:
    compiled = _STRUCT_CACHE.get(dim)
    if compiled is None:
        compiled = struct.Struct(f"<{dim}f")
        _STRUCT_CACHE[dim] = compiled
    return compiled


def pack_float32_vector(vec: Optional[Sequence[float]], dim: int = 1024) -> Optional[bytes]:
    """
    Pack a finite numeric sequence into `dim * 4` little-endian IEEE-754 float32 bytes.
    Returns `None` if `vec` is missing, wrong dimension, or contains non-finite values.
    """
    if vec is None or dim <= 0 or isinstance(vec, (str, bytes, bytearray, memoryview)):
        return None
    try:
        if len(vec) != dim:
            return None
        floats = [float(v) for v in vec if not isinstance(v, bool)]
        if len(floats) != dim or not all(math.isfinite(v) for v in floats):
            return None
        return _get_float32_struct(dim).pack(*floats)
    except (TypeError, ValueError, OverflowError, struct.error):
        return None


def unpack_float32_vector(blob: Optional[bytes], dim: int = 1024) -> Optional[array.array]:
    """
    Unpack `dim * 4` little-endian IEEE-754 float32 bytes into `array.array('f')`.
    Returns `None` if `blob` is empty or does not match `dim * 4` bytes.
    """
    if not blob or dim <= 0 or not isinstance(blob, (bytes, bytearray, memoryview)):
        return None
    if len(blob) != dim * 4:
        return None
    raw = bytes(blob) if not isinstance(blob, bytes) else blob
    arr = array.array("f")
    if arr.itemsize != 4:
        return array.array("f", _get_float32_struct(dim).unpack(raw))
    arr.frombytes(raw)
    if sys.byteorder != "little":
        arr.byteswap()
    return arr


def resolve_stored_vector(
    embedding_blob: Optional[bytes],
    legacy_embedding: Any,
    row_embed_model: Optional[str],
    expected_model_tag: str,
    dim: int = 1024,
) -> Optional[Sequence[float]]:
    """
    Resolve a stored vector while enforcing strict model-space isolation (`INV-FS-VEC-01` & `INV-FS-BLOB-02`).
    Never mixes deterministic BLAKE2b hash vectors with neural Ollama vectors or incompatible models.
    """
    if dim <= 0 or not expected_model_tag:
        return None
    row_tag = row_embed_model.strip() if isinstance(row_embed_model, str) else ""
    if row_tag and row_tag != expected_model_tag:
        return None

    if isinstance(embedding_blob, (bytes, bytearray, memoryview)) and len(embedding_blob) == dim * 4:
        return unpack_float32_vector(bytes(embedding_blob), dim=dim)

    if legacy_embedding is not None:
        if row_tag == expected_model_tag or (
            not row_tag and expected_model_tag.startswith("deterministic:")
        ):
            legacy_vec: Any = legacy_embedding
            if isinstance(legacy_vec, str):
                try:
                    legacy_vec = json.loads(legacy_vec)
                except (json.JSONDecodeError, TypeError, ValueError):
                    return None
            if isinstance(legacy_vec, array.array) and legacy_vec.typecode == "f":
                if len(legacy_vec) == dim and all(math.isfinite(v) for v in legacy_vec):
                    return legacy_vec
                return None
            if isinstance(legacy_vec, (list, tuple)) or (
                hasattr(legacy_vec, "__len__")
                and hasattr(legacy_vec, "__iter__")
                and not isinstance(legacy_vec, (str, bytes, bytearray, memoryview, dict))
            ):
                try:
                    if len(legacy_vec) != dim:
                        return None
                    floats = [float(v) for v in legacy_vec if not isinstance(v, bool)]
                    if len(floats) != dim or not all(math.isfinite(v) for v in floats):
                        return None
                    return array.array("f", floats)
                except (TypeError, ValueError, OverflowError):
                    return None
    return None


def build_fts5_match_query(query_text: str) -> Optional[str]:
    """
    Build a safe SQLite FTS5 `MATCH` query from free-form text.
    Extracts alphanumeric/underscore tokens (`len >= 2`), expands underscore sub-tokens
    (e.g. `keep_alive` -> `"keep_alive" OR "keep" OR "alive"`), deduplicates preserving order,
    and caps at 16 tokens.
    """
    if not query_text:
        return None
    tokens: List[str] = []
    seen = set()
    for raw in _FTS5_TOKEN_RE.findall(query_text):
        tok = raw.lower().strip("_")
        if len(tok) >= 2 and tok not in seen:
            seen.add(tok)
            tokens.append(tok)
            if len(tokens) >= 16:
                break
        if "_" in tok:
            for sub in tok.split("_"):
                if len(sub) >= 2 and sub not in seen:
                    seen.add(sub)
                    tokens.append(sub)
                    if len(tokens) >= 16:
                        break
            if len(tokens) >= 16:
                break
    if not tokens:
        return None
    return " OR ".join(f'"{tok}"' for tok in tokens)


class FSWatchRoot(Base):
    """Registered OS directory root mapped to an isolated WorkspaceZone."""
    __tablename__ = "fs_watch_roots"
    __table_args__ = (
        UniqueConstraint("host_node", "root_path", name="uq_watch_host_root"),
    )

    id = Column(Integer, primary_key=True, index=True)
    host_node = Column(String(64), nullable=False, default="local", index=True)
    root_path = Column(String(1024), nullable=False, index=True)
    workspace = Column(String(64), nullable=False, default="user_docs", index=True)
    enabled = Column(Boolean, default=True, nullable=False)
    last_scanned_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class FSFile(Base):
    """In-place OS file pointer record (never duplicates raw file bytes into DB)."""
    __tablename__ = "fs_files"
    __table_args__ = (
        UniqueConstraint("host_node", "file_path", name="uq_fs_host_filepath"),
        Index("ix_fs_inode_lookup", "host_node", "device_id", "inode"),
        Index("ix_fs_workspace_hash", "workspace", "file_hash"),
    )

    id = Column(Integer, primary_key=True, index=True)
    host_node = Column(String(64), nullable=False, default="local", index=True)
    workspace = Column(String(64), nullable=False, default="user_docs", index=True)
    device_id = Column(String(64), nullable=False, default="0")
    inode = Column(Integer, nullable=False, default=0, index=True)
    file_path = Column(String(1024), nullable=False, index=True)
    parent_path = Column(String(1024), nullable=False, index=True)
    file_name = Column(String(512), nullable=False, index=True)
    extension = Column(String(32), nullable=False, default="", index=True)
    mime_type = Column(String(128), nullable=False, default="text/plain")
    size_bytes = Column(Integer, nullable=False, default=0)
    mtime = Column(Float, nullable=False, default=0.0, index=True)
    atime = Column(Float, nullable=False, default=0.0)
    file_hash = Column(String(64), nullable=False, index=True)
    total_pages = Column(Integer, nullable=False, default=1)
    privacy_level = Column(String(32), nullable=False, default="standard", index=True)
    handoff_repo = Column(String(255), nullable=True, index=True)  # Non-null if handed off to krusch-git
    is_deleted = Column(Boolean, default=False, nullable=False, index=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    pages = relationship("FSPage", back_populates="file", cascade="all, delete-orphan")
    chunks = relationship("FSChunk", back_populates="file", cascade="all, delete-orphan")
    memories = relationship("PageMemory", back_populates="file", cascade="all, delete-orphan")


class FSPage(Base):
    """
    1-based KruschNexus page ledger.
    Tracks per-page SHA-256 (`page_hash`) so single-page edits only re-index that page
    and only flag memories anchored to the modified page.
    """
    __tablename__ = "fs_pages"
    __table_args__ = (
        UniqueConstraint("file_id", "page_number", name="uq_fs_file_page_number"),
        Index("ix_fs_pages_file_page", "file_id", "page_number"),
    )

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("fs_files.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace = Column(String(64), nullable=False, default="user_docs", index=True)
    page_number = Column(Integer, nullable=False, index=True)  # 1-based physical or logical page
    printed_page = Column(String(64), nullable=True)
    page_hash = Column(String(64), nullable=False, index=True)  # SHA-256 of normalized page text
    section_header = Column(String(512), nullable=True)
    locator = Column(String(512), nullable=True)
    citation = Column(String(512), nullable=False)
    page_text = Column(Text, nullable=False, default="")
    blocks_json = Column(Text, nullable=True)  # JSON-serialized ContentBlock list with bbox
    char_count = Column(Integer, nullable=False, default=0)
    ocr_applied = Column(Boolean, default=False, nullable=False)
    ocr_confidence = Column(Float, nullable=True)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    file = relationship("FSFile", back_populates="pages")
    chunks = relationship("FSChunk", back_populates="page", cascade="all, delete-orphan")
    memories = relationship("PageMemory", back_populates="page")


class FSChunk(Base):
    """KruschNexus structure-aware chunk grounded to an exact `FSPage` (`page_number`)."""
    __tablename__ = "fs_chunks"
    __table_args__ = (
        Index("ix_fs_chunks_file_page", "file_id", "page_number"),
    )

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("fs_files.id", ondelete="CASCADE"), nullable=False, index=True)
    page_id = Column(Integer, ForeignKey("fs_pages.id", ondelete="CASCADE"), nullable=False, index=True)
    workspace = Column(String(64), nullable=False, default="user_docs", index=True)
    page_number = Column(Integer, nullable=False, index=True)
    printed_page = Column(String(64), nullable=True)
    chunk_index = Column(Integer, nullable=False, default=0)
    citation = Column(String(512), nullable=False)
    header = Column(String(512), nullable=True)
    locator = Column(String(512), nullable=True)
    content = Column(Text, nullable=False)
    source_hash = Column(String(64), nullable=False, index=True)
    char_start = Column(Integer, nullable=True)
    char_end = Column(Integer, nullable=True)
    bbox = Column(Text, nullable=True)  # JSON list [left, top, width, height]
    embedding = Column(UniversalVector(1024), nullable=True)
    embedding_blob = Column(LargeBinary, nullable=True)
    embed_model = Column(String(128), nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    file = relationship("FSFile", back_populates="chunks")
    page = relationship("FSPage", back_populates="chunks")


class PageMemory(Base):
    """
    Semantic, episodic, or slot memory directly tied to a specific page of an OS file.
    Carries `anchor_page_hash` and verbatim `quoted_sentence` (`INV-12` span grounding).
    """
    __tablename__ = "page_memories"
    __table_args__ = (
        Index("ix_page_memories_file_page", "file_id", "page_number"),
    )

    id = Column(Integer, primary_key=True, index=True)
    file_id = Column(Integer, ForeignKey("fs_files.id", ondelete="CASCADE"), nullable=False, index=True)
    page_id = Column(Integer, ForeignKey("fs_pages.id", ondelete="SET NULL"), nullable=True, index=True)
    workspace = Column(String(64), nullable=False, default="user_docs", index=True)
    page_number = Column(Integer, nullable=False, index=True)
    printed_page = Column(String(64), nullable=True)
    category = Column(String(32), nullable=False, default="fact", index=True)
    memory_key = Column(String(255), nullable=True, index=True)
    memory_content = Column(Text, nullable=False)
    quoted_sentence = Column(Text, nullable=False)
    citation = Column(String(512), nullable=False)
    locator = Column(String(512), nullable=True)
    bbox = Column(Text, nullable=True)  # JSON list [left, top, width, height]
    char_start = Column(Integer, nullable=True)
    char_end = Column(Integer, nullable=True)
    anchor_page_hash = Column(String(64), nullable=False, index=True)
    is_drifted = Column(Boolean, default=False, nullable=False, index=True)
    auto_extracted = Column(Boolean, default=False, nullable=False)
    embedding = Column(UniversalVector(1024), nullable=True)
    embedding_blob = Column(LargeBinary, nullable=True)
    embed_model = Column(String(128), nullable=True, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    file = relationship("FSFile", back_populates="memories")
    page = relationship("FSPage", back_populates="memories")


def _migrate_sqlite_schema_and_fts5(engine) -> bool:
    """
    Idempotently upgrade SQLite schemas (`embedding_blob`, `embed_model` + indexes)
    and provision external-content Porter FTS5 virtual tables, sync triggers, and backfill.
    """
    if getattr(engine.dialect, "name", "") != "sqlite":
        return False

    has_pages = False
    has_memories = False
    with engine.begin() as conn:
        chunk_cols = {
            row[1] for row in conn.execute(text("PRAGMA table_info(fs_chunks)")).fetchall()
        }
        if chunk_cols:
            if "embedding_blob" not in chunk_cols:
                conn.execute(text("ALTER TABLE fs_chunks ADD COLUMN embedding_blob BLOB"))
            if "embed_model" not in chunk_cols:
                conn.execute(text("ALTER TABLE fs_chunks ADD COLUMN embed_model VARCHAR(128)"))
            conn.execute(
                text("CREATE INDEX IF NOT EXISTS ix_fs_chunks_embed_model ON fs_chunks(embed_model)")
            )

        mem_cols = {
            row[1] for row in conn.execute(text("PRAGMA table_info(page_memories)")).fetchall()
        }
        if mem_cols:
            has_memories = True
            if "embedding_blob" not in mem_cols:
                conn.execute(text("ALTER TABLE page_memories ADD COLUMN embedding_blob BLOB"))
            if "embed_model" not in mem_cols:
                conn.execute(text("ALTER TABLE page_memories ADD COLUMN embed_model VARCHAR(128)"))
            conn.execute(
                text(
                    "CREATE INDEX IF NOT EXISTS ix_page_memories_embed_model ON page_memories(embed_model)"
                )
            )

        page_cols = {
            row[1] for row in conn.execute(text("PRAGMA table_info(fs_pages)")).fetchall()
        }
        if page_cols:
            has_pages = True

    try:
        with engine.begin() as conn:
            if has_pages:
                conn.execute(
                    text(
                        """
                        CREATE VIRTUAL TABLE IF NOT EXISTS fs_pages_fts USING fts5(
                            section_header,
                            locator,
                            citation,
                            page_text,
                            content='fs_pages',
                            content_rowid='id',
                            tokenize='porter unicode61'
                        )
                        """
                    )
                )
                conn.execute(
                    text(
                        """
                        CREATE TRIGGER IF NOT EXISTS fs_pages_fts_ai AFTER INSERT ON fs_pages BEGIN
                            INSERT INTO fs_pages_fts(rowid, section_header, locator, citation, page_text)
                            VALUES (new.id, new.section_header, new.locator, new.citation, new.page_text);
                        END
                        """
                    )
                )
                conn.execute(
                    text(
                        """
                        CREATE TRIGGER IF NOT EXISTS fs_pages_fts_ad AFTER DELETE ON fs_pages BEGIN
                            INSERT INTO fs_pages_fts(fs_pages_fts, rowid, section_header, locator, citation, page_text)
                            VALUES ('delete', old.id, old.section_header, old.locator, old.citation, old.page_text);
                        END
                        """
                    )
                )
                conn.execute(
                    text(
                        """
                        CREATE TRIGGER IF NOT EXISTS fs_pages_fts_au AFTER UPDATE ON fs_pages BEGIN
                            INSERT INTO fs_pages_fts(fs_pages_fts, rowid, section_header, locator, citation, page_text)
                            VALUES ('delete', old.id, old.section_header, old.locator, old.citation, old.page_text);
                            INSERT INTO fs_pages_fts(rowid, section_header, locator, citation, page_text)
                            VALUES (new.id, new.section_header, new.locator, new.citation, new.page_text);
                        END
                        """
                    )
                )
                pages_cnt = conn.execute(text("SELECT count(*) FROM fs_pages")).scalar() or 0
                fts_pages_cnt = (
                    conn.execute(text("SELECT count(*) FROM fs_pages_fts_docsize")).scalar() or 0
                )
                if pages_cnt > 0 and fts_pages_cnt == 0:
                    conn.execute(text("INSERT INTO fs_pages_fts(fs_pages_fts) VALUES('rebuild')"))

            if has_memories:
                conn.execute(
                    text(
                        """
                        CREATE VIRTUAL TABLE IF NOT EXISTS page_memories_fts USING fts5(
                            memory_key,
                            memory_content,
                            quoted_sentence,
                            locator,
                            content='page_memories',
                            content_rowid='id',
                            tokenize='porter unicode61'
                        )
                        """
                    )
                )
                conn.execute(
                    text(
                        """
                        CREATE TRIGGER IF NOT EXISTS page_memories_fts_ai AFTER INSERT ON page_memories BEGIN
                            INSERT INTO page_memories_fts(rowid, memory_key, memory_content, quoted_sentence, locator)
                            VALUES (new.id, new.memory_key, new.memory_content, new.quoted_sentence, new.locator);
                        END
                        """
                    )
                )
                conn.execute(
                    text(
                        """
                        CREATE TRIGGER IF NOT EXISTS page_memories_fts_ad AFTER DELETE ON page_memories BEGIN
                            INSERT INTO page_memories_fts(page_memories_fts, rowid, memory_key, memory_content, quoted_sentence, locator)
                            VALUES ('delete', old.id, old.memory_key, old.memory_content, old.quoted_sentence, old.locator);
                        END
                        """
                    )
                )
                conn.execute(
                    text(
                        """
                        CREATE TRIGGER IF NOT EXISTS page_memories_fts_au AFTER UPDATE ON page_memories BEGIN
                            INSERT INTO page_memories_fts(page_memories_fts, rowid, memory_key, memory_content, quoted_sentence, locator)
                            VALUES ('delete', old.id, old.memory_key, old.memory_content, old.quoted_sentence, old.locator);
                            INSERT INTO page_memories_fts(rowid, memory_key, memory_content, quoted_sentence, locator)
                            VALUES (new.id, new.memory_key, new.memory_content, new.quoted_sentence, new.locator);
                        END
                        """
                    )
                )
                mem_cnt = conn.execute(text("SELECT count(*) FROM page_memories")).scalar() or 0
                fts_mem_cnt = (
                    conn.execute(text("SELECT count(*) FROM page_memories_fts_docsize")).scalar() or 0
                )
                if mem_cnt > 0 and fts_mem_cnt == 0:
                    conn.execute(
                        text("INSERT INTO page_memories_fts(page_memories_fts) VALUES('rebuild')")
                    )
        return True
    except Exception as exc:
        logger.warning("SQLite FTS5 provisioning skipped or unavailable: %s", exc)
        return False


def migrate_sqlite_schema_and_fts5(engine) -> bool:
    """Public entrypoint for SQLite schema upgrade & external-content Porter FTS5 provisioning."""
    return _migrate_sqlite_schema_and_fts5(engine)


def create_db_session_factory(db_url: str):
    """Initialize SQLite WAL or PostgreSQL engine, create tables, and migrate SQLite FTS5/BLOB columns."""
    if db_url.startswith("sqlite"):
        if db_url.startswith("sqlite:///"):
            db_path = db_url.replace("sqlite:///", "", 1).split("?", 1)[0]
            if db_path and db_path != ":memory:" and not db_path.startswith("file:"):
                Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False, "timeout": 10.0},
        )

        @event.listens_for(engine, "connect")
        def _set_sqlite_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA journal_mode=WAL;")
            cursor.execute("PRAGMA synchronous=NORMAL;")
            cursor.execute("PRAGMA foreign_keys=ON;")
            cursor.execute("PRAGMA busy_timeout=10000;")
            cursor.close()
    else:
        engine = create_engine(db_url, pool_pre_ping=True)

    Base.metadata.create_all(bind=engine)
    if db_url.startswith("sqlite"):
        _migrate_sqlite_schema_and_fts5(engine)
    return engine, sessionmaker(autocommit=False, autoflush=False, bind=engine)
