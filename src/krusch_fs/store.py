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

import os
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    Float,
    String,
    Boolean,
    DateTime,
    Text,
    ForeignKey,
    UniqueConstraint,
    Index,
    event,
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from krusch_nexus.store import UniversalVector

Base = declarative_base()


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
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    file = relationship("FSFile", back_populates="memories")
    page = relationship("FSPage", back_populates="memories")


def create_db_session_factory(db_url: str):
    """Initialize SQLite WAL or PostgreSQL engine and create tables idempotently."""
    if db_url.startswith("sqlite:///"):
        db_path = db_url.replace("sqlite:///", "", 1)
        if db_path != ":memory:":
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
    return engine, sessionmaker(autocommit=False, autoflush=False, bind=engine)
