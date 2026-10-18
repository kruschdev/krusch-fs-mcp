"""
KruschFS Core Engine & Multi-Node Fleet Client (client.py)
==========================================================
Implements:
1. In-place OS Pointer Indexing via KruschNexus (`parse_os_file_with_nexus` + `chunk_document_pages`)
2. Multi-Node Fleet SSH Streaming (`sync_fleet` / `scan_remote_node`) across configured fleet hosts
3. O(1) Inode Move / Rename Tracking (preserving `FSPage` and `PageMemory` records across moves)
4. Per-Page SHA-256 (`page_hash`) Delta Re-Indexing & Page-Granular Memory Drift Detection
5. Write-Through Page Memory Pinning (`remember_on_page`) with `INV-12` Verbatim Span Verification
6. Hybrid RRF Search (`page_memories` + `fs_chunks`) with Dual-Clock Recency Decay and `host_node` filtering
"""

import os
import re
import json
import math
import time
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Union

from krusch_nexus import chunk_document_pages, format_citation

from .models import (
    KruschFSConfig,
    WorkspaceZone,
    PrivacyLevel,
    PageMemoryItem,
    PageView,
    PageTreeNode,
    FilePageTree,
    PageSearchHit,
    FileLocationHit,
    SyncReport,
    FleetNodeSyncResult,
    FleetSyncReport,
)
from .store import (
    create_db_session_factory,
    FSWatchRoot,
    FSFile,
    FSPage,
    FSChunk,
    PageMemory,
)
from .shield import (
    compute_fast_file_hash,
    compute_page_hash,
    should_ignore_path,
    is_git_repo_root,
    classify_workspace_zone,
    classify_privacy_level,
    parse_os_file_with_nexus,
    parse_remote_text_with_nexus,
)
from .embeddings import embed_text, cosine_similarity
from .fleet import load_fleet_nodes, probe_node_ssh, stream_remote_node_entries

QUERY_TOKEN_RE = re.compile(r"[a-z0-9_\.\-]{2,}")


class KruschFSClient:
    """Canonical client for the KruschFS OS & Page-Anchored Memory engine."""

    def __init__(self, config: Optional[KruschFSConfig] = None):
        self.config = config or KruschFSConfig()
        self.engine, self.SessionLocal = create_db_session_factory(self.config.db_url)

    @classmethod
    def from_env(cls) -> "KruschFSClient":
        return cls(KruschFSConfig())

    def _embed(self, text: str) -> List[float]:
        return embed_text(
            text=text,
            backend=self.config.embed_backend,
            ollama_url=self.config.ollama_url,
            model=self.config.embed_model,
            dim=self.config.embed_dim,
        )

    @staticmethod
    def _memory_to_item(
        mem: PageMemory,
        file_path: str,
        current_page_hash: Optional[str] = None,
        host_node: str = "krusch",
    ) -> PageMemoryItem:
        bbox_val = None
        if mem.bbox:
            try:
                bbox_val = json.loads(mem.bbox) if isinstance(mem.bbox, str) else list(mem.bbox)
            except Exception:
                bbox_val = None
        return PageMemoryItem(
            id=mem.id,
            host_node=host_node,
            file_id=mem.file_id,
            file_path=file_path,
            workspace=mem.workspace,
            page_number=mem.page_number,
            printed_page=mem.printed_page,
            category=mem.category,
            memory_key=mem.memory_key,
            memory_content=mem.memory_content,
            quoted_sentence=mem.quoted_sentence,
            citation=mem.citation,
            locator=mem.locator,
            bbox=bbox_val,
            char_start=mem.char_start,
            char_end=mem.char_end,
            anchor_page_hash=mem.anchor_page_hash,
            current_page_hash=current_page_hash or mem.anchor_page_hash,
            is_drifted=bool(mem.is_drifted),
            created_at=mem.created_at.isoformat() if mem.created_at else None,
        )

    def _update_citations_on_rename(self, db, fs_file: FSFile, old_name: str, new_name: str):
        if old_name == new_name:
            return
        for p in db.query(FSPage).filter(FSPage.file_id == fs_file.id).all():
            if p.citation.startswith(old_name):
                p.citation = new_name + p.citation[len(old_name):]
            p.workspace = fs_file.workspace
        for c in db.query(FSChunk).filter(FSChunk.file_id == fs_file.id).all():
            if c.citation.startswith(old_name):
                c.citation = new_name + c.citation[len(old_name):]
            c.workspace = fs_file.workspace
        for m in db.query(PageMemory).filter(PageMemory.file_id == fs_file.id).all():
            if m.citation.startswith(old_name):
                m.citation = new_name + m.citation[len(old_name):]
            m.workspace = fs_file.workspace

    def _upsert_parsed_file_pages(
        self,
        db,
        node_name: str,
        abs_path: str,
        device_id: str,
        inode: int,
        size_bytes: int,
        mtime: float,
        atime: float,
        file_hash: str,
        privacy: PrivacyLevel,
        target_ws: str,
        handoff_repo: Optional[str],
        parsed_res,
        auto_slots: List[Dict[str, Any]],
        existing_by_path: Optional[FSFile],
        _report: Optional[SyncReport] = None,
    ) -> FSFile:
        file_name = os.path.basename(abs_path)
        parent_path = os.path.dirname(abs_path)
        ext = os.path.splitext(file_name)[1].lower()
        total_pages = max(1, len(parsed_res.pages))

        if existing_by_path is None:
            fs_file = FSFile(
                host_node=node_name,
                workspace=target_ws,
                device_id=device_id,
                inode=inode,
                file_path=abs_path,
                parent_path=parent_path,
                file_name=file_name,
                extension=ext,
                mime_type=parsed_res.detected_mime or parsed_res.mime,
                size_bytes=size_bytes,
                mtime=mtime,
                atime=atime,
                file_hash=file_hash,
                total_pages=total_pages,
                privacy_level=privacy.value,
                handoff_repo=handoff_repo,
                is_deleted=False,
            )
            db.add(fs_file)
            db.flush()
        else:
            fs_file = existing_by_path
            fs_file.workspace = target_ws
            fs_file.device_id = device_id
            fs_file.inode = inode
            fs_file.parent_path = parent_path
            fs_file.file_name = file_name
            fs_file.extension = ext
            fs_file.mime_type = parsed_res.detected_mime or parsed_res.mime
            fs_file.size_bytes = size_bytes
            fs_file.mtime = mtime
            fs_file.atime = atime
            fs_file.file_hash = file_hash
            fs_file.total_pages = total_pages
            fs_file.privacy_level = privacy.value
            if handoff_repo:
                fs_file.handoff_repo = handoff_repo
            fs_file.is_deleted = False
            fs_file.updated_at = datetime.now(timezone.utc)
            db.flush()

        existing_pages: Dict[int, FSPage] = {
            p.page_number: p
            for p in db.query(FSPage).filter(FSPage.file_id == fs_file.id).all()
        }
        seen_page_numbers = set()
        live_pages_by_num: Dict[int, FSPage] = {}
        changed_or_removed_pages = set()

        for page_idx, page_data in enumerate(parsed_res.pages, start=1):
            p_num = page_data.index or page_idx
            seen_page_numbers.add(p_num)
            p_hash = compute_page_hash(page_data.text)
            sec_hdr = page_data.locator or (
                page_data.structured_locator.header if page_data.structured_locator else f"Page {p_num}"
            )
            cit = format_citation(
                filename=file_name,
                page_number=p_num,
                pdf_page=page_data.pdf_page or p_num,
                printed_page=page_data.printed_page,
                locator=page_data.locator,
                header=sec_hdr,
            )
            blocks_payload = json.dumps([b.model_dump() for b in (page_data.blocks or [])])

            old_page = existing_pages.get(p_num)
            if old_page and old_page.page_hash == p_hash:
                live_pages_by_num[p_num] = old_page
                if _report is not None:
                    _report.pages_unchanged_skipped += 1
                continue

            changed_or_removed_pages.add(p_num)
            if old_page is None:
                fs_page = FSPage(
                    file_id=fs_file.id,
                    workspace=target_ws,
                    page_number=p_num,
                    printed_page=page_data.printed_page,
                    page_hash=p_hash,
                    section_header=sec_hdr,
                    locator=page_data.locator,
                    citation=cit,
                    page_text=page_data.text,
                    blocks_json=blocks_payload,
                    char_count=len(page_data.text or ""),
                    ocr_applied=bool(page_data.ocr_applied),
                    ocr_confidence=page_data.confidence,
                )
                db.add(fs_page)
                db.flush()
            else:
                fs_page = old_page
                fs_page.workspace = target_ws
                fs_page.printed_page = page_data.printed_page
                fs_page.page_hash = p_hash
                fs_page.section_header = sec_hdr
                fs_page.locator = page_data.locator
                fs_page.citation = cit
                fs_page.page_text = page_data.text
                fs_page.blocks_json = blocks_payload
                fs_page.char_count = len(page_data.text or "")
                fs_page.ocr_applied = bool(page_data.ocr_applied)
                fs_page.ocr_confidence = page_data.confidence
                fs_page.updated_at = datetime.now(timezone.utc)
                db.query(FSChunk).filter(FSChunk.page_id == fs_page.id).delete()
                db.query(PageMemory).filter(
                    PageMemory.file_id == fs_file.id,
                    PageMemory.page_number == p_num,
                    PageMemory.auto_extracted == True,  # noqa: E712
                ).delete()
                db.flush()

            live_pages_by_num[p_num] = fs_page

            if privacy not in (PrivacyLevel.VAULT_LOCKED,):
                nexus_chunks = chunk_document_pages(
                    pages=[page_data],
                    filename=file_name,
                    file_hash=file_hash,
                    max_chars=1800,
                    overlap_chars=150,
                )
                page_full_text = page_data.text or ""
                for c_idx, nc in enumerate(nexus_chunks):
                    c_cit = format_citation(
                        filename=file_name,
                        page_number=p_num,
                        pdf_page=nc.pdf_page or p_num,
                        printed_page=nc.printed_page or page_data.printed_page,
                        locator=nc.locator or page_data.locator,
                        header=nc.header or sec_hdr,
                    )
                    c_start = nc.char_start
                    c_end = nc.char_end
                    if (c_start is None or c_end is None) and nc.text and nc.text in page_full_text:
                        c_start = page_full_text.find(nc.text)
                        c_end = c_start + len(nc.text)
                    can_slice = (
                        c_start is not None
                        and c_end is not None
                        and page_full_text[c_start:c_end] == nc.text
                    )
                    db.add(
                        FSChunk(
                            file_id=fs_file.id,
                            page_id=fs_page.id,
                            workspace=target_ws,
                            page_number=p_num,
                            printed_page=nc.printed_page or page_data.printed_page,
                            chunk_index=c_idx,
                            citation=c_cit,
                            header=nc.header or sec_hdr,
                            locator=nc.locator or page_data.locator,
                            content="" if can_slice else nc.text,
                            source_hash=nc.source_hash,
                            char_start=c_start,
                            char_end=c_end,
                            bbox=json.dumps(nc.bbox) if nc.bbox else None,
                            embedding=self._embed(f"{sec_hdr or ''} {nc.text}"),
                        )
                    )
            if _report is not None:
                _report.pages_indexed += 1

            page_slots = [s for s in auto_slots if s.get("page_number") == p_num]
            for slot in page_slots:
                db.add(
                    PageMemory(
                        file_id=fs_file.id,
                        page_id=fs_page.id,
                        workspace=target_ws,
                        page_number=p_num,
                        printed_page=page_data.printed_page,
                        category=slot.get("category", "slot"),
                        memory_key=slot.get("memory_key"),
                        memory_content=slot["memory_content"],
                        quoted_sentence=slot["quoted_sentence"],
                        citation=cit,
                        locator=slot.get("locator") or page_data.locator,
                        char_start=slot.get("char_start", 0),
                        char_end=slot.get("char_end", len(slot["quoted_sentence"])),
                        anchor_page_hash=p_hash,
                        is_drifted=False,
                        auto_extracted=True,
                        embedding=self._embed(
                            f"{slot.get('memory_key', '')} {slot['memory_content']} {slot['quoted_sentence']}"
                        ),
                    )
                )
                if _report is not None:
                    _report.memories_auto_extracted += 1

        for old_p_num, old_p in existing_pages.items():
            if old_p_num not in seen_page_numbers:
                changed_or_removed_pages.add(old_p_num)
                db.query(PageMemory).filter(
                    PageMemory.file_id == fs_file.id,
                    PageMemory.page_number == old_p_num,
                    PageMemory.auto_extracted == True,  # noqa: E712
                ).delete()
                db.delete(old_p)
        db.flush()

        # Reconcile pinned PageMemory anchors:
        # 1) Same-page re-anchoring (if quote still exists on mem.page_number)
        # 2) Cross-page relocation ("same text, new page" when insertions/deletions shift pages)
        # 3) True content drift (STALE_DRIFT only when quoted_sentence no longer exists on any page)
        if changed_or_removed_pages:
            pinned_memories = (
                db.query(PageMemory)
                .filter(
                    PageMemory.file_id == fs_file.id,
                    PageMemory.auto_extracted == False,  # noqa: E712
                )
                .all()
            )
            for mem in pinned_memories:
                if mem.page_number not in changed_or_removed_pages and not mem.is_drifted:
                    continue

                curr_page = live_pages_by_num.get(mem.page_number)
                if curr_page is not None and mem.quoted_sentence and mem.quoted_sentence in (curr_page.page_text or ""):
                    pos = curr_page.page_text.find(mem.quoted_sentence)
                    mem.page_id = curr_page.id
                    mem.printed_page = curr_page.printed_page
                    mem.citation = curr_page.citation
                    mem.locator = curr_page.locator
                    mem.anchor_page_hash = curr_page.page_hash
                    mem.char_start = pos
                    mem.char_end = pos + len(mem.quoted_sentence)
                    mem.is_drifted = False
                    continue

                relocated = False
                if mem.quoted_sentence:
                    candidate_pages = sorted(
                        (p for p_num, p in live_pages_by_num.items() if p_num != mem.page_number),
                        key=lambda p: (abs(p.page_number - mem.page_number), p.page_number),
                    )
                    for cand_page in candidate_pages:
                        cand_text = cand_page.page_text or ""
                        if mem.quoted_sentence in cand_text:
                            pos = cand_text.find(mem.quoted_sentence)
                            mem.page_id = cand_page.id
                            mem.page_number = cand_page.page_number
                            mem.printed_page = cand_page.printed_page
                            mem.citation = cand_page.citation
                            mem.locator = cand_page.locator
                            mem.anchor_page_hash = cand_page.page_hash
                            mem.char_start = pos
                            mem.char_end = pos + len(mem.quoted_sentence)
                            mem.is_drifted = False
                            if _report is not None:
                                _report.memories_relocated += 1
                            relocated = True
                            break

                if not relocated:
                    if curr_page is None:
                        mem.page_id = None
                    mem.is_drifted = True
                    if _report is not None:
                        _report.memories_flagged_drifted += 1

        db.commit()
        db.refresh(fs_file)
        if _report is not None:
            _report.files_indexed += 1
        return fs_file

    def index_file(
        self,
        file_path: str,
        workspace: Optional[str] = None,
        handoff_repo: Optional[str] = None,
        host_node: Optional[str] = None,
        _report: Optional[SyncReport] = None,
    ) -> Optional[FSFile]:
        """Index or incrementally update a local OS file in-place."""
        node_name = host_node or self.config.host_node
        abs_path = os.path.abspath(os.path.expanduser(file_path))
        if not os.path.isfile(abs_path):
            return None

        st = os.stat(abs_path)
        size_bytes = int(st.st_size)
        inode = int(st.st_ino)
        device_id = str(st.st_dev)
        mtime = float(st.st_mtime)
        atime = float(st.st_atime)
        file_name = os.path.basename(abs_path)
        parent_path = os.path.dirname(abs_path)
        ext = os.path.splitext(file_name)[1].lower()

        target_ws = (
            WorkspaceZone.REPO_BOUNDARIES.value
            if handoff_repo
            else classify_workspace_zone(abs_path, workspace)
        )
        privacy = classify_privacy_level(abs_path, size_bytes, self.config.max_parse_bytes)

        if privacy == PrivacyLevel.VAULT_LOCKED:
            file_hash = f"vault_locked:{inode}:{size_bytes}:{int(mtime)}"
        else:
            file_hash = compute_fast_file_hash(abs_path, size_bytes)

        db = self.SessionLocal()
        try:
            existing_by_path = (
                db.query(FSFile)
                .filter(FSFile.host_node == node_name, FSFile.file_path == abs_path)
                .first()
            )

            if existing_by_path and existing_by_path.file_hash == file_hash and not existing_by_path.is_deleted:
                existing_by_path.atime = atime
                if handoff_repo and not existing_by_path.handoff_repo:
                    existing_by_path.handoff_repo = handoff_repo
                db.commit()
                db.refresh(existing_by_path)
                if _report is not None:
                    _report.files_unchanged += 1
                return existing_by_path

            if existing_by_path is None and inode > 0:
                moved_candidate = (
                    db.query(FSFile)
                    .filter(
                        FSFile.host_node == node_name,
                        FSFile.device_id == device_id,
                        FSFile.inode == inode,
                        FSFile.file_hash == file_hash,
                    )
                    .first()
                )
                if moved_candidate and not os.path.exists(moved_candidate.file_path):
                    old_name = moved_candidate.file_name
                    moved_candidate.file_path = abs_path
                    moved_candidate.parent_path = parent_path
                    moved_candidate.file_name = file_name
                    moved_candidate.extension = ext
                    moved_candidate.workspace = target_ws
                    moved_candidate.mtime = mtime
                    moved_candidate.atime = atime
                    moved_candidate.is_deleted = False
                    moved_candidate.updated_at = datetime.now(timezone.utc)
                    self._update_citations_on_rename(db, moved_candidate, old_name, file_name)
                    db.commit()
                    db.refresh(moved_candidate)
                    if _report is not None:
                        _report.files_moved_in_place += 1
                    return moved_candidate

            if privacy == PrivacyLevel.VAULT_LOCKED and _report is not None:
                _report.vault_locked_skipped += 1

            parsed_res, auto_slots = parse_os_file_with_nexus(abs_path, privacy, file_hash)
            return self._upsert_parsed_file_pages(
                db=db,
                node_name=node_name,
                abs_path=abs_path,
                device_id=device_id,
                inode=inode,
                size_bytes=size_bytes,
                mtime=mtime,
                atime=atime,
                file_hash=file_hash,
                privacy=privacy,
                target_ws=target_ws,
                handoff_repo=handoff_repo,
                parsed_res=parsed_res,
                auto_slots=auto_slots,
                existing_by_path=existing_by_path,
                _report=_report,
            )
        finally:
            db.close()

    def index_remote_entry(
        self,
        host_node: str,
        entry: Dict[str, Any],
        workspace: Optional[str] = None,
        _report: Optional[SyncReport] = None,
    ) -> Optional[FSFile]:
        """Index a file entry streamed over SSH from a remote fleet node (`compute-node-01`, `storage-node-01`, etc.)."""
        abs_path = entry["file_path"]
        device_id = str(entry.get("device_id", "0"))
        inode = int(entry.get("inode", 0))
        size_bytes = int(entry.get("size_bytes", 0))
        mtime = float(entry.get("mtime", 0.0))
        atime = float(entry.get("atime", mtime))
        file_hash = str(entry["file_hash"])
        handoff_repo = entry.get("handoff_repo")
        priv_str = entry.get("privacy_level", "standard")
        privacy = PrivacyLevel(priv_str) if priv_str in [p.value for p in PrivacyLevel] else PrivacyLevel.STANDARD
        target_ws = (
            WorkspaceZone.REPO_BOUNDARIES.value
            if handoff_repo
            else classify_workspace_zone(abs_path, workspace)
        )

        db = self.SessionLocal()
        try:
            existing_by_path = (
                db.query(FSFile)
                .filter(FSFile.host_node == host_node, FSFile.file_path == abs_path)
                .first()
            )
            if (entry.get("unchanged") or (existing_by_path and existing_by_path.file_hash == file_hash)) and existing_by_path:
                existing_by_path.atime = atime
                db.commit()
                if _report is not None:
                    _report.files_unchanged += 1
                return existing_by_path

            if existing_by_path is None and inode > 0:
                moved_candidate = (
                    db.query(FSFile)
                    .filter(
                        FSFile.host_node == host_node,
                        FSFile.device_id == device_id,
                        FSFile.inode == inode,
                        FSFile.file_hash == file_hash,
                    )
                    .first()
                )
                if moved_candidate:
                    old_name = moved_candidate.file_name
                    new_name = os.path.basename(abs_path)
                    moved_candidate.file_path = abs_path
                    moved_candidate.parent_path = os.path.dirname(abs_path)
                    moved_candidate.file_name = new_name
                    moved_candidate.extension = os.path.splitext(new_name)[1].lower()
                    moved_candidate.workspace = target_ws
                    moved_candidate.mtime = mtime
                    moved_candidate.atime = atime
                    moved_candidate.is_deleted = False
                    moved_candidate.updated_at = datetime.now(timezone.utc)
                    self._update_citations_on_rename(db, moved_candidate, old_name, new_name)
                    db.commit()
                    if _report is not None:
                        _report.files_moved_in_place += 1
                    return moved_candidate

            if privacy == PrivacyLevel.VAULT_LOCKED and _report is not None:
                _report.vault_locked_skipped += 1
            if handoff_repo and _report is not None:
                _report.repo_boundaries_handed_off += 1

            parsed_res, auto_slots = parse_remote_text_with_nexus(
                file_path=abs_path,
                text_content=entry.get("text_content"),
                privacy_level=privacy,
                file_hash=file_hash,
                size_bytes=size_bytes,
            )
            return self._upsert_parsed_file_pages(
                db=db,
                node_name=host_node,
                abs_path=abs_path,
                device_id=device_id,
                inode=inode,
                size_bytes=size_bytes,
                mtime=mtime,
                atime=atime,
                file_hash=file_hash,
                privacy=privacy,
                target_ws=target_ws,
                handoff_repo=handoff_repo,
                parsed_res=parsed_res,
                auto_slots=auto_slots,
                existing_by_path=existing_by_path,
                _report=_report,
            )
        finally:
            db.close()

    def scan_path(
        self,
        target_path: str,
        workspace: Optional[str] = None,
        register_watch_root: bool = True,
        host_node: Optional[str] = None,
    ) -> SyncReport:
        """Scan a local or remote directory/file into KruschFS."""
        node_name = host_node or self.config.host_node
        fleet_map = load_fleet_nodes()
        if node_name != self.config.host_node and node_name in fleet_map and not fleet_map[node_name].get("local"):
            return self.scan_remote_node(node_name, roots=[target_path], workspace=workspace)

        t0 = time.perf_counter()
        abs_root = os.path.abspath(os.path.expanduser(target_path))
        report = SyncReport(host_node=node_name, scanned_paths=[abs_root])

        if not os.path.exists(abs_root):
            raise FileNotFoundError(f"Path not found: {abs_root}")

        if os.path.isfile(abs_root):
            report.files_discovered = 1
            self.index_file(abs_root, workspace=workspace, host_node=node_name, _report=report)
            report.duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)
            return report

        if register_watch_root:
            db = self.SessionLocal()
            try:
                ws_zone = classify_workspace_zone(abs_root, workspace)
                wr = (
                    db.query(FSWatchRoot)
                    .filter(FSWatchRoot.host_node == node_name, FSWatchRoot.root_path == abs_root)
                    .first()
                )
                if wr is None:
                    wr = FSWatchRoot(
                        host_node=node_name,
                        root_path=abs_root,
                        workspace=ws_zone,
                        enabled=True,
                        last_scanned_at=datetime.now(timezone.utc),
                    )
                    db.add(wr)
                else:
                    wr.last_scanned_at = datetime.now(timezone.utc)
                    if workspace:
                        wr.workspace = workspace
                db.commit()
            finally:
                db.close()

        for current_dir, dirnames, filenames in os.walk(abs_root, topdown=True):
            dirnames[:] = [
                d
                for d in sorted(dirnames)
                if d not in (".git", "node_modules", ".venv", "venv", "__pycache__", ".cache", ".ingested")
                and not should_ignore_path(os.path.join(current_dir, d))
            ]

            if is_git_repo_root(current_dir):
                repo_name = os.path.basename(current_dir)
                report.repo_boundaries_handed_off += 1
                for doc_candidate in ("README.md", "AGENTS.md"):
                    candidate_path = os.path.join(current_dir, doc_candidate)
                    if os.path.isfile(candidate_path):
                        report.files_discovered += 1
                        self.index_file(
                            candidate_path,
                            workspace=WorkspaceZone.REPO_BOUNDARIES.value,
                            handoff_repo=repo_name,
                            host_node=node_name,
                            _report=report,
                        )
                env_dirs = [current_dir]
                projects_sub = os.path.join(current_dir, "projects")
                if os.path.isdir(projects_sub):
                    try:
                        for sub in sorted(os.listdir(projects_sub)):
                            sub_p = os.path.join(projects_sub, sub)
                            if os.path.isdir(sub_p):
                                env_dirs.append(sub_p)
                    except Exception:
                        pass
                for ed in env_dirs:
                    try:
                        for fn in sorted(os.listdir(ed)):
                            low = fn.lower()
                            if low == ".env" or low.startswith(".env.") or low.endswith(".env"):
                                ep = os.path.join(ed, fn)
                                if os.path.isfile(ep) and not os.path.islink(ep):
                                    report.files_discovered += 1
                                    self.index_file(
                                        ep,
                                        workspace=WorkspaceZone.SYSTEM_CONFIG.value,
                                        host_node=node_name,
                                        _report=report,
                                    )
                    except Exception:
                        pass
                dirnames[:] = []
                continue

            for fname in sorted(filenames):
                fpath = os.path.join(current_dir, fname)
                if should_ignore_path(fpath) or os.path.islink(fpath):
                    continue
                report.files_discovered += 1
                self.index_file(fpath, workspace=workspace, host_node=node_name, _report=report)

        report.duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        return report

    def scan_remote_node(
        self,
        node_name: str,
        roots: Optional[List[str]] = None,
        workspace: Optional[str] = None,
        ssh_target_override: Optional[str] = None,
    ) -> SyncReport:
        """Scan a remote computer on the fleet over SSH and index its pages into KruschFS."""
        t0 = time.perf_counter()
        fleet_map = load_fleet_nodes()
        node_cfg = fleet_map.get(node_name, {})
        target_roots = [
            os.path.expanduser(r) if r.startswith("~") else r
            for r in (roots or node_cfg.get("default_roots", ["/etc/systemd/system", "/etc/fstab"]))
        ]
        report = SyncReport(host_node=node_name, scanned_paths=target_roots)

        ssh_target = ssh_target_override or probe_node_ssh(node_name, fleet_map=fleet_map)
        if not ssh_target:
            raise ConnectionError(f"Fleet node '{node_name}' is unreachable over SSH.")

        db = self.SessionLocal()
        try:
            known_hashes = {
                f.file_path: f.file_hash
                for f in db.query(FSFile).filter(FSFile.host_node == node_name, FSFile.is_deleted == False).all()  # noqa: E712
            }
            for r_path in target_roots:
                ws_zone = classify_workspace_zone(r_path, workspace)
                wr = (
                    db.query(FSWatchRoot)
                    .filter(FSWatchRoot.host_node == node_name, FSWatchRoot.root_path == r_path)
                    .first()
                )
                if wr is None:
                    db.add(
                        FSWatchRoot(
                            host_node=node_name,
                            root_path=r_path,
                            workspace=ws_zone,
                            enabled=True,
                            last_scanned_at=datetime.now(timezone.utc),
                        )
                    )
                else:
                    wr.last_scanned_at = datetime.now(timezone.utc)
            db.commit()
        finally:
            db.close()

        entries = stream_remote_node_entries(
            ssh_target=ssh_target,
            roots=target_roots,
            known_hashes=known_hashes,
        )
        report.files_discovered = len(entries)
        for entry in entries:
            self.index_remote_entry(
                host_node=node_name,
                entry=entry,
                workspace=workspace,
                _report=report,
            )

        report.duration_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        return report

    def sync_fleet(self, nodes: Optional[List[str]] = None) -> FleetSyncReport:
        """
        Synchronize all computers configured in `~/.krusch-fs/fleet.json` (or the local workstation).
        Online nodes are indexed immediately; sleeping/offline edge nodes are skipped in <2s.
        """
        t0 = time.perf_counter()
        fleet_map = load_fleet_nodes()
        target_nodes = nodes or list(fleet_map.keys())
        node_results: List[FleetNodeSyncResult] = []

        total_files = 0
        total_pages = 0
        total_memories = 0
        online_cnt = 0
        offline_cnt = 0

        for node_name in target_nodes:
            cfg = fleet_map.get(node_name)
            if not cfg:
                node_results.append(
                    FleetNodeSyncResult(
                        host_node=node_name,
                        role="Unknown Node",
                        status="error",
                        error=f"Node '{node_name}' is not in configured fleet registry.",
                    )
                )
                continue

            if cfg.get("local"):
                combined = SyncReport(host_node=node_name, scanned_paths=[])
                for r_path in cfg.get("default_roots", []):
                    exp_path = os.path.expanduser(r_path)
                    if os.path.exists(exp_path):
                        sub = self.scan_path(exp_path, host_node=node_name)
                        combined.scanned_paths.extend(sub.scanned_paths)
                        combined.files_discovered += sub.files_discovered
                        combined.files_indexed += sub.files_indexed
                        combined.files_moved_in_place += sub.files_moved_in_place
                        combined.files_unchanged += sub.files_unchanged
                        combined.pages_indexed += sub.pages_indexed
                        combined.pages_unchanged_skipped += sub.pages_unchanged_skipped
                        combined.memories_auto_extracted += sub.memories_auto_extracted
                        combined.memories_flagged_drifted += sub.memories_flagged_drifted
                        combined.repo_boundaries_handed_off += sub.repo_boundaries_handed_off
                        combined.vault_locked_skipped += sub.vault_locked_skipped
                        combined.duration_ms = round(combined.duration_ms + sub.duration_ms, 2)
                online_cnt += 1
                total_files += combined.files_indexed
                total_pages += combined.pages_indexed
                total_memories += combined.memories_auto_extracted
                node_results.append(
                    FleetNodeSyncResult(
                        host_node=node_name,
                        role=cfg["role"],
                        status="indexed",
                        ssh_target="local",
                        report=combined,
                    )
                )
            else:
                ssh_target = probe_node_ssh(node_name, fleet_map=fleet_map)
                if not ssh_target:
                    offline_cnt += 1
                    node_results.append(
                        FleetNodeSyncResult(
                            host_node=node_name,
                            role=cfg["role"],
                            status="offline_skipped",
                            ssh_target=None,
                        )
                    )
                    continue
                try:
                    rep = self.scan_remote_node(node_name, ssh_target_override=ssh_target)
                    online_cnt += 1
                    total_files += rep.files_indexed
                    total_pages += rep.pages_indexed
                    total_memories += rep.memories_auto_extracted
                    node_results.append(
                        FleetNodeSyncResult(
                            host_node=node_name,
                            role=cfg["role"],
                            status="indexed",
                            ssh_target=ssh_target,
                            report=rep,
                        )
                    )
                except Exception as e:
                    node_results.append(
                        FleetNodeSyncResult(
                            host_node=node_name,
                            role=cfg["role"],
                            status="error",
                            ssh_target=ssh_target,
                            error=str(e),
                        )
                    )

        return FleetSyncReport(
            total_nodes_configured=len(target_nodes),
            nodes_online_indexed=online_cnt,
            nodes_offline_skipped=offline_cnt,
            total_files_indexed=total_files,
            total_pages_indexed=total_pages,
            total_memories_extracted=total_memories,
            duration_ms=round((time.perf_counter() - t0) * 1000.0, 2),
            nodes=node_results,
        )

    def remember_on_page(
        self,
        file_path: str,
        page_number: int,
        memory_content: str,
        quoted_sentence: str,
        category: str = "fact",
        memory_key: Optional[str] = None,
        host_node: Optional[str] = None,
    ) -> PageMemoryItem:
        """Write-Through Page Memory Anchor (`krusch_fs_remember_on_page`) across local or remote fleet files."""
        node_name = host_node or self.config.host_node
        abs_path = os.path.abspath(os.path.expanduser(file_path)) if node_name == self.config.host_node else file_path

        if node_name == self.config.host_node and os.path.isfile(abs_path):
            self.index_file(abs_path, host_node=node_name)

        clean_quote = (quoted_sentence or "").strip()
        if not clean_quote:
            raise ValueError("quoted_sentence is required to anchor a memory to a specific page (INV-12).")

        db = self.SessionLocal()
        try:
            fs_file = (
                db.query(FSFile)
                .filter(FSFile.host_node == node_name, FSFile.file_path == abs_path)
                .first()
            )
            if not fs_file:
                raise FileNotFoundError(f"File not found in KruschFS index for node '{node_name}': {abs_path}")

            fs_page = (
                db.query(FSPage)
                .filter(FSPage.file_id == fs_file.id, FSPage.page_number == int(page_number))
                .first()
            )
            if not fs_page:
                raise ValueError(
                    f"Page {page_number} does not exist in {fs_file.file_name} (total_pages={fs_file.total_pages})."
                )

            page_text = fs_page.page_text or ""
            pos = page_text.find(clean_quote)
            if pos < 0:
                norm_pattern = re.sub(r"\s+", r"\\s+", re.escape(clean_quote))
                m = re.search(norm_pattern, page_text, flags=re.IGNORECASE)
                if not m:
                    raise ValueError(
                        f"Span grounding failed (INV-12): quoted_sentence '{clean_quote[:80]}' "
                        f"was not found on page {page_number} of {fs_file.file_name}."
                    )
                pos = m.start()
                end_pos = m.end()
                matched_verbatim = page_text[pos:end_pos]
            else:
                end_pos = pos + len(clean_quote)
                matched_verbatim = clean_quote

            matched_bbox = None
            if fs_page.blocks_json:
                try:
                    blocks = json.loads(fs_page.blocks_json)
                    for b in blocks:
                        b_text = b.get("text", "")
                        if matched_verbatim in b_text and b.get("bbox"):
                            matched_bbox = b["bbox"]
                            break
                except Exception:
                    matched_bbox = None

            mem = PageMemory(
                file_id=fs_file.id,
                page_id=fs_page.id,
                workspace=fs_file.workspace,
                page_number=fs_page.page_number,
                printed_page=fs_page.printed_page,
                category=category,
                memory_key=memory_key,
                memory_content=memory_content.strip(),
                quoted_sentence=matched_verbatim,
                citation=fs_page.citation,
                locator=fs_page.locator or fs_page.section_header,
                bbox=json.dumps(matched_bbox) if matched_bbox else None,
                char_start=pos,
                char_end=end_pos,
                anchor_page_hash=fs_page.page_hash,
                is_drifted=False,
                auto_extracted=False,
                embedding=self._embed(f"{memory_key or ''} {memory_content} {matched_verbatim}"),
            )
            db.add(mem)
            db.commit()
            db.refresh(mem)
            return self._memory_to_item(mem, fs_file.file_path, fs_page.page_hash, fs_file.host_node)
        finally:
            db.close()

    def get_page_tree(self, file_path: str, host_node: Optional[str] = None) -> FilePageTree:
        """Return the PageIndex Table of Contents tree (`krusch_fs_page_tree`) for a local or remote fleet file."""
        node_name = host_node or self.config.host_node
        abs_path = os.path.abspath(os.path.expanduser(file_path)) if node_name == self.config.host_node else file_path
        if node_name == self.config.host_node and os.path.isfile(abs_path):
            self.index_file(abs_path, host_node=node_name)

        db = self.SessionLocal()
        try:
            fs_file = (
                db.query(FSFile)
                .filter(FSFile.host_node == node_name, FSFile.file_path == abs_path)
                .first()
            )
            if not fs_file:
                raise FileNotFoundError(f"File not found in KruschFS index for node '{node_name}': {abs_path}")

            pages = (
                db.query(FSPage)
                .filter(FSPage.file_id == fs_file.id)
                .order_by(FSPage.page_number.asc())
                .all()
            )
            all_memories = (
                db.query(PageMemory)
                .filter(PageMemory.file_id == fs_file.id)
                .order_by(PageMemory.page_number.asc(), PageMemory.id.asc())
                .all()
            )
            mem_by_page: Dict[int, List[PageMemory]] = {}
            for m in all_memories:
                mem_by_page.setdefault(m.page_number, []).append(m)

            nodes: List[PageTreeNode] = []
            for p in pages:
                p_mems = [
                    self._memory_to_item(m, fs_file.file_path, p.page_hash, fs_file.host_node)
                    for m in mem_by_page.get(p.page_number, [])
                ]
                drifted_cnt = sum(1 for m in p_mems if m.is_drifted)
                preview_text = " ".join((p.page_text or "").strip().split())[:200]
                nodes.append(
                    PageTreeNode(
                        page_number=p.page_number,
                        printed_page=p.printed_page,
                        section_header=p.section_header or f"Page {p.page_number}",
                        locator=p.locator,
                        page_hash=p.page_hash,
                        char_count=p.char_count,
                        memory_count=len(p_mems),
                        drifted_memory_count=drifted_cnt,
                        preview=preview_text,
                        memories=p_mems,
                    )
                )

            return FilePageTree(
                host_node=fs_file.host_node,
                file_id=fs_file.id,
                file_path=fs_file.file_path,
                file_name=fs_file.file_name,
                workspace=fs_file.workspace,
                mime_type=fs_file.mime_type,
                total_pages=fs_file.total_pages,
                total_memories=len(all_memories),
                privacy_level=fs_file.privacy_level,
                handoff_repo=fs_file.handoff_repo,
                pages=nodes,
            )
        finally:
            db.close()

    def read_page(
        self,
        file_path: str,
        page_number: int = 1,
        end_page: Optional[int] = None,
        host_node: Optional[str] = None,
    ) -> Union[PageView, List[PageView]]:
        """Hydrate a single page (or page range) of a local or remote fleet file (`krusch_fs_read_page`)."""
        node_name = host_node or self.config.host_node
        abs_path = os.path.abspath(os.path.expanduser(file_path)) if node_name == self.config.host_node else file_path
        if node_name == self.config.host_node and os.path.isfile(abs_path):
            self.index_file(abs_path, host_node=node_name)

        db = self.SessionLocal()
        try:
            fs_file = (
                db.query(FSFile)
                .filter(FSFile.host_node == node_name, FSFile.file_path == abs_path)
                .first()
            )
            if not fs_file:
                raise FileNotFoundError(f"File not found in KruschFS index for node '{node_name}': {abs_path}")

            target_end = int(end_page) if end_page is not None else int(page_number)
            pages = (
                db.query(FSPage)
                .filter(
                    FSPage.file_id == fs_file.id,
                    FSPage.page_number >= int(page_number),
                    FSPage.page_number <= target_end,
                )
                .order_by(FSPage.page_number.asc())
                .all()
            )
            if not pages:
                raise ValueError(
                    f"Requested page {page_number} out of range for {fs_file.file_name} (1..{fs_file.total_pages})."
                )

            views: List[PageView] = []
            for p in pages:
                mems = (
                    db.query(PageMemory)
                    .filter(PageMemory.file_id == fs_file.id, PageMemory.page_number == p.page_number)
                    .order_by(PageMemory.id.asc())
                    .all()
                )
                blocks_list = []
                if p.blocks_json:
                    try:
                        blocks_list = json.loads(p.blocks_json)
                    except Exception:
                        blocks_list = []
                views.append(
                    PageView(
                        host_node=fs_file.host_node,
                        file_id=fs_file.id,
                        file_path=fs_file.file_path,
                        file_name=fs_file.file_name,
                        workspace=fs_file.workspace,
                        page_number=p.page_number,
                        total_pages=fs_file.total_pages,
                        printed_page=p.printed_page,
                        page_hash=p.page_hash,
                        section_header=p.section_header,
                        locator=p.locator,
                        citation=p.citation,
                        text=p.page_text,
                        ocr_applied=bool(p.ocr_applied),
                        ocr_confidence=p.ocr_confidence,
                        blocks=blocks_list,
                        memories=[
                            self._memory_to_item(m, fs_file.file_path, p.page_hash, fs_file.host_node) for m in mems
                        ],
                        privacy_level=fs_file.privacy_level,
                        handoff_repo=fs_file.handoff_repo,
                    )
                )

            return views[0] if end_page is None else views
        finally:
            db.close()

    def search(
        self,
        query: str,
        workspace: Optional[str] = None,
        path_prefix: Optional[str] = None,
        category: Optional[str] = None,
        host_node: Optional[str] = None,
        include_memories: bool = True,
        limit: int = 5,
        node: Optional[str] = None,
        top_k: Optional[int] = None,
    ) -> List[PageSearchHit]:
        """
        Hybrid RRF Search (`krusch_fs_search`) across all fleet nodes (or a specific `host_node`).
        """
        q_clean = (query or "").strip()
        if not q_clean:
            return []

        effective_node = host_node or node
        effective_limit = top_k if top_k is not None else limit
        cat_norm = (category or "").strip().lower()
        mem_category: Optional[str] = category
        if cat_norm in ("", "all", "*"):
            mem_category = None
        elif cat_norm in ("systemd", "config", "env", "system_config", "service"):
            workspace = workspace or WorkspaceZone.SYSTEM_CONFIG.value
            mem_category = None
        elif cat_norm in ("docs", "user_docs", "document", "documents"):
            workspace = workspace or WorkspaceZone.USER_DOCS.value
            mem_category = None

        q_vec = self._embed(q_clean)
        q_tokens = set(QUERY_TOKEN_RE.findall(q_clean.lower()))
        now_ts = time.time()

        db = self.SessionLocal()
        try:
            file_q = db.query(FSFile).filter(FSFile.is_deleted == False)  # noqa: E712
            if effective_node and effective_node != "all":
                file_q = file_q.filter(FSFile.host_node == effective_node)
            if workspace and workspace != "all":
                file_q = file_q.filter(FSFile.workspace == workspace)
            if path_prefix:
                abs_pref = os.path.expanduser(path_prefix)
                file_q = file_q.filter(FSFile.file_path.like(f"{abs_pref}%"))

            files_map: Dict[int, FSFile] = {f.id: f for f in file_q.all()}
            if not files_map:
                return []

            valid_file_ids = list(files_map.keys())
            pages_map: Dict[tuple, FSPage] = {
                (p.file_id, p.page_number): p
                for p in db.query(FSPage).filter(FSPage.file_id.in_(valid_file_ids)).all()
            }

            all_mems = (
                db.query(PageMemory)
                .filter(PageMemory.file_id.in_(valid_file_ids))
                .order_by(PageMemory.id.asc())
                .all()
            )
            mems_by_file_page: Dict[tuple, List[PageMemory]] = {}
            for m in all_mems:
                mems_by_file_page.setdefault((m.file_id, m.page_number), []).append(m)

            candidates: Dict[tuple, Dict[str, Any]] = {}

            def _lexical_score(text_blob: str) -> float:
                if not q_tokens or not text_blob:
                    return 0.0
                lower_blob = text_blob.lower()
                blob_tokens = set(QUERY_TOKEN_RE.findall(lower_blob))
                overlap = len(q_tokens & blob_tokens) / max(1, len(q_tokens))
                phrase_bonus = 0.35 if q_clean.lower() in lower_blob else 0.0
                return overlap + phrase_bonus

            if include_memories:
                for m in all_mems:
                    if mem_category and m.category != mem_category:
                        continue
                    f_obj = files_map.get(m.file_id)
                    if not f_obj:
                        continue
                    searchable = f"{f_obj.host_node} {f_obj.file_name} {m.memory_key or ''} {m.memory_content} {m.quoted_sentence} {m.locator or ''}"
                    lex = _lexical_score(searchable)
                    dense = cosine_similarity(q_vec, m.embedding or [])
                    key_exact = 0.5 if (m.memory_key and m.memory_key.lower() in q_clean.lower()) else 0.0
                    raw_score = (0.55 * dense) + (0.45 * lex) + key_exact
                    if raw_score <= 0.05:
                        continue

                    key = (m.file_id, m.page_number)
                    reasons = ["page_memory_match"]
                    if key_exact > 0:
                        reasons.append("exact_memory_key")
                    if m.is_drifted:
                        raw_score *= 0.75
                        reasons.append("memory_drifted_warning")

                    entry = candidates.get(key)
                    if entry is None or raw_score > entry["raw_score"]:
                        bbox_val = None
                        if m.bbox:
                            try:
                                bbox_val = json.loads(m.bbox)
                            except Exception:
                                bbox_val = None
                        candidates[key] = {
                            "raw_score": raw_score,
                            "match_source": "page_memory" if entry is None else "hybrid_page_and_memory",
                            "match_reasons": reasons,
                            "snippet": f"[Memory: {m.memory_content}] (Quote: \"{m.quoted_sentence}\")",
                            "header": m.locator,
                            "locator": m.locator,
                            "citation": m.citation,
                            "bbox": bbox_val,
                            "char_start": m.char_start,
                            "char_end": m.char_end,
                        }

            if not mem_category:
                chunks = db.query(FSChunk).filter(FSChunk.file_id.in_(valid_file_ids)).all()
                for c in chunks:
                    f_obj = files_map.get(c.file_id)
                    if not f_obj:
                        continue
                    p_obj = pages_map.get((c.file_id, c.page_number))
                    chunk_text = c.content
                    if not chunk_text and p_obj and p_obj.page_text:
                        if c.char_start is not None and c.char_end is not None:
                            chunk_text = p_obj.page_text[c.char_start:c.char_end]
                        else:
                            chunk_text = p_obj.page_text
                    chunk_text = chunk_text or ""
                    searchable = f"{f_obj.host_node} {f_obj.file_name} {c.header or ''} {c.locator or ''} {chunk_text}"
                    lex = _lexical_score(searchable)
                    dense = cosine_similarity(q_vec, c.embedding or [])
                    raw_score = (0.50 * dense) + (0.50 * lex)
                    if raw_score <= 0.05:
                        continue

                    key = (c.file_id, c.page_number)
                    existing = candidates.get(key)
                    if existing is None:
                        bbox_val = None
                        if c.bbox:
                            try:
                                bbox_val = json.loads(c.bbox)
                            except Exception:
                                bbox_val = None
                        candidates[key] = {
                            "raw_score": raw_score,
                            "match_source": "page_chunk",
                            "match_reasons": ["hybrid_chunk_match"],
                            "snippet": chunk_text[:300].strip(),
                            "header": c.header,
                            "locator": c.locator,
                            "citation": c.citation,
                            "bbox": bbox_val,
                            "char_start": c.char_start,
                            "char_end": c.char_end,
                        }
                    else:
                        is_memory_upgrade = existing["match_source"] == "page_memory"
                        if raw_score > existing["raw_score"] and not is_memory_upgrade:
                            existing["snippet"] = chunk_text[:300].strip()
                            existing["header"] = c.header
                            existing["locator"] = c.locator
                            existing["citation"] = c.citation
                            existing["char_start"] = c.char_start
                            existing["char_end"] = c.char_end
                        existing["raw_score"] = max(existing["raw_score"], raw_score) + (0.15 if is_memory_upgrade else 0.0)
                        if is_memory_upgrade:
                            existing["match_source"] = "hybrid_page_and_memory"
                        if "hybrid_chunk_match" not in existing["match_reasons"]:
                            existing["match_reasons"].append("hybrid_chunk_match")

            hits: List[PageSearchHit] = []
            for (file_id, page_num), cand in candidates.items():
                f_obj = files_map[file_id]
                p_obj = pages_map.get((file_id, page_num))
                age_mod_days = max(0.0, (now_ts - (f_obj.mtime or now_ts)) / 86400.0)
                age_acc_days = max(0.0, (now_ts - (f_obj.atime or f_obj.mtime or now_ts)) / 86400.0)
                decay = 0.7 * math.exp(-0.005 * age_mod_days) + 0.3 * math.exp(-0.01 * age_acc_days)
                final_score = round(cand["raw_score"] * decay, 4)

                p_hash = p_obj.page_hash if p_obj else ""
                page_mems = [
                    self._memory_to_item(m, f_obj.file_path, p_hash, f_obj.host_node)
                    for m in mems_by_file_page.get((file_id, page_num), [])
                ]

                hits.append(
                    PageSearchHit(
                        host_node=f_obj.host_node,
                        file_id=f_obj.id,
                        file_path=f_obj.file_path,
                        file_name=f_obj.file_name,
                        workspace=f_obj.workspace,
                        page_number=page_num,
                        printed_page=p_obj.printed_page if p_obj else None,
                        citation=cand["citation"],
                        header=cand["header"],
                        locator=cand["locator"],
                        score=final_score,
                        match_source=cand["match_source"],
                        match_reasons=cand["match_reasons"],
                        snippet=cand["snippet"],
                        bbox=cand["bbox"],
                        char_start=cand["char_start"],
                        char_end=cand["char_end"],
                        page_hash=p_hash,
                        page_memories=page_mems,
                        handoff_repo=f_obj.handoff_repo,
                    )
                )

            hits.sort(key=lambda h: h.score, reverse=True)
            return hits[: max(1, int(effective_limit))]
        finally:
            db.close()

    def locate(
        self,
        pattern: Optional[str] = None,
        workspace: Optional[str] = None,
        extension: Optional[str] = None,
        min_size_mb: Optional[float] = None,
        modified_within_hours: Optional[float] = None,
        find_duplicates: bool = False,
        host_node: Optional[str] = None,
        limit: int = 25,
        node: Optional[str] = None,
        category: Optional[str] = None,
        min_size_bytes: Optional[int] = None,
    ) -> List[FileLocationHit]:
        """Fast Tier-A metadata & inode locator across the fleet (`krusch_fs_locate`)."""
        effective_node = host_node or node
        cat_norm = (category or "").strip().lower()
        if cat_norm in ("systemd", "config", "env", "system_config", "service") and not workspace:
            workspace = WorkspaceZone.SYSTEM_CONFIG.value
        elif cat_norm in ("docs", "user_docs", "document", "documents") and not workspace:
            workspace = WorkspaceZone.USER_DOCS.value

        db = self.SessionLocal()
        try:
            q = db.query(FSFile).filter(FSFile.is_deleted == False)  # noqa: E712
            if effective_node and effective_node != "all":
                q = q.filter(FSFile.host_node == effective_node)
            if workspace and workspace != "all":
                q = q.filter(FSFile.workspace == workspace)
            if pattern:
                p_clean = pattern.strip()
                if p_clean not in ("*", "**", "*.*", ""):
                    sql_pat = p_clean.replace("*", "%").replace("?", "_").strip("%")
                    if sql_pat:
                        pat = f"%{sql_pat}%"
                        q = q.filter((FSFile.file_name.ilike(pat)) | (FSFile.file_path.ilike(pat)))
            if extension:
                ext_norm = extension if extension.startswith(".") else f".{extension}"
                q = q.filter(FSFile.extension == ext_norm.lower())
            if min_size_mb is not None:
                q = q.filter(FSFile.size_bytes >= int(float(min_size_mb) * 1024 * 1024))
            elif min_size_bytes is not None and int(min_size_bytes) > 0:
                q = q.filter(FSFile.size_bytes >= int(min_size_bytes))
            if modified_within_hours is not None:
                cutoff = time.time() - (float(modified_within_hours) * 3600.0)
                q = q.filter(FSFile.mtime >= cutoff)

            rows = q.order_by(FSFile.mtime.desc()).all()
            if find_duplicates:
                hash_counts: Dict[str, int] = {}
                for r in rows:
                    hash_counts[r.file_hash] = hash_counts.get(r.file_hash, 0) + 1
                rows = [r for r in rows if hash_counts.get(r.file_hash, 0) > 1]

            results: List[FileLocationHit] = []
            for r in rows[: max(1, int(limit))]:
                mem_cnt = db.query(PageMemory).filter(PageMemory.file_id == r.id).count()
                results.append(
                    FileLocationHit(
                        host_node=r.host_node,
                        file_id=r.id,
                        file_path=r.file_path,
                        file_name=r.file_name,
                        workspace=r.workspace,
                        extension=r.extension,
                        mime_type=r.mime_type,
                        size_bytes=r.size_bytes,
                        inode=r.inode,
                        mtime=r.mtime,
                        file_hash=r.file_hash,
                        total_pages=r.total_pages,
                        memory_count=mem_cnt,
                        privacy_level=r.privacy_level,
                        handoff_repo=r.handoff_repo,
                    )
                )
            return results
        finally:
            db.close()

    def status(self) -> Dict[str, Any]:
        """Return index health, counts per fleet node and workspace zone, and drifted memory diagnostics."""
        db = self.SessionLocal()
        try:
            active_files = db.query(FSFile).filter(FSFile.is_deleted == False).all()  # noqa: E712
            total_pages = db.query(FSPage).count()
            total_chunks = db.query(FSChunk).count()
            total_memories = db.query(PageMemory).count()
            drifted_memories = db.query(PageMemory).filter(PageMemory.is_drifted == True).count()  # noqa: E712
            roots = db.query(FSWatchRoot).all()

            by_workspace: Dict[str, int] = {ws.value: 0 for ws in WorkspaceZone}
            by_host_node: Dict[str, int] = {}
            for f in active_files:
                by_workspace[f.workspace] = by_workspace.get(f.workspace, 0) + 1
                by_host_node[f.host_node] = by_host_node.get(f.host_node, 0) + 1

            return {
                "default_host_node": self.config.host_node,
                "db_url": self.config.db_url,
                "total_files": len(active_files),
                "total_pages": total_pages,
                "total_chunks": total_chunks,
                "total_page_memories": total_memories,
                "drifted_page_memories": drifted_memories,
                "files_by_host_node": by_host_node,
                "files_by_workspace": by_workspace,
                "watch_roots": [
                    {
                        "host_node": r.host_node,
                        "root_path": r.root_path,
                        "workspace": r.workspace,
                        "enabled": r.enabled,
                        "last_scanned_at": r.last_scanned_at.isoformat() if r.last_scanned_at else None,
                    }
                    for r in roots
                ],
            }
        finally:
            db.close()
