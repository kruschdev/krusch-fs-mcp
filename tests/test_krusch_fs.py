"""
Hermetic Test Suite for KruschFS (`tests/test_krusch_fs.py`)
============================================================
Verifies:
1. Multi-page KruschNexus segmentation, PageIndex tree (`krusch_fs_page_tree`), and single-page hydration (`krusch_fs_read_page`).
2. Write-through Page Memory pinning (`krusch_fs_remember_on_page`) and fail-closed `INV-12` verbatim quote verification.
3. Per-page `page_hash` delta re-indexing and page-granular memory drift detection (`is_drifted`).
4. O(1) Inode move/rename correlation preserving page memories and updating citations in-place.
5. Zero-Trust `.env` secret value redaction (`KEYS_ONLY`), SSH key `VAULT_LOCKED` protection, and systemd `config_rule` slot extraction.
6. `.git` repository boundary handoff to `krusch-git` (`repo_boundaries` workspace).
7. MCP server tool execution and behavioral annotations.
"""

import os
import json
import shutil
from pathlib import Path
import pytest

from krusch_fs import (
    KruschFSClient,
    KruschFSConfig,
    WorkspaceZone,
    PrivacyLevel,
)
from krusch_fs.mcp import (
    set_client,
    krusch_fs_search,
    krusch_fs_page_tree,
    krusch_fs_read_page,
    krusch_fs_remember_on_page,
    krusch_fs_locate,
    krusch_fs_sync,
    READ_ONLY_ANNOTATIONS,
    WRITE_IDEMPOTENT_ANNOTATIONS,
)


@pytest.fixture
def fs_env(tmp_path):
    db_file = tmp_path / "test_krusch_fs.db"
    workspace_dir = tmp_path / "os_root"
    workspace_dir.mkdir(parents=True, exist_ok=True)
    cfg = KruschFSConfig(
        db_url=f"sqlite:///{db_file}",
        host_node="krusch-test",
        embed_backend="deterministic",
    )
    client = KruschFSClient(cfg)
    set_client(client)
    return client, workspace_dir


def test_multi_page_indexing_and_write_through_page_memory(fs_env):
    client, root = fs_env
    doc_path = root / "home_insurance_policy.md"
    doc_path.write_text(
        "# Section 1: Property Overview\n"
        "Insured property located at 742 Evergreen Terrace.\n"
        "Construction type is masonry frame.\n\n"
        "# Section 2: Coverage & Deductibles\n"
        "The annual windstorm and hail deductible is $2,500 per occurrence.\n"
        "Personal property coverage limit is $175,000.\n\n"
        "# Section 3: Exclusions & Riders\n"
        "Commercial short-term rental usage requires Rider B-12.\n",
        encoding="utf-8",
    )

    rep = client.scan_path(str(doc_path))
    assert rep.files_indexed == 1
    assert rep.pages_indexed == 3

    tree = client.get_page_tree(str(doc_path))
    assert tree.total_pages == 3
    assert tree.pages[0].section_header == "Section 1: Property Overview"
    assert tree.pages[1].section_header == "Section 2: Coverage & Deductibles"
    assert tree.pages[2].section_header == "Section 3: Exclusions & Riders"

    # Fail-closed INV-12 check: quote not on page 2 must raise ValueError
    with pytest.raises(ValueError, match="Span grounding failed"):
        client.remember_on_page(
            file_path=str(doc_path),
            page_number=2,
            memory_content="Hallucinated deductible of $500",
            quoted_sentence="This sentence does not exist on page 2.",
        )

    # Valid write-through memory on Page 2
    mem = client.remember_on_page(
        file_path=str(doc_path),
        page_number=2,
        memory_content="Windstorm and hail deductible is $2,500 per occurrence.",
        quoted_sentence="The annual windstorm and hail deductible is $2,500 per occurrence.",
        category="fact",
        memory_key="windstorm_deductible",
    )
    assert mem.page_number == 2
    assert mem.is_drifted is False
    assert "home_insurance_policy.md p.2" in mem.citation
    assert mem.char_start is not None and mem.char_end > mem.char_start

    # Read only Page 2 and confirm memory is attached directly to Page 2
    page2 = client.read_page(str(doc_path), page_number=2)
    assert page2.page_number == 2
    assert len(page2.memories) == 1
    assert page2.memories[0].memory_key == "windstorm_deductible"

    # Hybrid search should surface Page 2 with its attached page_memory
    hits = client.search("windstorm hail deductible amount")
    assert len(hits) >= 1
    top = hits[0]
    assert top.page_number == 2
    assert top.file_name == "home_insurance_policy.md"
    assert any(m.memory_key == "windstorm_deductible" for m in top.page_memories)


def test_per_page_delta_reindexing_and_granular_memory_drift(fs_env):
    client, root = fs_env
    runbook = root / "fleet_runbook.md"
    runbook.write_text(
        "# Page 1: Node Topology\n"
        "workstation-01 is the primary orchestrator at 192.0.2.10.\n\n"
        "# Page 2: Storage Policy\n"
        "OS drives are strictly protected from Docker image storage.\n\n"
        "# Page 3: Voice Service\n"
        "Whisper STT listens on port 9000 via systemd.\n",
        encoding="utf-8",
    )

    client.scan_path(str(runbook))
    m1 = client.remember_on_page(
        file_path=str(runbook),
        page_number=1,
        memory_content="Orchestrator IP is 192.0.2.10",
        quoted_sentence="workstation-01 is the primary orchestrator at 192.0.2.10.",
    )
    m3 = client.remember_on_page(
        file_path=str(runbook),
        page_number=3,
        memory_content="Whisper runs on port 9000",
        quoted_sentence="Whisper STT listens on port 9000 via systemd.",
    )
    assert not m1.is_drifted and not m3.is_drifted

    # Modify ONLY Page 3 (changing port 9000 -> 9050), leaving Pages 1 and 2 untouched!
    runbook.write_text(
        "# Page 1: Node Topology\n"
        "workstation-01 is the primary orchestrator at 192.0.2.10.\n\n"
        "# Page 2: Storage Policy\n"
        "OS drives are strictly protected from Docker image storage.\n\n"
        "# Page 3: Voice Service\n"
        "Whisper STT was migrated to port 9050 in October.\n",
        encoding="utf-8",
    )

    rep = client.scan_path(str(runbook))
    # Pages 1 and 2 must be skipped via page_hash match; only Page 3 re-indexed!
    assert rep.pages_unchanged_skipped == 2
    assert rep.pages_indexed == 1
    assert rep.memories_flagged_drifted == 1

    p1_after = client.read_page(str(runbook), page_number=1)
    p3_after = client.read_page(str(runbook), page_number=3)
    assert p1_after.memories[0].is_drifted is False
    assert p3_after.memories[0].is_drifted is True


def test_cross_page_insertion_relocates_memory_without_false_drift(fs_env):
    client, root = fs_env
    runbook = root / "shift_runbook.md"
    runbook.write_text(
        "# Page 1: Node Topology\n"
        "workstation-01 is the primary orchestrator at 192.0.2.10.\n\n"
        "# Page 2: Storage Policy\n"
        "OS drives are strictly protected from Docker image storage.\n",
        encoding="utf-8",
    )

    client.scan_path(str(runbook))
    mem = client.remember_on_page(
        file_path=str(runbook),
        page_number=2,
        memory_content="Never store Docker images on OS drives",
        quoted_sentence="OS drives are strictly protected from Docker image storage.",
        category="config_rule",
        memory_key="os_drive_rule",
    )
    assert mem.page_number == 2
    assert mem.is_drifted is False

    # Insert a new section BEFORE Storage Policy, shifting Storage Policy from Page 2 -> Page 3
    runbook.write_text(
        "# Page 1: Node Topology\n"
        "workstation-01 is the primary orchestrator at 192.0.2.10.\n\n"
        "# Page 1.5: Network Mesh\n"
        "All nodes communicate over Tailscale WireGuard mesh.\n\n"
        "# Page 2: Storage Policy\n"
        "OS drives are strictly protected from Docker image storage.\n",
        encoding="utf-8",
    )

    rep = client.scan_path(str(runbook))
    assert rep.memories_relocated == 1
    assert rep.memories_flagged_drifted == 0

    p2_new = client.read_page(str(runbook), page_number=2)
    p3_new = client.read_page(str(runbook), page_number=3)
    assert len(p2_new.memories) == 0
    assert len(p3_new.memories) == 1
    relocated = p3_new.memories[0]
    assert relocated.memory_key == "os_drive_rule"
    assert relocated.page_number == 3
    assert relocated.is_drifted is False
    assert relocated.anchor_page_hash == p3_new.page_hash
    assert "shift_runbook.md p.3" in relocated.citation


def test_inode_move_and_rename_preserves_page_memories(fs_env):
    client, root = fs_env
    downloads = root / "Downloads"
    archive = root / "Documents" / "Taxes"
    downloads.mkdir(parents=True)
    archive.mkdir(parents=True)

    orig_file = downloads / "receipt_draft.md"
    orig_file.write_text(
        "# Hardware Invoice\n"
        "Purchased Dual RTX 3060 24GB for $580.00 total.\n",
        encoding="utf-8",
    )

    client.scan_path(str(orig_file))
    client.remember_on_page(
        file_path=str(orig_file),
        page_number=1,
        memory_content="Dual RTX 3060 cost $580.00",
        quoted_sentence="Purchased Dual RTX 3060 24GB for $580.00 total.",
        category="slot",
        memory_key="gpu_invoice_total",
    )

    # Move and rename on the same filesystem (preserving inode & content hash)
    moved_file = archive / "2026_gpu_invoice.md"
    os.rename(orig_file, moved_file)

    rep = client.scan_path(str(moved_file))
    assert rep.files_moved_in_place == 1
    assert rep.pages_indexed == 0  # Zero re-parsing or re-embedding!

    page1 = client.read_page(str(moved_file), page_number=1)
    assert page1.file_name == "2026_gpu_invoice.md"
    assert len(page1.memories) == 1
    assert page1.memories[0].memory_key == "gpu_invoice_total"
    assert page1.memories[0].citation.startswith("2026_gpu_invoice.md p.1")


def test_env_secret_redaction_and_systemd_config_extraction(fs_env):
    client, root = fs_env
    env_file = root / ".env.production"
    env_file.write_text(
        "# Production credentials\n"
        "APP_CLIENT_ID=demo_client_id_12345\n"
        "APP_CLIENT_SECRET=TopSecretValueNeverIndex999!\n",
        encoding="utf-8",
    )

    service_file = root / "whisper-asr.service"
    service_file.write_text(
        "[Unit]\n"
        "Description=Whisper ASR Worker Server\n\n"
        "[Service]\n"
        "WorkingDirectory=/opt/services/asr-worker\n"
        "ExecStart=/usr/bin/python3 scripts/whisper_asr_server.py --port 9000\n",
        encoding="utf-8",
    )

    ssh_dir = root / ".ssh"
    ssh_dir.mkdir()
    priv_key = ssh_dir / "id_ed25519"
    priv_key.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nSUPER_SECRET_KEY\n", encoding="utf-8")

    rep = client.scan_path(str(root))
    assert rep.vault_locked_skipped == 1

    # 1. Verify .env secret value is NEVER stored anywhere in page text or memories
    env_page = client.read_page(str(env_file), page_number=1)
    assert env_page.privacy_level == PrivacyLevel.KEYS_ONLY.value
    assert "TopSecretValueNeverIndex999!" not in env_page.text
    assert "demo_client_id_12345" not in env_page.text
    assert "APP_CLIENT_SECRET=[REDACTED]" in env_page.text

    # Yet searching for the variable name finds the exact .env file & page!
    env_hits = client.search("APP_CLIENT_SECRET")
    assert len(env_hits) >= 1
    assert env_hits[0].file_name == ".env.production"
    assert "TopSecretValueNeverIndex999!" not in json.dumps(env_hits[0].model_dump())

    # 2. Verify systemd [Service] directives were extracted onto Page 2
    svc_tree = client.get_page_tree(str(service_file))
    assert svc_tree.total_pages == 2
    assert svc_tree.pages[1].section_header == "[Service]"
    assert any(m.memory_key == "ExecStart" for m in svc_tree.pages[1].memories)

    # 3. Verify private SSH key content is vault-locked
    key_page = client.read_page(str(priv_key), page_number=1)
    assert key_page.privacy_level == PrivacyLevel.VAULT_LOCKED.value
    assert "SUPER_SECRET_KEY" not in key_page.text


def test_git_repo_boundary_handoff_to_krusch_git(fs_env):
    client, root = fs_env
    repo_dir = root / "sample-repo"
    (repo_dir / ".git").mkdir(parents=True)
    (repo_dir / "src").mkdir(parents=True)
    (repo_dir / "README.md").write_text("# Sample Repo\nHandled by krusch-git for AST search.\n", encoding="utf-8")
    (repo_dir / "src" / "app.py").write_text("def main():\n    return 42\n", encoding="utf-8")

    rep = client.scan_path(str(root))
    assert rep.repo_boundaries_handed_off == 1

    # README.md is indexed in repo_boundaries with handoff_repo="sample-repo"
    loc_hits = client.locate(workspace=WorkspaceZone.REPO_BOUNDARIES.value)
    assert len(loc_hits) == 1
    assert loc_hits[0].file_name == "README.md"
    assert loc_hits[0].handoff_repo == "sample-repo"

    # Internal source code (src/app.py) is NOT double-indexed
    all_files = client.locate()
    assert not any(f.file_name == "app.py" for f in all_files)


def test_mcp_tools_and_behavioral_annotations(fs_env):
    client, root = fs_env
    note = root / "architecture_note.md"
    note.write_text(
        "# Memory Spine\n"
        "Every memory in KruschFS is bound to a 1-based KruschNexus page.\n",
        encoding="utf-8",
    )

    # Verify Invariant #567 annotations
    for ann in (READ_ONLY_ANNOTATIONS, WRITE_IDEMPOTENT_ANNOTATIONS):
        dump = ann.model_dump(by_alias=True) if hasattr(ann, "model_dump") else dict(ann)
        assert "readOnlyHint" in dump
        assert "destructiveHint" in dump
        assert "idempotentHint" in dump
        assert "openWorldHint" in dump

    sync_res = json.loads(krusch_fs_sync(action="scan", path=str(root)))
    assert sync_res["status"] == "success"

    rem_res = json.loads(
        krusch_fs_remember_on_page(
            file_path=str(note),
            page_number=1,
            memory_content="KruschFS binds every memory to a 1-based page.",
            quoted_sentence="Every memory in KruschFS is bound to a 1-based KruschNexus page.",
            category="decision",
            memory_key="page_binding_invariant",
        )
    )
    assert rem_res["status"] == "success"
    assert rem_res["page_memory"]["page_number"] == 1

    tree_res = json.loads(krusch_fs_page_tree(file_path=str(note)))
    assert tree_res["status"] == "success"
    assert tree_res["page_tree"]["total_memories"] == 1

    page_res = json.loads(krusch_fs_read_page(file_path=str(note), page_number=1))
    assert page_res["status"] == "success"
    assert len(page_res["page"]["memories"]) == 1

    search_res = json.loads(krusch_fs_search(query="page_binding_invariant KruschNexus page"))
    assert search_res["status"] == "success"
    assert search_res["count"] >= 1

    loc_res = json.loads(krusch_fs_locate(extension=".md"))
    assert loc_res["status"] == "success"
    assert loc_res["count"] == 1


def _create_minimal_docx(docx_path: Path, paragraphs: list[str]) -> None:
    """Create a valid minimal OOXML .docx archive using Python's standard library zipfile."""
    import zipfile

    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/word/document.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
        "</Types>"
    )
    rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="word/document.xml"/>'
        "</Relationships>"
    )
    body_xml = "".join(
        f"<w:p><w:r><w:t>{p}</w:t></w:r></w:p>" for p in paragraphs
    )
    doc_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f"<w:body>{body_xml}</w:body></w:document>"
    )
    with zipfile.ZipFile(docx_path, "w") as zf:
        zf.writestr("[Content_Types].xml", content_types)
        zf.writestr("_rels/.rels", rels)
        zf.writestr("word/document.xml", doc_xml)


def test_real_pdf_and_docx_nexus_page_memory_grounding(fs_env):
    client, root = fs_env
    docx_dst = root / "policy_manual.docx"
    html_dst = root / "sample_contract.html"

    _create_minimal_docx(
        docx_dst,
        [
            "Section 1. Permitted Office Premises Use",
            "Tenant shall use the leased premises solely for general commercial office operations.",
        ],
    )
    html_dst.write_text(
        "<html><body><h1>Commercial Lease Agreement</h1>"
        "<p>The permitted office premises use is restricted to software engineering.</p>"
        "</body></html>",
        encoding="utf-8",
    )

    rep = client.scan_path(str(root))
    assert rep.files_indexed == 2

    docx_p1 = client.read_page(str(docx_dst), page_number=1)
    assert docx_p1.page_number == 1
    assert "general commercial office operations" in docx_p1.text

    mem = client.remember_on_page(
        file_path=str(docx_dst),
        page_number=1,
        memory_content="Commercial lease agreement governs permitted office premises use.",
        quoted_sentence="Tenant shall use the leased premises solely for general commercial office operations.",
        category="fact",
        memory_key="contract_permitted_use",
    )
    assert mem.page_number == 1
    assert "policy_manual.docx p.1" in mem.citation

    hits = client.search("contract_permitted_use commercial office premises")
    assert len(hits) >= 1
    assert hits[0].file_name == "policy_manual.docx"
    assert hits[0].page_number == 1
    assert any(m.memory_key == "contract_permitted_use" for m in hits[0].page_memories)


def test_multi_node_fleet_indexing_and_host_filtering(fs_env, monkeypatch):
    from krusch_fs.fleet import load_fleet_nodes

    client, root = fs_env

    # Verify external fleet.json loading
    fleet_cfg_file = root / "custom_fleet.json"
    fleet_cfg_file.write_text(
        json.dumps(
            {
                "workstation": {"local": True, "role": "Primary Workstation", "ssh_targets": [], "default_roots": [str(root)]},
                "compute-node-01": {"local": False, "role": "GPU Compute Worker", "ssh_targets": ["192.0.2.10"], "default_roots": ["/etc/systemd/system"]},
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("KRUSCH_FS_FLEET_CONFIG", str(fleet_cfg_file))
    loaded_fleet = load_fleet_nodes()
    assert "workstation" in loaded_fleet
    assert "compute-node-01" in loaded_fleet

    # Simulate remote SSH streamed entries from compute-node-01 and storage-node-01
    compute_entry = {
        "file_path": "/etc/systemd/system/vllm-swarm.service",
        "device_id": "2049",
        "inode": 88101,
        "size_bytes": 215,
        "mtime": 1760600000.0,
        "atime": 1760600000.0,
        "privacy_level": "standard",
        "file_hash": "hash_compute_vllm_1",
        "unchanged": False,
        "handoff_repo": None,
        "text_content": (
            "[Unit]\n"
            "Description=vLLM GPU Compute Server\n\n"
            "[Service]\n"
            "WorkingDirectory=/opt/vllm\n"
            "ExecStart=/usr/local/bin/vllm serve --port 8000\n"
        ),
    }

    storage_entry = {
        "file_path": "/etc/fstab",
        "device_id": "2050",
        "inode": 99202,
        "size_bytes": 180,
        "mtime": 1760600100.0,
        "atime": 1760600100.0,
        "privacy_level": "standard",
        "file_hash": "hash_storage_fstab_1",
        "unchanged": False,
        "handoff_repo": None,
        "text_content": (
            "# /etc/fstab on storage-node-01\n"
            "UUID=db-nvme-01 /mnt/database ext4 defaults,noatime 0 2\n"
            "UUID=media-hdd-01 /mnt/media1 ext4 defaults 0 2\n"
        ),
    }

    client.index_remote_entry("compute-node-01", compute_entry)
    client.index_remote_entry("storage-node-01", storage_entry)

    # Pin a page memory directly to Page 1 of /etc/fstab on storage-node-01
    mem = client.remember_on_page(
        file_path="/etc/fstab",
        page_number=1,
        memory_content="storage-node-01 mounts PostgreSQL vector storage at /mnt/database on NVMe.",
        quoted_sentence="UUID=db-nvme-01 /mnt/database ext4 defaults,noatime 0 2",
        category="config_rule",
        memory_key="storage_database_mount",
        host_node="storage-node-01",
    )
    assert mem.host_node == "storage-node-01"
    assert mem.page_number == 1

    # Search filtered to compute-node-01 only
    dev_hits = client.search("vLLM WorkingDirectory /opt/vllm", host_node="compute-node-01")
    assert len(dev_hits) >= 1
    assert dev_hits[0].host_node == "compute-node-01"
    assert dev_hits[0].page_number == 2  # [Service] stanza is Page 2!

    # Search filtered to storage-node-01 only
    serv_hits = client.search("storage_database_mount /mnt/database", host_node="storage-node-01")
    assert len(serv_hits) >= 1
    assert serv_hits[0].host_node == "storage-node-01"
    assert serv_hits[0].file_path == "/etc/fstab"

    # Fleet status shows files grouped by host_node
    st = client.status()
    assert st["files_by_host_node"]["compute-node-01"] == 1
    assert st["files_by_host_node"]["storage-node-01"] == 1


def test_fs01_symlink_rejection_and_realpath_privacy_classification(fs_env):
    client, root = fs_env
    real_doc = root / "real_doc.md"
    real_doc.write_text("# Real Doc\nLegitimate content.\n", encoding="utf-8")

    # 1. File symlink must be rejected by index_file()
    symlink_doc = root / "symlink_doc.md"
    os.symlink(real_doc, symlink_doc)
    assert client.index_file(str(symlink_doc)) is None

    # 2. File inside a symlinked directory pointing to an ignored path (node_modules) must be rejected
    ignored_dir = root / "node_modules" / "pkg"
    ignored_dir.mkdir(parents=True)
    ignored_file = ignored_dir / "readme.md"
    ignored_file.write_text("# Package\nShould be ignored.\n", encoding="utf-8")

    linked_dir = root / "innocent_dir"
    os.symlink(ignored_dir, linked_dir)
    assert client.index_file(str(linked_dir / "readme.md")) is None

    # 3. File inside a symlinked directory pointing into /.ssh/ must get VAULT_LOCKED via real_path
    ssh_dir = root / ".ssh"
    ssh_dir.mkdir(exist_ok=True)
    custom_secret_file = ssh_dir / "custom_identity_token"
    custom_secret_file.write_text("SECRET_SSH_IDENTITY_MATERIAL_XYZ", encoding="utf-8")

    alias_ssh_dir = root / "public_looking_dir"
    os.symlink(ssh_dir, alias_ssh_dir)
    indexed_secret = client.index_file(str(alias_ssh_dir / "custom_identity_token"))
    assert indexed_secret is not None
    assert indexed_secret.privacy_level == PrivacyLevel.VAULT_LOCKED.value
    p1 = client.read_page(str(alias_ssh_dir / "custom_identity_token"), page_number=1)
    assert "SECRET_SSH_IDENTITY_MATERIAL_XYZ" not in p1.text


def test_fs02_multiline_env_redaction_and_systemd_inline_env_redaction(fs_env):
    from krusch_fs.shield import redact_env_content_to_pages, _segment_unpaged_text_into_pages

    client, root = fs_env
    env_file = root / ".env"
    env_file.write_text(
        "\n\n# Header comment\n"
        'MULTI_DOUBLE="first line of secret\n'
        "FAKE_KEY_IN_DOUBLE=leaked_value_123\n"
        "# fake comment inside multiline secret\n"
        'end of double secret"\n'
        "MULTI_TRIPLE=\"\"\"-----BEGIN PRIVATE KEY-----\n"
        "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC=\n"
        "FAKE_TRIPLE_KEY=leaked_triple_456\n"
        "-----END PRIVATE KEY-----\"\"\"\n"
        "MULTI_SINGLE='line one\n"
        "FAKE_SINGLE_KEY=leaked_single_789\n"
        "line two'\n"
        "REAL_AFTER_KEY=real_secret_value\n",
        encoding="utf-8",
    )

    res, slots = redact_env_content_to_pages(str(env_file), ".env", "hash123")
    page_text = res.pages[0].text
    assert "leaked_value_123" not in page_text
    assert "leaked_triple_456" not in page_text
    assert "leaked_single_789" not in page_text
    assert "real_secret_value" not in page_text
    assert "FAKE_KEY_IN_DOUBLE" not in page_text
    assert "FAKE_TRIPLE_KEY" not in page_text
    assert "FAKE_SINGLE_KEY" not in page_text
    assert "# fake comment inside multiline secret" not in page_text
    assert "# [REDACTED_MULTILINE]" in page_text

    slot_keys = [s["memory_key"] for s in slots]
    assert slot_keys == ["MULTI_DOUBLE", "MULTI_TRIPLE", "MULTI_SINGLE", "REAL_AFTER_KEY"]

    # Verify FS-06: every slot's char_start:char_end slices exact quoted_sentence in final full_text
    for s in slots:
        assert page_text[s["char_start"]:s["char_end"]] == s["quoted_sentence"]

    # Verify systemd .service inline Environment="KEY=SECRET" redaction
    svc_text = (
        "[Unit]\n"
        "Description=API Worker\n\n"
        "[Service]\n"
        'Environment="OPENAI_API_KEY=sk-live-999999" "DB_PASSWORD=topsecret"\n'
        "Environment=RAW_TOKEN=tok_abc123\n"
        "ExecStart=/usr/bin/python3 app.py\n"
    )
    pages, _ = _segment_unpaged_text_into_pages(svc_text, "api-worker.service")
    combined_svc_text = "\n".join(p.text for p in pages)
    assert "sk-live-999999" not in combined_svc_text
    assert "topsecret" not in combined_svc_text
    assert "tok_abc123" not in combined_svc_text
    assert 'Environment="OPENAI_API_KEY=[REDACTED]" "DB_PASSWORD=[REDACTED]"' in combined_svc_text
    assert "Environment=RAW_TOKEN=[REDACTED]" in combined_svc_text


def test_fs03_remote_scanner_json_payload_expanduser_and_ssh_guard(fs_env, monkeypatch):
    import subprocess
    import sys
    from krusch_fs.fleet import REMOTE_SCANNER_SCRIPT_TEMPLATE, probe_node_ssh, stream_remote_node_entries

    client, root = fs_env
    env_p = root / ".env.remote"
    env_p.write_text(
        'SECRET_KEY="line1\nFAKE_INNER=secret_inner\nline2"\nNORMAL_KEY=val\n',
        encoding="utf-8",
    )

    # 1. Payload with None/True/False must parse via json.loads(__PAYLOAD_JSON_STR__) without NameError
    payload_obj = {
        "roots": [str(env_p)],
        "known_hashes": {"/nonexistent": None},
        "max_depth": 2,
        "max_files": 10,
        "flag_true": True,
        "flag_false": False,
    }
    script_code = REMOTE_SCANNER_SCRIPT_TEMPLATE.replace(
        "__PAYLOAD_JSON_STR__", json.dumps(json.dumps(payload_obj))
    )
    proc = subprocess.run([sys.executable, "-c", script_code], capture_output=True, text=True, check=True)
    lines = [json.loads(line) for line in proc.stdout.splitlines() if line.strip().startswith("{")]
    assert len(lines) == 1
    assert "FAKE_INNER" not in lines[0]["text_content"]
    assert "# [REDACTED_MULTILINE]" in lines[0]["text_content"]

    # 2. Reject ssh_target starting with "-"
    with pytest.raises(ValueError, match="Invalid ssh_target"):
        stream_remote_node_entries("-oProxyCommand=evil", ["/etc"], {})

    assert probe_node_ssh("bad-node", fleet_map={"bad-node": {"local": False, "ssh_targets": ["-oProxyCommand=evil"]}}) is None

    # 3. Verify "--" is passed before ssh_target and ~ is not expanded locally in scan_remote_node
    captured_cmds = []
    captured_inputs = []

    def fake_run(cmd, *args, **kwargs):
        captured_cmds.append(cmd)
        if "input" in kwargs:
            captured_inputs.append(kwargs["input"])

        class DummyRes:
            returncode = 0
            stdout = ""
            stderr = ""

        return DummyRes()

    monkeypatch.setattr(subprocess, "run", fake_run)
    target = probe_node_ssh("remote-1", fleet_map={"remote-1": {"local": False, "ssh_targets": ["10.0.0.99"]}})
    assert target == "10.0.0.99"
    assert "--" in captured_cmds[-1]
    dash_idx = captured_cmds[-1].index("--")
    assert captured_cmds[-1][dash_idx + 1] == "10.0.0.99"

    client.scan_remote_node("remote-1", roots=["~/remote_docs"], ssh_target_override="10.0.0.99")
    assert len(captured_inputs) == 1
    # Verify ~/remote_docs was sent unexpanded in the payload so the remote host expands ~
    assert "~/remote_docs" in captured_inputs[0]


def test_fs04_deleted_files_marked_deleted_and_filtered(fs_env):
    from krusch_fs.store import FSChunk

    client, root = fs_env
    scan_dir = root / "watched_docs"
    scan_dir.mkdir()
    f1 = scan_dir / "keep.md"
    f2 = scan_dir / "remove_me.md"
    f1.write_text("# Keep\nThis file stays on disk.\n", encoding="utf-8")
    f2.write_text("# Remove\nThis file will be deleted soon.\n", encoding="utf-8")

    client.scan_path(str(scan_dir))
    mem = client.remember_on_page(
        file_path=str(f2),
        page_number=1,
        memory_content="Temporary note on remove_me.md",
        quoted_sentence="This file will be deleted soon.",
    )
    assert not mem.is_drifted
    assert client.status()["total_files"] == 2

    # Delete f2 from disk and re-scan directory
    f2.unlink()
    rep = client.scan_path(str(scan_dir))
    assert rep.memories_flagged_drifted == 1

    st = client.status()
    assert st["total_files"] == 1
    assert st["total_pages"] == 1
    assert st["drifted_page_memories"] == 1

    # Chunks for deleted file must be removed
    db = client.SessionLocal()
    try:
        assert db.query(FSChunk).filter(FSChunk.file_id == mem.file_id).count() == 0
    finally:
        db.close()

    # get_page_tree and read_page must filter is_deleted == False and raise FileNotFoundError
    with pytest.raises(FileNotFoundError):
        client.get_page_tree(str(f2))
    with pytest.raises(FileNotFoundError):
        client.read_page(str(f2), page_number=1)


def test_fs05_fs06_fs07_drift_status_clamping_exact_hash_relocation_and_pointer_slice(fs_env):
    from krusch_fs.store import FSChunk, PageMemory

    client, root = fs_env
    doc = root / "evolving_spec.md"
    doc.write_text(
        "# Page 1: Intro\n"
        "Shared sentence across pages.\n\n"
        "# Page 2: Target Section\n"
        "Shared sentence across pages.\n"
        "Unique target anchor text on page 2.\n\n"
        "# Page 3: Epilogue\n"
        "Epilogue text that will be removed when file shrinks.\n",
        encoding="utf-8",
    )
    client.scan_path(str(doc))

    # FS-06: Verify pointer-slice chunk deduplication stored content=""
    db = client.SessionLocal()
    try:
        chunks = db.query(FSChunk).all()
        assert len(chunks) >= 3
        assert all(c.content == "" for c in chunks)
    finally:
        db.close()

    # Pin memory on Page 2 using the shared sentence and a memory on Page 3
    m_shared = client.remember_on_page(
        file_path=str(doc),
        page_number=2,
        memory_content="Anchored to Page 2 target section.",
        quoted_sentence="Shared sentence across pages.",
    )
    m_epilogue = client.remember_on_page(
        file_path=str(doc),
        page_number=3,
        memory_content="Epilogue note.",
        quoted_sentence="Epilogue text that will be removed when file shrinks.",
    )
    assert m_shared.drift_status == "VALID"
    assert m_epilogue.drift_status == "VALID"

    # FS-07: Check _memory_to_item with current_page_hash="" preserves ""
    db = client.SessionLocal()
    try:
        raw_mem = db.query(PageMemory).filter(PageMemory.id == m_shared.id).first()
        item_empty_hash = client._memory_to_item(raw_mem, str(doc), current_page_hash="")
        assert item_empty_hash.current_page_hash == ""
    finally:
        db.close()

    # Insert a new Page 2 that ALSO contains "Shared sentence across pages." (modified page),
    # while shifting the original Page 2 (with exact anchor_page_hash!) to Page 3, and dropping old Page 3.
    doc.write_text(
        "# Page 1: Intro\n"
        "Shared sentence across pages.\n\n"
        "# Page 2: Newly Inserted Section\n"
        "Shared sentence across pages.\n"
        "Modified content on new page 2.\n\n"
        "# Page 2: Target Section\n"
        "Shared sentence across pages.\n"
        "Unique target anchor text on page 2.\n",
        encoding="utf-8",
    )
    client.scan_path(str(doc))

    # Because Page 3 has the exact anchor_page_hash of old Page 2, m_shared must relocate to Page 3!
    p3 = client.read_page(str(doc), page_number=3)
    assert any(m.id == m_shared.id and not m.is_drifted and m.drift_status == "VALID" for m in p3.memories)

    # Now shrink the file to 1 page so m_epilogue (and m_shared) are beyond total_pages=1 and un-relocated
    doc.write_text("# Page 1: Minimal\nCompletely rewritten single page.\n", encoding="utf-8")
    client.scan_path(str(doc))

    tree = client.get_page_tree(str(doc))
    assert tree.total_pages == 1
    assert len(tree.pages[0].memories) == 2
    assert all(m.is_drifted and m.drift_status == "STALE_DRIFT" and m.page_number == 1 for m in tree.pages[0].memories)

    p1 = client.read_page(str(doc), page_number=1)
    assert len(p1.memories) == 2
    assert all(m.drift_status == "STALE_DRIFT" for m in p1.memories)


def test_fs08_fs09_fs10_busy_timeout_idempotent_remember_and_mcp_sync(fs_env):
    from sqlalchemy import text

    client, root = fs_env
    # FS-08: Verify PRAGMA busy_timeout=10000
    with client.engine.connect() as conn:
        timeout_val = conn.execute(text("PRAGMA busy_timeout;")).scalar()
        assert int(timeout_val) == 10000

    doc = root / "idempotent.md"
    doc.write_text("# Policy\nAll backups must be encrypted with age.\n", encoding="utf-8")

    # FS-10: krusch_fs_sync with singular path, default action="status", and node="all"
    sync_out = json.loads(krusch_fs_sync(path=str(doc), node="all"))
    assert sync_out["status"] == "success"
    assert sync_out["sync_report"]["host_node"] == "krusch-test"
    assert sync_out["sync_report"]["files_indexed"] == 1

    # Re-running with force=True must re-index the file instead of skipping as unchanged
    forced_out = json.loads(krusch_fs_sync(path=str(doc), node="all", force=True))
    assert forced_out["status"] == "success"
    assert forced_out["sync_report"]["files_indexed"] == 1
    assert forced_out["sync_report"]["files_unchanged"] == 0
    assert "all" not in client.status()["files_by_host_node"]

    # FS-09: Repeated identical remember_on_page calls must be idempotent
    m1 = client.remember_on_page(
        file_path=str(doc),
        page_number=1,
        memory_content="Backups use age encryption",
        quoted_sentence="All backups must be encrypted with age.",
        category="config_rule",
        memory_key="backup_encryption",
    )
    m2 = client.remember_on_page(
        file_path=str(doc),
        page_number=1,
        memory_content="Backups use age encryption",
        quoted_sentence="All backups must be encrypted with age.",
        category="config_rule",
        memory_key="backup_encryption",
    )
    assert m1.id == m2.id
    p1 = client.read_page(str(doc), page_number=1)
    assert len(p1.memories) == 1


def test_fs11_memory_to_item_host_node_env_and_upsert_parsed_file_pages(fs_env, monkeypatch):
    from krusch_fs.store import PageMemory

    client, root = fs_env
    monkeypatch.setenv("KRUSCH_FS_NODE", "kruschdev-env-node")

    dummy_mem = PageMemory(
        id=999,
        file_id=1,
        workspace="homelab_projects",
        page_number=1,
        printed_page="1",
        category="annotation",
        memory_key="test_key",
        memory_content="test content",
        quoted_sentence="All backups must be encrypted with age.",
        citation="idempotent.md p.1",
        locator="Page 1",
        anchor_page_hash="hash1",
        is_drifted=0,
    )
    item = client._memory_to_item(dummy_mem, file_path="/tmp/idempotent.md")
    assert item.host_node == "kruschdev-env-node"


def test_scan_path_edge_cases_and_malformed_fleet_config(fs_env, tmp_path, caplog):
    import logging
    from krusch_fs.fleet import load_fleet_nodes

    client, root = fs_env

    # 1. Non-existent path raises FileNotFoundError
    missing_path = root / "does_not_exist_12345.md"
    with pytest.raises(FileNotFoundError, match="Path not found"):
        client.scan_path(str(missing_path))

    # 2. Directory scan with register_watch_root=False indexes files without adding a WatchRoot
    sub_dir = root / "unwatched_subdir"
    sub_dir.mkdir(parents=True, exist_ok=True)
    (sub_dir / "note.md").write_text("# Unwatched\nHello world.\n", encoding="utf-8")
    rep = client.scan_path(str(sub_dir), register_watch_root=False)
    assert rep.files_indexed == 1
    assert rep.pages_indexed == 1

    # 3. Malformed fleet.json logs a warning and falls back to local default fleet
    bad_fleet = tmp_path / "bad_fleet.json"
    bad_fleet.write_text("{ invalid json", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        nodes = load_fleet_nodes(str(bad_fleet))
    assert isinstance(nodes, dict) and len(nodes) == 1
    assert any("Failed to load fleet topology" in rec.message for rec in caplog.records)


def test_remember_on_page_validates_page_number_and_client_registry(fs_env):
    from krusch_fs.client import InvalidPageNumberError, PageNumberOutOfRangeError
    from krusch_fs.mcp import get_client, set_client

    client, root = fs_env
    doc = root / "page_validation.md"
    doc.write_text("# Page 1\nValid sentence.\n", encoding="utf-8")

    with pytest.raises(InvalidPageNumberError, match="must be a numeric integer"):
        client.remember_on_page(
            file_path=str(doc),
            page_number="not-a-number",  # type: ignore[arg-type]
            memory_content="test",
            quoted_sentence="Valid sentence.",
        )

    with pytest.raises(PageNumberOutOfRangeError, match="must be >= 1"):
        client.remember_on_page(
            file_path=str(doc),
            page_number=0,
            memory_content="test",
            quoted_sentence="Valid sentence.",
        )

    set_client(client)
    assert get_client() is client
    assert get_client(client) is client


def test_get_mcp_thread_safe_singleton_and_cli_validators():
    import argparse
    import threading
    from krusch_fs.mcp import get_mcp, mcp
    from krusch_fs.cli import validate_nodes, validate_path, validate_workspace, main as cli_main

    # 1. Verify get_mcp() thread-safe singleton identity
    results = []

    def fetch_mcp():
        results.append(get_mcp())

    threads = [threading.Thread(target=fetch_mcp) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 8
    assert all(inst is mcp for inst in results)

    # 2. Verify CLI validators accept valid inputs and reject invalid/metacharacter inputs
    assert validate_nodes("krusch,kruschdev,compute-node-01") == "krusch,kruschdev,compute-node-01"
    assert validate_path("/etc/systemd/system") == "/etc/systemd/system"
    assert validate_workspace("user_docs") == "user_docs"

    for bad_node in ("", "   ", "-oProxyCommand=evil", "krusch;rm -rf /", "krusch,,kruschdev", "node$1"):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_nodes(bad_node)

    for bad_path in ("", "   ", "-rf", "/tmp/test;id", "/tmp/`whoami`", "/tmp/bad\x00path"):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_path(bad_path)

    for bad_ws in ("", "   ", "-bad", "user_docs;id", "bad/workspace", "ws$1"):
        with pytest.raises(argparse.ArgumentTypeError):
            validate_workspace(bad_ws)

    with pytest.raises(SystemExit):
        cli_main(["sync-fleet", "--nodes", "krusch;evil"])


