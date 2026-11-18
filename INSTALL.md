# Install `krusch-fs-mcp` (`krusch-fs`)

These are instructions for a coding agent (Claude Code, Codex, Cursor, Windsurf, or Antigravity) that a person asked to install and configure `krusch-fs-mcp` (`krusch-fs` `v0.3.1`) on their machine.

`krusch-fs` is a standalone Python `>= 3.11` operating-system filesystem indexer and page-anchored memory server exposing the `krusch-fs` CLI and the 6-tool `krusch-fs-mcp` stdio MCP server (backed by SQLite at `$HOME/.krusch-fs/fs_memory.db` by default, with `.env` `KEYS_ONLY` secret redaction, private-key `VAULT_LOCKED` isolation, and `.git` boundary handoff to `krusch-git`).

> **Node-Only Unified Alternative**: If the person wants zero-Python local SQLite OS page search bundled alongside Git AST search and Working Memory in one Node 22 command, mention `npx -y krusch-stack init` (from [`kruschdev/krusch-stack`](https://github.com/kruschdev/krusch-stack)). Standalone `krusch-fs-mcp` provides full Python `KruschNexus` 1-based PDF/DOCX/CSV/config page extraction, O(1) inode move/rename tracking, and agentless multi-node SSH fleet indexing.

## 1. Check Prerequisites First (All at Once)

Run a single read-only check before making any changes:

```bash
id -u
python3 --version 2>/dev/null || echo "MISSING: python3"
python3 -m venv --help >/dev/null 2>&1 || echo "MISSING: python3-venv"
git --version 2>/dev/null || echo "MISSING: git"
ollama --version 2>/dev/null || echo "OPTIONAL_MISSING: ollama"
```

Evaluate the results:
1. **User check**: If `id -u` prints `0` (`root`), stop and ask the person to run you under a standard non-root user account.
2. **Python `>= 3.11` with `venv` (Required)**: `pyproject.toml` requires Python `3.11` or newer. If `python3` is missing, older than `3.11`, or lacks the `venv` module, ask the person before installing Python `3.11+` (`uv python install 3.12`, `pyenv`, `brew`, or OS packages).
3. **Ollama (Optional)**: `krusch-fs` works offline out of the box using deterministic local vectors when no Ollama variables are set, or connects to local Ollama (`http://127.0.0.1:11434`, default model `snowflake-arctic-embed2`, `1024d`) when `OLLAMA_URL` or `EMBED_MODEL` is configured.

## 2. Install in an Isolated Virtual Environment & Verify

Check `pwd` first so you clone into an appropriate directory (for example, `$HOME/src/krusch-fs-mcp` if `pwd` is `$HOME`):

```bash
git clone https://github.com/kruschdev/krusch-fs-mcp.git
cd krusch-fs-mcp
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e ".[dev]"
```

Ensure `krusch_nexus` (consumed in Zero-Config Library Mode for 1-based page segmentation and citations) resolves inside `.venv`:

```bash
.venv/bin/python -c "import krusch_nexus" 2>/dev/null || .venv/bin/pip install -e ".[krusch_nexus]"
```

Run the automated `pytest` verification suite (`28` tests covering FTS5 Porter stemming, Float32 vector packing, `.env` secret shield redaction, symlink/path-traversal guards, inode move tracking, PDF/DOCX page grounding, and all 6 MCP tool annotations):

```bash
.venv/bin/pytest tests/ -v
```

## 3. Initialize `$HOME/.krusch-fs` & Verify the CLI

Single-workstation mode works locally out of the box with zero SSH configuration:

```bash
mkdir -p "$HOME/.krusch-fs"
.venv/bin/krusch-fs status
```

- **Single workstation (Default)**: Scan any local directory or config file on demand:
  ```bash
  .venv/bin/krusch-fs scan "$HOME/Documents" --workspace user_docs
  .venv/bin/krusch-fs status
  ```
- **Multi-node SSH fleet (Only if requested by the person)**: Copy `fleet.example.json` without overwriting an existing config, then ask the person which SSH hostnames and `default_roots` to configure before running `sync-fleet`:
  ```bash
  [ -f "$HOME/.krusch-fs/fleet.json" ] || cp fleet.example.json "$HOME/.krusch-fs/fleet.json"
  ```

## 4. Register `krusch-fs-mcp` in the Person's Coding Agent / IDE

Capture the absolute path to `.venv/bin/krusch-fs-mcp` (`"$(pwd)/.venv/bin/krusch-fs-mcp"`) and the person's expanded `$HOME` directory (`echo "$HOME"`), then merge the `krusch-fs` entry into their active MCP client config without removing existing servers.

Exposes 6 annotated MCP tools: `krusch_fs_search`, `krusch_fs_page_tree`, `krusch_fs_read_page`, `krusch_fs_remember_on_page`, `krusch_fs_locate`, and `krusch_fs_sync`.

- **Claude Code CLI**:
  ```bash
  claude mcp add krusch-fs \
    -e KRUSCH_FS_DB_URL="sqlite:///$HOME/.krusch-fs/fs_memory.db" \
    -- "$(pwd)/.venv/bin/krusch-fs-mcp"
  ```

- **Cursor (`~/.cursor/mcp.json`), Windsurf (`~/.codeium/windsurf/mcp_config.json`), or Antigravity (`~/.gemini/antigravity/mcp_config.json`)**:
  *(Substitute `/Users/you` and `/absolute/path/to/krusch-fs-mcp` with the real paths from `echo "$HOME"` and `pwd`; only add `OLLAMA_URL` / `EMBED_MODEL` if local Ollama with `snowflake-arctic-embed2` is running.)*
  ```json
  {
    "mcpServers": {
      "krusch-fs": {
        "command": "/absolute/path/to/krusch-fs-mcp/.venv/bin/krusch-fs-mcp",
        "env": {
          "KRUSCH_FS_DB_URL": "sqlite:////Users/you/.krusch-fs/fs_memory.db"
        }
      }
    }
  }
  ```
  *(Note the 4 slashes in `sqlite:////...` for an absolute POSIX path in SQLAlchemy.)*

- **Codex (`~/.codex/config.toml`)**:
  ```toml
  [mcp_servers.krusch-fs]
  command = "/absolute/path/to/krusch-fs-mcp/.venv/bin/krusch-fs-mcp"

  [mcp_servers.krusch-fs.env]
  KRUSCH_FS_DB_URL = "sqlite:////Users/you/.krusch-fs/fs_memory.db"
  ```

## Never

- **Never run global `pip install` or `sudo pip`**: always install inside `.venv` (`python3 -m venv .venv && .venv/bin/pip install ...`).
- **Never run `krusch-fs` or `pytest` as `root` or with `sudo`**.
- **Never overwrite an existing `$HOME/.krusch-fs/fleet.json` or wipe existing entries in an IDE MCP config file**; read, parse, and merge only the `krusch-fs` server entry.
- **Never copy `fleet.example.json` and run `sync-fleet` against placeholder example hosts** (`compute-node-01`, `storage-node-01`) unless the person asked for multi-node SSH setup and supplied real hostnames.
- **Never disable privacy guards** (`KEYS_ONLY` `.env` redaction or `VAULT_LOCKED` private-key exclusions).

## Tell the Person After

Share a concise status summary:
1. **Virtual environment & database path**: Report the exact `.venv` path and SQLite store location (`$HOME/.krusch-fs/fs_memory.db`).
2. **Verification status**: Confirm `.venv/bin/pytest tests/ -v` (`28/28` tests) and `.venv/bin/krusch-fs status` succeeded.
3. **Embedding mode**: Note whether `krusch-fs` is using offline deterministic embeddings or local Ollama (`snowflake-arctic-embed2`).
4. **Configured IDEs**: List the updated MCP config files and suggest testing in their next session with: `"Run krusch_fs_locate or krusch_fs_search to verify krusch-fs is connected."`
