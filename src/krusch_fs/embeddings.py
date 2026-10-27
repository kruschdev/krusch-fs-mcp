"""
KruschFS Local Embedding & Similarity Helper (embeddings.py)
============================================================
Provides zero-egress local embeddings (`INV-1` & `INV-FS-VEC-01`):
- `deterministic`: Fast feature-hashed n-gram 1024-d unit vector (zero external daemon latency).
- `ollama`: Local Ollama HTTP `/api/embed` (`snowflake-arctic-embed2`, 1024-d) with legacy
  `/api/embeddings` 404 fallback, asymmetric query prefixing, isotropic cosine calibration,
  and strict fail-null isolation (never silently poisoning neural indices with hash vectors).
"""

import re
import math
import json
import hashlib
import threading
import urllib.error
import urllib.request
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    from krusch_toolkit.embeddings import format_embedding_input as _tk_format_embedding_input  # type: ignore
except Exception:
    _tk_format_embedding_input = None

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")
_SUMPROD = getattr(math, "sumprod", None)

_EMBED_CACHE_MAX = 512
_EMBED_CACHE: "OrderedDict[Tuple[int, str, str, str, str, str], List[float]]" = OrderedDict()
_EMBED_CACHE_LOCK = threading.Lock()
_LAST_URLOPEN_REF: Any = urllib.request.urlopen

_QWEN3_DOMAIN_TASKS: Dict[str, str] = {
    "general": "Given a web search query, retrieve relevant passages that answer the query",
    "code": "Given a code search query, retrieve relevant code snippets that answer the query",
    "law": "Given a legal search query, retrieve relevant statutory passages that answer the query",
    "legal": "Given a legal search query, retrieve relevant statutory passages that answer the query",
    "biz": "Given a business contract query, retrieve relevant clauses and propositions that answer the query",
    "fs": "Given a filesystem or configuration query, retrieve relevant file pages and notes that answer the query",
    "memory": "Given a search query, retrieve relevant technical memories and invariants that answer the query",
}


def clear_embed_cache() -> None:
    """Clear the in-process Ollama embedding LRU cache."""
    with _EMBED_CACHE_LOCK:
        _EMBED_CACHE.clear()


def _normalize_model_name(model: Optional[str]) -> str:
    raw = (model or "").strip().lower()
    changed = True
    while changed:
        changed = False
        for prefix in ("ollama/", "models/"):
            if raw.startswith(prefix):
                raw = raw[len(prefix):].strip()
                changed = True
    if raw.endswith(":latest"):
        raw = raw[:-7].strip()
    return raw or "snowflake-arctic-embed2"


def _ollama_api_model_name(model: Optional[str]) -> str:
    raw = (model or "").strip()
    lower = raw.lower()
    if lower.startswith("ollama/"):
        raw = raw[7:].strip()
    elif lower.startswith("models/"):
        raw = raw[7:].strip()
    return raw or "snowflake-arctic-embed2"


def _max_input_chars(norm_model: str) -> int:
    if norm_model.startswith("bge-large"):
        return 1150
    return 6000


def _validate_and_normalize_vec(vec: Any, dim: int) -> Optional[List[float]]:
    if not isinstance(vec, list) or len(vec) != dim:
        return None
    floats: List[float] = []
    sq_sum = 0.0
    try:
        for v in vec:
            if isinstance(v, bool):
                return None
            fv = float(v)
            if not math.isfinite(fv):
                return None
            floats.append(fv)
            sq_sum += fv * fv
    except (TypeError, ValueError, OverflowError):
        return None
    norm = math.sqrt(sq_sum)
    if not math.isfinite(norm) or norm <= 1e-12:
        return None
    return [fv / norm for fv in floats]


def _cache_get(key: Optional[Tuple[int, str, str, str, str, str]]) -> Optional[List[float]]:
    global _LAST_URLOPEN_REF
    with _EMBED_CACHE_LOCK:
        if urllib.request.urlopen is not _LAST_URLOPEN_REF:
            _EMBED_CACHE.clear()
            _LAST_URLOPEN_REF = urllib.request.urlopen
            return None
        if key is None or key not in _EMBED_CACHE:
            return None
        _EMBED_CACHE.move_to_end(key)
        return list(_EMBED_CACHE[key])


def _cache_put(key: Optional[Tuple[int, str, str, str, str, str]], vec: List[float]) -> None:
    if key is None:
        return
    with _EMBED_CACHE_LOCK:
        _EMBED_CACHE[key] = list(vec)
        _EMBED_CACHE.move_to_end(key)
        while len(_EMBED_CACHE) > _EMBED_CACHE_MAX:
            _EMBED_CACHE.popitem(last=False)


def _deterministic_token_vector(text: str, dim: int = 1024) -> List[float]:
    """
    Compute a normalized 1024-d feature-hashed vector from word unigrams and bigrams
    so semantic/lexical cosine similarity works deterministically offline in <0.2ms.
    """
    vec = [0.0] * dim
    tokens = TOKEN_RE.findall((text or "").lower())
    if not tokens:
        vec[0] = 1.0
        return vec

    features = list(tokens)
    for i in range(len(tokens) - 1):
        features.append(f"{tokens[i]}_{tokens[i + 1]}")

    for feat in features:
        digest = hashlib.blake2b(feat.encode("utf-8"), digest_size=8).digest()
        idx = int.from_bytes(digest[:4], "little") % dim
        sign = 1.0 if (digest[4] & 1) == 0 else -1.0
        vec[idx] += sign

    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0:
        vec = [v / norm for v in vec]
    return vec


def canonical_embed_model_tag(
    backend: str = "deterministic",
    model: str = "snowflake-arctic-embed2",
) -> str:
    """Return canonical vector-space tag for strict index/query model-space isolation."""
    if (backend or "").strip().lower() != "ollama":
        return "deterministic:blake2b-v1"
    norm = _normalize_model_name(model)
    return f"ollama:{norm}"


def format_embedding_input(
    text: str,
    model: str = "snowflake-arctic-embed2",
    mode: str = "document",
    domain: str = "general",
    instruction: Optional[str] = None,
) -> str:
    """Apply model-specific asymmetric query prefixes while keeping documents unmodified."""
    if not text:
        return ""
    if (mode or "document").strip().lower() != "query":
        return text

    norm_model = _normalize_model_name(model)
    if norm_model.startswith("snowflake-arctic-embed2"):
        if text.lower().startswith("query: "):
            return text
        return f"query: {text}"

    if norm_model.startswith("bge-large"):
        prefix = "Represent this sentence for searching relevant passages: "
        if text.startswith(prefix):
            return text
        return f"{prefix}{text}"

    if norm_model.startswith("nomic-embed-text"):
        prefix = "search_query: "
        if text.startswith(prefix):
            return text
        return f"{prefix}{text}"

    if norm_model.startswith("qwen3-embedding"):
        if text.startswith("Instruct: ") and "\nQuery:" in text:
            return text
        if instruction and instruction.strip():
            return f"Instruct: {instruction.strip()}\nQuery:{text}"
        if _tk_format_embedding_input is not None:
            try:
                formatted = _tk_format_embedding_input(
                    text,
                    model=norm_model,
                    mode="query",
                    domain=domain,
                    instruction=instruction,
                )
                if isinstance(formatted, str) and formatted:
                    return formatted
            except Exception:
                pass
        dom_key = (domain or "general").strip().lower()
        task = _QWEN3_DOMAIN_TASKS.get(dom_key, _QWEN3_DOMAIN_TASKS["general"])
        return f"Instruct: {task}\nQuery:{text}"

    return text


def calibrate_query_similarity(
    raw_cosine: float,
    model: str = "snowflake-arctic-embed2",
    backend: str = "deterministic",
    query_vec: Optional[Sequence[float]] = None,
) -> float:
    """Piecewise concave isotropic cosine calibration for contrastive neural embeddings."""
    try:
        raw = float(raw_cosine)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(raw) or raw <= 0.0:
        return 0.0
    if raw >= 1.0:
        return 1.0
    if (backend or "").strip().lower() != "ollama":
        return raw

    if query_vec is not None and len(query_vec) > 0:
        sample = query_vec[:64]
        try:
            nnz = sum(1 for x in sample if abs(float(x)) > 1e-7)
            if nnz < min(12, len(sample)):
                return raw
        except (TypeError, ValueError):
            return raw

    norm_model = _normalize_model_name(model)
    if norm_model.startswith(("snowflake-arctic-embed2", "qwen3-embedding")):
        if raw <= 0.12:
            cal = raw * 3.0
        elif raw <= 0.38:
            cal = 0.36 + ((raw - 0.12) / 0.26) * 0.32
        elif raw <= 0.60:
            cal = 0.68 + ((raw - 0.38) / 0.22) * 0.16
        else:
            cal = 0.84 + ((raw - 0.60) / 0.40) * 0.16
        return min(1.0, max(0.0, float(cal)))

    return raw


def _ollama_legacy_single_embed(
    base_url: str,
    api_model: str,
    norm_model: str,
    truncated_text: str,
    dim: int,
    timeout: float = 8.0,
) -> Optional[List[float]]:
    legacy_payload: Dict[str, Any] = {
        "model": api_model,
        "prompt": truncated_text,
        "truncate": True,
        "keep_alive": -1,
    }
    if norm_model.startswith(("qwen3-embedding", "nomic-embed-text")):
        legacy_payload["dimensions"] = dim
    try:
        legacy_req = urllib.request.Request(
            f"{base_url}/api/embeddings",
            data=json.dumps(legacy_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(legacy_req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) == 200:
                data = json.loads(resp.read().decode("utf-8"))
                embeddings = data.get("embeddings")
                raw_vec = (
                    embeddings[0]
                    if isinstance(embeddings, list) and embeddings
                    else data.get("embedding")
                )
                return _validate_and_normalize_vec(raw_vec, dim)
    except Exception:
        return None
    return None


def embed_text(
    text: str,
    backend: str = "deterministic",
    ollama_url: str = "http://127.0.0.1:11434",
    model: str = "snowflake-arctic-embed2",
    dim: int = 1024,
    mode: str = "document",
    domain: str = "general",
) -> Optional[List[float]]:
    """
    Generate a 1024-d unit embedding vector locally with zero cloud egress.
    In `ollama` mode, returns `None` on empty input or any daemon/validation failure
    (never falling back to `_deterministic_token_vector`).
    """
    if (backend or "").strip().lower() != "ollama":
        return _deterministic_token_vector(text, dim=dim)

    if not (text or "").strip():
        return None

    base_url = (ollama_url or "http://127.0.0.1:11434").strip().rstrip("/")
    norm_model = _normalize_model_name(model)
    api_model = _ollama_api_model_name(model)
    model_tag = canonical_embed_model_tag("ollama", model)
    formatted = format_embedding_input(text, model=model, mode=mode, domain=domain)
    if not formatted.strip():
        return None

    cache_key = (
        (dim, base_url, model_tag, mode, domain, formatted[:2000])
        if len(formatted) <= 2000
        else None
    )
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    max_chars = _max_input_chars(norm_model)
    truncated = formatted[:max_chars]
    payload: Dict[str, Any] = {
        "model": api_model,
        "input": truncated,
        "truncate": True,
        "keep_alive": -1,
    }
    if norm_model.startswith(("qwen3-embedding", "nomic-embed-text")):
        payload["dimensions"] = dim

    norm_vec: Optional[List[float]] = None
    try:
        req = urllib.request.Request(
            f"{base_url}/api/embed",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8.0) as resp:
            if getattr(resp, "status", 200) == 200:
                data = json.loads(resp.read().decode("utf-8"))
                embeddings = data.get("embeddings")
                raw_vec = (
                    embeddings[0]
                    if isinstance(embeddings, list) and embeddings
                    else data.get("embedding")
                )
                norm_vec = _validate_and_normalize_vec(raw_vec, dim)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            norm_vec = _ollama_legacy_single_embed(
                base_url=base_url,
                api_model=api_model,
                norm_model=norm_model,
                truncated_text=truncated,
                dim=dim,
                timeout=8.0,
            )
    except Exception:
        norm_vec = None

    if norm_vec is not None:
        _cache_put(cache_key, norm_vec)
    return norm_vec


def embed_batch(
    texts: Sequence[str],
    backend: str = "deterministic",
    ollama_url: str = "http://127.0.0.1:11434",
    model: str = "snowflake-arctic-embed2",
    dim: int = 1024,
    mode: str = "document",
    domain: str = "general",
    batch_size: int = 32,
) -> List[Optional[List[float]]]:
    """
    Batch-embed texts preserving exact order and length.
    In `ollama` mode, empty/failed items return `None` without poisoning with hash vectors.
    """
    if not texts:
        return []

    if (backend or "").strip().lower() != "ollama":
        return [
            _deterministic_token_vector(t if (t or "").strip() else "", dim=dim)
            for t in texts
        ]

    results: List[Optional[List[float]]] = [None] * len(texts)
    base_url = (ollama_url or "http://127.0.0.1:11434").strip().rstrip("/")
    norm_model = _normalize_model_name(model)
    api_model = _ollama_api_model_name(model)
    model_tag = canonical_embed_model_tag("ollama", model)
    max_chars = _max_input_chars(norm_model)
    eff_batch_size = max(1, int(batch_size or 32))

    pending: List[Tuple[int, str, Optional[Tuple[int, str, str, str, str, str]]]] = []
    for idx, raw_text in enumerate(texts):
        if not (raw_text or "").strip():
            continue
        formatted = format_embedding_input(raw_text, model=model, mode=mode, domain=domain)
        if not formatted.strip():
            continue
        cache_key = (
            (dim, base_url, model_tag, mode, domain, formatted[:2000])
            if len(formatted) <= 2000
            else None
        )
        cached = _cache_get(cache_key)
        if cached is not None:
            results[idx] = cached
        else:
            pending.append((idx, formatted[:max_chars], cache_key))

    for start in range(0, len(pending), eff_batch_size):
        chunk = pending[start : start + eff_batch_size]
        payload: Dict[str, Any] = {
            "model": api_model,
            "input": [item[1] for item in chunk],
            "truncate": True,
            "keep_alive": -1,
        }
        if norm_model.startswith(("qwen3-embedding", "nomic-embed-text")):
            payload["dimensions"] = dim

        try:
            req = urllib.request.Request(
                f"{base_url}/api/embed",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=20.0) as resp:
                if getattr(resp, "status", 200) == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    embeddings = data.get("embeddings")
                    if isinstance(embeddings, list) and len(embeddings) == len(chunk):
                        for (orig_idx, _, cache_key), raw_vec in zip(chunk, embeddings):
                            norm_vec = _validate_and_normalize_vec(raw_vec, dim)
                            if norm_vec is not None:
                                results[orig_idx] = norm_vec
                                _cache_put(cache_key, norm_vec)
                    elif len(chunk) == 1 and isinstance(data.get("embedding"), list):
                        orig_idx, _, cache_key = chunk[0]
                        norm_vec = _validate_and_normalize_vec(data.get("embedding"), dim)
                        if norm_vec is not None:
                            results[orig_idx] = norm_vec
                            _cache_put(cache_key, norm_vec)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                for orig_idx, trunc_text, cache_key in chunk:
                    norm_vec = _ollama_legacy_single_embed(
                        base_url=base_url,
                        api_model=api_model,
                        norm_model=norm_model,
                        truncated_text=trunc_text,
                        dim=dim,
                        timeout=8.0,
                    )
                    if norm_vec is not None:
                        results[orig_idx] = norm_vec
                        _cache_put(cache_key, norm_vec)
            elif len(chunk) > 1:
                for orig_idx, trunc_text, cache_key in chunk:
                    single_payload: Dict[str, Any] = {
                        "model": api_model,
                        "input": trunc_text,
                        "truncate": True,
                        "keep_alive": -1,
                    }
                    if norm_model.startswith(("qwen3-embedding", "nomic-embed-text")):
                        single_payload["dimensions"] = dim
                    try:
                        s_req = urllib.request.Request(
                            f"{base_url}/api/embed",
                            data=json.dumps(single_payload).encode("utf-8"),
                            headers={"Content-Type": "application/json"},
                            method="POST",
                        )
                        with urllib.request.urlopen(s_req, timeout=8.0) as s_resp:
                            if getattr(s_resp, "status", 200) == 200:
                                s_data = json.loads(s_resp.read().decode("utf-8"))
                                s_embs = s_data.get("embeddings")
                                s_raw = (
                                    s_embs[0]
                                    if isinstance(s_embs, list) and s_embs
                                    else s_data.get("embedding")
                                )
                                norm_vec = _validate_and_normalize_vec(s_raw, dim)
                                if norm_vec is not None:
                                    results[orig_idx] = norm_vec
                                    _cache_put(cache_key, norm_vec)
                    except Exception:
                        continue
        except Exception:
            continue

    return results


def fast_unit_dot(q_vec: Sequence[float], doc_vec: Sequence[float]) -> float:
    """Fast C-level dot product for pre-normalized unit vectors, clamped to [0.0, 1.0]."""
    if not q_vec or not doc_vec or len(q_vec) != len(doc_vec):
        return 0.0
    if _SUMPROD is not None:
        dot = _SUMPROD(q_vec, doc_vec)
    else:
        dot = sum(a * b for a, b in zip(q_vec, doc_vec))
    if not math.isfinite(dot) or dot <= 0.0:
        return 0.0
    return 1.0 if dot >= 1.0 else float(dot)


def cosine_similarity(v1: Sequence[float], v2: Sequence[float]) -> float:
    """Compute cosine similarity between two equal-dimension float vectors."""
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    if _SUMPROD is not None:
        dot = _SUMPROD(v1, v2)
        n1 = math.sqrt(_SUMPROD(v1, v1))
        n2 = math.sqrt(_SUMPROD(v2, v2))
    else:
        dot = sum(a * b for a, b in zip(v1, v2))
        n1 = math.sqrt(sum(a * a for a in v1))
        n2 = math.sqrt(sum(b * b for b in v2))
    if (
        not math.isfinite(dot)
        or not math.isfinite(n1)
        or not math.isfinite(n2)
        or n1 <= 0.0
        or n2 <= 0.0
    ):
        return 0.0
    sim = dot / (n1 * n2)
    if sim <= 0.0:
        return 0.0
    return 1.0 if sim >= 1.0 else float(sim)
