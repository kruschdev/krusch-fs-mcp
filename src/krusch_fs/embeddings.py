"""
KruschFS Local Embedding & Similarity Helper (embeddings.py)
============================================================
Provides zero-egress local embeddings (`INV-1`):
- `deterministic`: Fast feature-hashed n-gram 1024-d unit vector (zero external daemon latency).
- `ollama`: Local Ollama HTTP `/api/embeddings` (`bge-large`, 1024-d) with graceful fallback.
"""

import re
import math
import hashlib
from typing import List
import requests

TOKEN_RE = re.compile(r"[a-z0-9_]{2,}")


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


def embed_text(
    text: str,
    backend: str = "deterministic",
    ollama_url: str = "http://127.0.0.1:11434",
    model: str = "bge-large",
    dim: int = 1024,
) -> List[float]:
    """Generate a 1024-d embedding vector locally with zero cloud egress."""
    if backend == "ollama":
        try:
            resp = requests.post(
                f"{ollama_url.rstrip('/')}/api/embeddings",
                json={"model": model, "prompt": text[:4000]},
                timeout=3.0,
            )
            if resp.status_code == 200:
                vec = resp.json().get("embedding")
                if isinstance(vec, list) and len(vec) == dim:
                    return vec
        except Exception:
            pass
    return _deterministic_token_vector(text, dim=dim)


def cosine_similarity(v1: List[float], v2: List[float]) -> float:
    """Compute cosine similarity between two equal-dimension float vectors."""
    if not v1 or not v2 or len(v1) != len(v2):
        return 0.0
    dot = sum(a * b for a, b in zip(v1, v2))
    n1 = math.sqrt(sum(a * a for a in v1))
    n2 = math.sqrt(sum(b * b for b in v2))
    if n1 == 0.0 or n2 == 0.0:
        return 0.0
    return max(0.0, dot / (n1 * n2))
