"""Tiny local retrieval for the security review agent.

The source notes are deliberately small and the generated index is plain JSON.
Only embedding calls go through Ollama; ranking is implemented here so no vector
database or retrieval framework is required.
"""

from __future__ import annotations

import json
import math
import os
import re
from pathlib import Path
from typing import Any, Mapping, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCES_DIR = PROJECT_ROOT / "knowledge" / "sources"
DEFAULT_INDEX_PATH = PROJECT_ROOT / "knowledge" / "index.json"
DEFAULT_EMBED_MODEL = "all-minilm"
OLLAMA_HOST = "http://127.0.0.1:11434"

_MIN_CHUNK_WORDS = 200
_TARGET_CHUNK_WORDS = 275
_MAX_CHUNK_WORDS = 350
_CHUNK_OVERLAP_WORDS = 40
_REQUIRED_METADATA = ("title", "cwe", "source_url")
_SUPPORTED_CWE_IDS = ("78", "89", "502")


def _parse_note(path: Path) -> tuple[dict[str, str], str]:
    """Read the small front matter format used by knowledge/sources/*.md."""
    raw = path.read_text(encoding="utf-8")
    lines = raw.splitlines()
    if not lines or lines[0].strip() != "---":
        raise ValueError(f"Knowledge note {path} is missing front matter")

    try:
        end = next(i for i, line in enumerate(lines[1:], 1) if line.strip() == "---")
    except StopIteration as exc:
        raise ValueError(f"Knowledge note {path} has unclosed front matter") from exc

    metadata: dict[str, str] = {}
    for line in lines[1:end]:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            raise ValueError(f"Invalid metadata line in {path}: {line!r}")
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip().strip('"\'')

    missing = [key for key in _REQUIRED_METADATA if not metadata.get(key)]
    if missing:
        raise ValueError(f"Knowledge note {path} is missing: {', '.join(missing)}")

    text = "\n".join(lines[end + 1 :]).strip()
    if not text:
        raise ValueError(f"Knowledge note {path} has no text")
    return metadata, text


def _chunk_text(text: str) -> list[str]:
    """Split text into deterministic 200-350 word windows with small overlap."""
    words = text.split()
    if not words:
        return []
    if len(words) <= _MAX_CHUNK_WORDS:
        return [" ".join(words)]

    chunks: list[str] = []
    start = 0
    while len(words) - start > _MAX_CHUNK_WORDS:
        end = start + _TARGET_CHUNK_WORDS
        words_after_overlap = len(words) - (end - _CHUNK_OVERLAP_WORDS)
        if words_after_overlap < _MIN_CHUNK_WORDS:
            end = len(words) - _MIN_CHUNK_WORDS + _CHUNK_OVERLAP_WORDS
        chunks.append(" ".join(words[start:end]))
        start = end - _CHUNK_OVERLAP_WORDS
    chunks.append(" ".join(words[start:]))
    return chunks


def _response_embeddings(response: Any) -> list[list[float]]:
    if isinstance(response, Mapping):
        raw_vectors = response.get("embeddings")
    else:
        raw_vectors = getattr(response, "embeddings", None)
    if raw_vectors is None:
        raise RuntimeError("Ollama returned no embeddings")

    try:
        vectors = [[float(value) for value in vector] for vector in raw_vectors]
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Ollama returned malformed embeddings") from exc
    if not vectors or any(not vector for vector in vectors):
        raise RuntimeError("Ollama returned empty embeddings")
    return vectors


def _embed_texts(texts: Sequence[str], model: str) -> list[list[float]]:
    try:
        import ollama
    except ImportError as exc:  # pragma: no cover - dependency is declared by the app
        raise RuntimeError("The 'ollama' package is required for local embeddings") from exc

    try:
        response = ollama.Client(host=OLLAMA_HOST).embed(model=model, input=list(texts))
    except Exception as exc:
        raise RuntimeError(
            f"Could not create embeddings with local Ollama model {model!r} at {OLLAMA_HOST}"
        ) from exc
    vectors = _response_embeddings(response)
    if len(vectors) != len(texts):
        raise RuntimeError(
            f"Ollama returned {len(vectors)} embeddings for {len(texts)} texts"
        )
    return vectors


def build_index(index_path: Path | None = None) -> Path:
    """Embed the bundled notes and write a portable JSON index."""
    destination = Path(index_path) if index_path is not None else DEFAULT_INDEX_PATH
    source_paths = sorted(SOURCES_DIR.glob("*.md"))
    if not source_paths:
        raise FileNotFoundError(f"No knowledge notes found in {SOURCES_DIR}")

    chunks: list[dict[str, Any]] = []
    for source_path in source_paths:
        metadata, text = _parse_note(source_path)
        for position, chunk_text in enumerate(_chunk_text(text)):
            chunks.append(
                {
                    "title": metadata["title"],
                    "cwe": metadata["cwe"],
                    "source_url": metadata["source_url"],
                    "text": chunk_text,
                    "source_file": source_path.name,
                    "chunk": position,
                }
            )

    model = os.environ.get("SECURITY_REVIEW_EMBED_MODEL", DEFAULT_EMBED_MODEL)
    vectors = _embed_texts([chunk["text"] for chunk in chunks], model)
    dimensions = len(vectors[0])
    if any(len(vector) != dimensions for vector in vectors):
        raise RuntimeError("Ollama returned embeddings with inconsistent dimensions")
    for chunk, vector in zip(chunks, vectors, strict=True):
        chunk["embedding"] = vector

    payload = {
        "version": 1,
        "embedding_model": model,
        "dimensions": dimensions,
        "chunks": chunks,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return destination


def _cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float:
    if len(left) != len(right):
        raise ValueError("Embedding dimensions do not match")
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if left_norm == 0.0 or right_norm == 0.0:
        return 0.0
    return sum(a * b for a, b in zip(left, right, strict=True)) / (
        left_norm * right_norm
    )


def _cwes_in_query(query: str) -> set[str]:
    """Return supported explicit CWE references in a user's query."""
    supported = "|".join(_SUPPORTED_CWE_IDS)
    matches = re.findall(rf"\bCWE\s*[-_:]?\s*({supported})\b", query, re.IGNORECASE)
    return {f"CWE-{identifier}" for identifier in matches}


def search_docs(
    query: str, index_path: Path | None = None, top_k: int = 2
) -> list[dict[str, Any]]:
    """Return the most similar note chunks from an existing local index."""
    if not query.strip():
        raise ValueError("query must not be empty")
    if top_k <= 0:
        return []

    path = Path(index_path) if index_path is not None else DEFAULT_INDEX_PATH
    if not path.is_file():
        raise FileNotFoundError(
            f"RAG index not found at {path}. Run security_review.rag.build_index() first."
        )

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        model = str(payload["embedding_model"])
        dimensions = int(payload["dimensions"])
        chunks = payload["chunks"]
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"Invalid RAG index at {path}") from exc
    if not isinstance(chunks, list) or not chunks:
        raise ValueError(f"RAG index at {path} contains no chunks")

    query_vector = _embed_texts([query], model)[0]
    if len(query_vector) != dimensions:
        raise ValueError(
            f"Query embedding has {len(query_vector)} dimensions; index expects {dimensions}"
        )

    ranked: list[dict[str, Any]] = []
    requested_cwes = _cwes_in_query(query)
    for chunk in chunks:
        try:
            chunk_cwe = str(chunk["cwe"])
            if requested_cwes and chunk_cwe.upper() not in requested_cwes:
                continue
            score = _cosine_similarity(query_vector, chunk["embedding"])
            result = {
                "title": str(chunk["title"]),
                "cwe": chunk_cwe,
                "source_url": str(chunk["source_url"]),
                "text": str(chunk["text"]),
                "score": float(score),
            }
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Invalid chunk in RAG index at {path}") from exc
        ranked.append(result)

    ranked.sort(key=lambda item: (-item["score"], item["title"], item["text"]))
    return ranked[:top_k]
