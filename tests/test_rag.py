from __future__ import annotations

import json
import sys
import types

import pytest

from security_review import rag


def _semantic_vector(text: str) -> list[float]:
    lowered = text.lower()
    groups = (
        ("command", "shell", "subprocess", "executable"),
        ("sql", "query", "database", "parameter"),
        ("yaml", "deserial", "object", "loader"),
    )
    return [float(sum(lowered.count(term) for term in group)) for group in groups] + [1.0]


@pytest.fixture
def fake_ollama(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, list[str], str]]:
    calls: list[tuple[str, list[str], str]] = []

    class FakeClient:
        def __init__(self, host: str) -> None:
            self.host = host

        def embed(self, *, model: str, input: list[str]) -> dict[str, list[list[float]]]:
            calls.append((model, input, self.host))
            return {"embeddings": [_semantic_vector(text) for text in input]}

    monkeypatch.setitem(sys.modules, "ollama", types.SimpleNamespace(Client=FakeClient))
    return calls


def test_build_and_search_real_notes(
    tmp_path, monkeypatch: pytest.MonkeyPatch, fake_ollama
) -> None:
    monkeypatch.setenv("SECURITY_REVIEW_EMBED_MODEL", "test-minilm")
    index_path = tmp_path / "nested" / "index.json"

    assert rag.build_index(index_path) == index_path
    payload = json.loads(index_path.read_text(encoding="utf-8"))

    assert payload["embedding_model"] == "test-minilm"
    assert payload["dimensions"] == 4
    assert len(payload["chunks"]) == 6
    assert {chunk["cwe"] for chunk in payload["chunks"]} == {
        "CWE-78",
        "CWE-89",
        "CWE-502",
    }
    assert all(chunk["source_url"].startswith("https://") for chunk in payload["chunks"])
    assert all(chunk["text"] and chunk["embedding"] for chunk in payload["chunks"])

    results = rag.search_docs(
        "unsafe YAML object deserialization loader", index_path=index_path, top_k=2
    )

    assert len(results) == 2
    assert all(result["cwe"] == "CWE-502" for result in results)
    assert set(results[0]) == {"title", "cwe", "source_url", "text", "score"}
    assert results[0]["score"] >= results[1]["score"] > 0
    assert fake_ollama[0][0] == "test-minilm"
    assert fake_ollama[-1][2] == "http://127.0.0.1:11434"


def test_chunking_is_deterministic_and_overlapping() -> None:
    words = [f"word-{position}" for position in range(700)]

    chunks = rag._chunk_text(" ".join(words))
    split_chunks = [chunk.split() for chunk in chunks]

    assert [len(chunk) for chunk in split_chunks] == [275, 275, 230]
    assert split_chunks[0][-40:] == split_chunks[1][:40]
    assert split_chunks[1][-40:] == split_chunks[2][:40]
    assert chunks == rag._chunk_text(" ".join(words))


def test_explicit_cwe_reference_filters_candidates(tmp_path, fake_ollama) -> None:
    index_path = rag.build_index(tmp_path / "index.json")

    results = rag.search_docs("How should CWE-78 be fixed?", index_path, top_k=10)

    assert len(results) == 2
    assert {result["cwe"] for result in results} == {"CWE-78"}


def test_search_requires_prebuilt_index(tmp_path) -> None:
    missing = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError, match=r"build_index\(\) first"):
        rag.search_docs("SQL injection", index_path=missing)


def test_search_rejects_embedding_dimension_mismatch(tmp_path, fake_ollama) -> None:
    index_path = tmp_path / "index.json"
    index_path.write_text(
        json.dumps(
            {
                "embedding_model": "test-minilm",
                "dimensions": 3,
                "chunks": [
                    {
                        "title": "Example",
                        "cwe": "CWE-89",
                        "source_url": "https://example.test",
                        "text": "SQL query",
                        "embedding": [1.0, 0.0, 0.0],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="index expects 3"):
        rag.search_docs("SQL query", index_path=index_path)
