"""Context retrieval for the RAG pipeline.

Two tiers:
  1. SQLite keyword search — always available, zero extra deps.
  2. ChromaDB vector search — optional, activated when ``chromadb`` is
     installed and an index has been built via ``analyzer llm index``.

Both tiers return plain text chunks that the prompt builder assembles into
the LLM context window.
"""

from __future__ import annotations

import importlib.util
import re
import sqlite3
from pathlib import Path

# ---------------------------------------------------------------------------
# Stopwords (very minimal — just to avoid single-char matches)
# ---------------------------------------------------------------------------

_STOPWORDS = {
    "a",
    "an",
    "the",
    "is",
    "are",
    "was",
    "were",
    "be",
    "been",
    "in",
    "on",
    "at",
    "to",
    "for",
    "of",
    "and",
    "or",
    "but",
    "what",
    "why",
    "how",
    "when",
    "where",
    "which",
    "who",
    "do",
    "does",
    "did",
    "have",
    "has",
    "had",
    "i",
    "me",
    "my",
    "we",
    "you",
    "he",
    "she",
    "it",
    "they",
}


def _keywords(question: str) -> list[str]:
    """Extract meaningful keywords from a natural language question."""
    words = re.findall(r"[a-zA-Z0-9_\-]{2,}", question.lower())
    return [w for w in words if w not in _STOPWORDS]


# ---------------------------------------------------------------------------
# Tier 1 — SQLite keyword search
# ---------------------------------------------------------------------------


def _sqlite_search(db_path: Path, keywords: list[str], limit: int = 6) -> list[str]:
    """Return text chunks matching any of the keywords from the errors table."""
    if not db_path.exists() or not keywords:
        return []

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    chunks: list[str] = []

    try:
        for kw in keywords[:5]:
            pattern = f"%{kw}%"
            rows = conn.execute(
                """
                SELECT error_type, normalized_msg, severity, count, last_seen
                FROM errors
                WHERE error_type LIKE ?
                   OR normalized_msg LIKE ?
                ORDER BY count DESC
                LIMIT ?
                """,
                (pattern, pattern, limit),
            ).fetchall()
            for row in rows:
                chunk = (
                    f"[ERROR] {row['error_type']} | severity={row['severity']} "
                    f"| count={row['count']} | last_seen={row['last_seen'][:19]}\n"
                    f"  {row['normalized_msg'][:300]}"
                )
                if chunk not in chunks:
                    chunks.append(chunk)

        # Also search findings table if it has data
        try:
            for kw in keywords[:5]:
                pattern = f"%{kw}%"
                rows = conn.execute(
                    """
                    SELECT rule_id, severity, message, source, created_at
                    FROM findings
                    WHERE message LIKE ?
                       OR rule_id LIKE ?
                    ORDER BY created_at DESC
                    LIMIT ?
                    """,
                    (pattern, pattern, limit),
                ).fetchall()
                for row in rows:
                    chunk = (
                        f"[FINDING] {row['rule_id']} | severity={row['severity']} "
                        f"| source={row['source']} | at={row['created_at'][:19]}\n"
                        f"  {row['message'][:300]}"
                    )
                    if chunk not in chunks:
                        chunks.append(chunk)
        except sqlite3.OperationalError:
            pass  # findings table may not exist yet

    finally:
        conn.close()

    return chunks[:limit]


# ---------------------------------------------------------------------------
# Tier 2 — ChromaDB vector search (optional)
# ---------------------------------------------------------------------------


def _chroma_available() -> bool:
    return importlib.util.find_spec("chromadb") is not None


def _chroma_search(
    chroma_path: Path,
    query_embedding: list[float],
    limit: int = 5,
) -> list[str]:
    """Query the ChromaDB collection for the nearest neighbours."""
    import chromadb  # type: ignore[import]

    client = chromadb.PersistentClient(path=str(chroma_path))
    try:
        col = client.get_collection("logsense")
    except Exception:
        return []

    results = col.query(
        query_embeddings=[query_embedding],
        n_results=min(limit, col.count()),
        include=["documents", "metadatas"],
    )
    chunks = []
    for doc, meta in zip(
        results.get("documents", [[]])[0],
        results.get("metadatas", [[]])[0],
    ):
        prefix = f"[{meta.get('kind', 'item').upper()}] {meta.get('label', '')}"
        chunks.append(f"{prefix}\n  {doc[:300]}")
    return chunks


def build_chroma_index(db_path: Path, chroma_path: Path, client) -> int:
    """Build (or rebuild) the ChromaDB index from the errors table.

    Args:
        db_path: SQLite database path.
        chroma_path: Directory where ChromaDB stores its files.
        client: OllamaClient (used for embeddings).

    Returns:
        Number of documents indexed.
    """
    if not _chroma_available():
        raise RuntimeError("chromadb is not installed. Run: pip install chromadb")

    import chromadb  # type: ignore[import]

    chroma = chromadb.PersistentClient(path=str(chroma_path))
    # Delete old collection if it exists
    try:
        chroma.delete_collection("logsense")
    except Exception:
        pass
    col = chroma.create_collection("logsense")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT fingerprint, error_type, normalized_msg, severity, count FROM errors"
    ).fetchall()
    conn.close()

    ids, docs, embeddings, metas = [], [], [], []
    for row in rows:
        text = f"{row['error_type']}: {row['normalized_msg']}"
        vec = client.embed(text)
        if not vec:
            continue
        ids.append(row["fingerprint"])
        docs.append(text[:500])
        embeddings.append(vec)
        metas.append(
            {
                "kind": "error",
                "label": f"{row['error_type']} (count={row['count']}, sev={row['severity']})",
                "severity": row["severity"],
                "count": row["count"],
            }
        )

    if ids:
        col.add(ids=ids, documents=docs, embeddings=embeddings, metadatas=metas)

    return len(ids)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def retrieve_context(
    question: str,
    db_path: Path,
    chroma_path: Path | None = None,
    ollama_client=None,
    limit: int = 6,
) -> list[str]:
    """Return a list of text chunks relevant to the question.

    Always does SQLite keyword search.  If ChromaDB is available, an index
    has been built, and an Ollama client is provided, also does vector search
    and merges results (deduped).
    """
    keywords = _keywords(question)
    chunks = _sqlite_search(db_path, keywords, limit=limit)

    # Vector search (optional enrichment)
    if chroma_path is not None and _chroma_available() and ollama_client is not None:
        try:
            vec = ollama_client.embed(question)
            if vec:
                vec_chunks = _chroma_search(chroma_path, vec, limit=limit)
                for c in vec_chunks:
                    if c not in chunks:
                        chunks.append(c)
        except Exception:
            pass  # vector search failure is non-fatal

    return chunks[:limit]
