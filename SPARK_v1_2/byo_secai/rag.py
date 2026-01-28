from __future__ import annotations

import json
import math
import pickle
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# Files supported for the on-disk Knowledge Library.
SUPPORTED_LIBRARY_EXTS = {".pdf", ".docx", ".txt", ".md"}


@dataclass
class RagChunk:
    chunk_id: str
    source_id: str
    source_type: str
    text: str
    meta: Dict[str, Any]


class RagIndex:
    """A lightweight, fully-local RAG index.

    Design goals:
    - No external services
    - Fast enough for Streamlit reruns
    - Deterministic / debuggable

    Implementation:
    - TF-IDF vectorization (scikit-learn)
    - Cosine similarity retrieval
    """

    def __init__(self, index_dir: str):
        self.index_dir = Path(index_dir).expanduser().resolve()
        self._vectorizer = None
        self._matrix = None
        self._chunks: List[RagChunk] = []

    # ---------------------------- paths ---------------------------------

    @property
    def _chunks_path(self) -> Path:
        return self.index_dir / "chunks.json"

    @property
    def _model_path(self) -> Path:
        return self.index_dir / "tfidf.pkl"

    # ---------------------------- build ---------------------------------

    @staticmethod
    def _clean_text(s: str) -> str:
        s = (s or "").strip()
        # collapse whitespace
        s = re.sub(r"\s+", " ", s)
        return s

    @staticmethod
    def _chunk_text(text: str, chunk_chars: int = 1200, overlap_chars: int = 200) -> List[str]:
        text = RagIndex._clean_text(text)
        if not text:
            return []
        chunk_chars = max(300, int(chunk_chars))
        overlap_chars = max(0, min(int(overlap_chars), chunk_chars - 50))

        out: List[str] = []
        i = 0
        while i < len(text):
            j = min(len(text), i + chunk_chars)
            out.append(text[i:j])
            if j >= len(text):
                break
            i = max(0, j - overlap_chars)
        return out

    def build(
        self,
        documents: List[Tuple[str, str, str, Dict[str, Any]]],
        chunk_chars: int = 1200,
        overlap_chars: int = 200,
    ) -> Dict[str, Any]:
        """Build index from documents.

        documents: List[(source_id, source_type, text, meta)]
        """
        self.index_dir.mkdir(parents=True, exist_ok=True)

        chunks: List[RagChunk] = []
        for source_id, source_type, text, meta in documents:
            for idx, ch in enumerate(self._chunk_text(text, chunk_chars, overlap_chars)):
                chunk_id = f"{source_id}::c{idx:04d}"
                chunks.append(
                    RagChunk(
                        chunk_id=chunk_id,
                        source_id=str(source_id),
                        source_type=str(source_type),
                        text=ch,
                        meta=dict(meta or {}),
                    )
                )

        # Lazy import so the rest of the app still runs even if sklearn isn't installed yet.
        from sklearn.feature_extraction.text import TfidfVectorizer  # type: ignore

        texts = [c.text for c in chunks]
        vectorizer = TfidfVectorizer(
            lowercase=True,
            stop_words="english",
            max_features=60000,
            ngram_range=(1, 2),
        )
        matrix = vectorizer.fit_transform(texts) if texts else None

        # persist
        self._chunks = chunks
        self._vectorizer = vectorizer
        self._matrix = matrix

        self._chunks_path.write_text(
            json.dumps([c.__dict__ for c in chunks], indent=2),
            encoding="utf-8",
        )
        with self._model_path.open("wb") as f:
            pickle.dump({"vectorizer": vectorizer, "matrix": matrix}, f)

        return {
            "ok": True,
            "index_dir": str(self.index_dir),
            "documents": len(documents),
            "chunks": len(chunks),
        }

    # ---------------------------- load ----------------------------------

    def load(self) -> bool:
        try:
            if not self._chunks_path.exists() or not self._model_path.exists():
                return False
            raw = json.loads(self._chunks_path.read_text(encoding="utf-8"))
            self._chunks = [RagChunk(**r) for r in raw if isinstance(r, dict)]
            with self._model_path.open("rb") as f:
                data = pickle.load(f)
            self._vectorizer = data.get("vectorizer")
            self._matrix = data.get("matrix")
            return True
        except Exception:
            return False

    # ---------------------------- query ---------------------------------

    @staticmethod
    def _cosine_sparse(q, m) -> List[float]:
        """Compute cosine similarity for sparse matrices."""
        if q is None or m is None:
            return []
        # q: (1, d) sparse
        # m: (n, d) sparse
        scores = (m @ q.T).toarray().reshape(-1)
        q_norm = math.sqrt((q.multiply(q)).sum())
        if q_norm == 0:
            return [0.0 for _ in range(len(scores))]
        m_norms = (m.multiply(m)).sum(axis=1)
        # m_norms is (n, 1) matrix
        out = []
        for i, s in enumerate(scores):
            denom = float(math.sqrt(m_norms[i, 0]) * q_norm) if m_norms[i, 0] != 0 else 0.0
            out.append(float(s / denom) if denom else 0.0)
        return out

    def query(self, text: str, top_k: int = 6) -> List[Tuple[RagChunk, float]]:
        if not text or self._vectorizer is None or self._matrix is None or not self._chunks:
            return []
        try:
            q = self._vectorizer.transform([self._clean_text(text)])
            scores = self._cosine_sparse(q, self._matrix)
            k = max(1, int(top_k))
            best = sorted(enumerate(scores), key=lambda t: t[1], reverse=True)[:k]
            return [(self._chunks[i], float(s)) for i, s in best if s > 0]
        except Exception:
            return []


# ---------------------------- library ingest ----------------------------


def default_rag_library_dir(data_dir: str) -> str:
    """Canonical folder for user-provided documents."""
    return str(Path(data_dir).expanduser().resolve() / "rag" / "library")


def _read_pdf_text(p: Path) -> str:
    # Try pypdf first (fast). If it yields empty text, fall back to pdfplumber.
    try:
        from pypdf import PdfReader  # type: ignore

        reader = PdfReader(str(p))
        parts: List[str] = []
        for page in reader.pages:
            try:
                t = page.extract_text() or ""
            except Exception:
                t = ""
            if t:
                parts.append(t)
        text = "\n".join(parts).strip()
        if text:
            return text
    except Exception:
        pass

    # Fallback: pdfplumber (often better for some PDFs)
    try:
        import pdfplumber  # type: ignore

        parts2: List[str] = []
        with pdfplumber.open(str(p)) as pdf:
            for page in pdf.pages:
                try:
                    t = page.extract_text() or ""
                except Exception:
                    t = ""
                if t:
                    parts2.append(t)
        return "\n".join(parts2).strip()
    except Exception:
        return ""

def _read_docx_text(p: Path) -> str:
    try:
        from docx import Document  # type: ignore

        doc = Document(str(p))
        parts = [para.text for para in doc.paragraphs if (para.text or "").strip()]
        return "\n".join(parts)
    except Exception:
        return ""


def read_library_file_text(path: str | Path) -> str:
    p = Path(path)
    ext = p.suffix.lower()

    if ext == ".pdf":
        return _read_pdf_text(p)
    if ext == ".docx":
        return _read_docx_text(p)
    if ext in (".txt", ".md"):
        try:
            return p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            try:
                return p.read_text(errors="ignore")
            except Exception:
                return ""
    return ""


def collect_library_documents(library_dir: str) -> List[Tuple[str, str, str, Dict[str, Any]]]:
    """Walk the knowledge library folder and return docs for RagIndex.build().

    Returns list of (source_id, source_type, text, meta)
    """
    out: List[Tuple[str, str, str, Dict[str, Any]]] = []
    root = Path(library_dir).expanduser().resolve()
    if not root.exists():
        return out

    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in SUPPORTED_LIBRARY_EXTS:
            continue
        text = read_library_file_text(p)
        if not (text or "").strip():
            continue
        rel = p.relative_to(root)
        source_id = str(rel)
        # Treat certain subfolders as "source types" so downstream RAG callers can
        # do two-pass retrieval (authoritative dictionary vs example queries).
        # Recommended layout:
        #   library/dictionary/...  -> source_type=dictionary
        #   library/examples/...    -> source_type=examples
        #   library/ads/...         -> source_type=ads
        #   library/*               -> source_type=library
        top = (rel.parts[0] if rel.parts else "").lower()
        source_type = "library"
        if top in ("dictionary", "datadictionary", "cs_dictionary"):
            source_type = "dictionary"
        elif top in ("examples", "queries", "query_catalog"):
            source_type = "examples"
        elif top in ("ads", "templates"):
            source_type = "ads"
        out.append(
            (
                source_id,
                source_type,
                text,
                {
                    "path": str(p),
                    "ext": p.suffix.lower(),
                    "title": p.stem,
                    "library_subdir": top or "",
                },
            )
        )
    return out


def default_rag_dir(data_dir: str) -> str:
    return str(Path(data_dir).expanduser().resolve() / "rag" / "tfidf_v1")
