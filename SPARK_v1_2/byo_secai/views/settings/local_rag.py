from __future__ import annotations

from pathlib import Path
import streamlit as st

from byo_secai.rag import RagIndex, default_rag_dir, default_rag_library_dir, collect_library_documents
from byo_secai.models import ArtifactType
from byo_secai import workflow


def _artifact_to_rag_text(obj) -> str:
    """Best-effort stringify for RAG indexing."""
    try:
        if hasattr(obj, "model_dump"):
            data = obj.model_dump()
            import json
            return json.dumps(data, ensure_ascii=False)
        if isinstance(obj, dict):
            import json
            return json.dumps(obj, ensure_ascii=False)
        return str(obj)
    except Exception:
        return ""


def render(cfg, store) -> None:
    st.subheader("Local RAG")

    lib_dir = default_rag_library_dir(cfg.data_dir)
    # Ensure folder exists so users can immediately drop files in.
    try:
        Path(lib_dir).mkdir(parents=True, exist_ok=True)
    except Exception:
        pass

    st.caption(f"Knowledge Library folder: `{lib_dir}` (supported: PDF/DOCX/TXT/MD)")
    b1, b2 = st.columns([1, 3])
    with b1:
        if st.button("Show library path"):
            st.code(lib_dir)
    with b2:
        st.caption("Drop documents into this folder, then click **Rebuild RAG index**.")

    cfg.rag_enabled = st.checkbox(
        "Enable local RAG (retrieve context from your Knowledge Library)",
        value=bool(getattr(cfg, "rag_enabled", True)),
        help="Uses a fully-local TF-IDF index under ./data/rag/ to provide grounded context during generation and in the Workspace.",
    )

    colr1, colr2, colr3 = st.columns(3)
    with colr1:
        cfg.rag_top_k = st.number_input(
            "Top-K retrieved chunks",
            min_value=1,
            max_value=12,
            value=int(getattr(cfg, "rag_top_k", 6)),
            step=1,
        )
    with colr2:
        cfg.rag_chunk_chars = st.number_input(
            "Chunk size (chars)",
            min_value=400,
            max_value=2400,
            value=int(getattr(cfg, "rag_chunk_chars", 1200)),
            step=100,
        )
    with colr3:
        cfg.rag_overlap_chars = st.number_input(
            "Chunk overlap",
            min_value=0,
            max_value=800,
            value=int(getattr(cfg, "rag_overlap_chars", 200)),
            step=50,
        )

    # Preview library counts so users immediately know whether rebuild will find anything.
    lib_docs = []
    try:
        lib_docs = collect_library_documents(lib_dir)
        if lib_docs:
            st.info(f"Library ready: {len(lib_docs)} docs (will chunk on rebuild)")
        else:
            st.warning("Library empty or unsupported files only. Add PDF/DOCX/TXT/MD into the folder above.")
    except Exception:
        st.warning("Unable to scan library folder.")

    include_artifacts = st.checkbox(
        "Also include generated artifacts in the RAG index",
        value=False,
        help="Optional: adds your Intel Briefs, Hunt Packages, Findings, ADS, etc. into the RAG index. Library docs are always included.",
    )

    st.markdown("---")
    st.caption("RAG indexing is manual to keep navigation fast. Rebuild only when you want to refresh the index.")

    rcolA, rcolB = st.columns([1, 2])
    with rcolA:
        rebuild = st.button("Rebuild RAG index", type="primary")

    if rebuild:
        st.session_state.pop("rag", None)
        rag_dir = default_rag_dir(cfg.data_dir)
        rag = RagIndex(rag_dir)

        docs = []
        # 1) Always include Knowledge Library documents
        try:
            docs.extend(collect_library_documents(lib_dir))
        except Exception:
            pass

        # 2) Optional: include serialized artifacts
        if include_artifacts:
            for at in ArtifactType:
                for aid in (store.list_ids(at) or []):
                    m = store.load(at, aid)
                    if m is None:
                        continue
                    docs.append((aid, at.value, _artifact_to_rag_text(m), {"title": getattr(getattr(m, "meta", None), "title", "")}))

        with st.spinner("Building index..."):
            try:
                res = rag.build(docs, chunk_chars=int(cfg.rag_chunk_chars), overlap_chars=int(cfg.rag_overlap_chars))
                st.success(f"RAG rebuilt: {res.get('chunks')} chunks from {res.get('documents')} docs")
            except Exception as e:
                st.error(f"RAG rebuild failed: {e}")
                return

        st.session_state["rag"] = rag
        try:
            workflow.set_rag(rag, enabled=bool(cfg.rag_enabled), top_k=int(cfg.rag_top_k))
        except Exception:
            pass

    with rcolB:
        st.caption("Tip: rebuild after importing docs or generating a batch of artifacts so the index reflects the latest content.")
