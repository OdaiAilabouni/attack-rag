"""Interactive RAG chat over MITRE ATT&CK + analyst runbooks, powered by Claude."""

import os
import sys
from pathlib import Path

import anthropic
import chromadb
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CHROMA_DIR = PROJECT_ROOT / "chroma_db"
COLLECTION_NAME = "attack_knowledge"
MODEL = "claude-sonnet-4-6"
TOP_K = 6

SYSTEM_PROMPT = """You are an expert security operations assistant that answers analyst questions using the MITRE ATT&CK framework and the organization's internal runbooks.

You have access to retrieved context for each question. The context contains two kinds of source documents:

1. **MITRE ATT&CK techniques** — adversary behavior descriptions identified by technique IDs like T1055, T1059.001, T1078.004. Each technique includes a name, the tactics it falls under (e.g. Execution, Persistence, Lateral Movement, Defense Evasion), the platforms it affects, and a description.

2. **Internal runbooks** — analyst-authored procedures encoding institutional knowledge about how to triage and respond to specific adversary behaviors. These represent the organization's accumulated expertise.

How to respond:

- Ground every claim in the retrieved context. Do not draw on background knowledge of adversary tradecraft beyond what the retrieved sources provide.
- Cite ATT&CK technique IDs (e.g., T1003.001, T1059.003) inline whenever you reference adversary behavior. Cite runbooks by filename (e.g., runbooks/lateral_movement_triage.md).
- When a runbook applies, prefer its guidance over generic ATT&CK descriptions — runbooks encode the organization's specific response procedures.
- If the retrieved context does not contain enough information to answer confidently, say so explicitly. Do not fabricate technique IDs, tactic names, or runbook procedures.
- Structure responses for working analysts: lead with the direct answer, then list relevant techniques and tactics, then point to the applicable runbook if one exists.
- Use precise security terminology. Distinguish between tactics (the why), techniques (the how), and sub-techniques (the specific variant).

When asked about an adversary group or threat actor by name, recognize that the retrieved context contains technique definitions, not threat-actor profiles. Map the question to the techniques the actor is known to use, and answer in terms of those techniques.

Format your response in plain Markdown. Use bold for technique IDs and runbook filenames so analysts can scan output quickly."""


def load_collection() -> chromadb.Collection:
    if not CHROMA_DIR.exists():
        print(f"No ChromaDB found at {CHROMA_DIR}.")
        print("Run `python src/ingest.py` first to build the index.")
        sys.exit(1)
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    return client.get_collection(COLLECTION_NAME)


def retrieve(collection: chromadb.Collection, question: str, k: int = TOP_K) -> list[dict]:
    result = collection.query(query_texts=[question], n_results=k)
    docs = result["documents"][0]
    metas = result["metadatas"][0]
    distances = result["distances"][0]
    return [
        {"text": doc, "metadata": meta, "distance": dist}
        for doc, meta, dist in zip(docs, metas, distances)
    ]


def format_context(hits: list[dict]) -> str:
    lines = []
    for i, hit in enumerate(hits, 1):
        meta = hit["metadata"]
        if meta.get("source") == "mitre-attack":
            header = f"[{i}] MITRE ATT&CK — {meta['technique_id']}: {meta['name']}"
        else:
            header = f"[{i}] Runbook — runbooks/{meta['filename']}"
        lines.append(f"{header}\n{hit['text']}\n")
    return "\n---\n".join(lines)


def ask(client: anthropic.Anthropic, collection: chromadb.Collection, question: str) -> None:
    hits = retrieve(collection, question)
    context = format_context(hits)

    user_message = (
        f"Retrieved context for the question:\n\n{context}\n\n"
        f"Question: {question}"
    )

    print()
    with client.messages.stream(
        model=MODEL,
        max_tokens=16000,
        system=[
            {
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": {"type": "ephemeral"},
            }
        ],
        messages=[{"role": "user", "content": user_message}],
    ) as stream:
        for text in stream.text_stream:
            print(text, end="", flush=True)
        final = stream.get_final_message()

    usage = final.usage
    print(
        f"\n\n[tokens: {usage.input_tokens} in, {usage.output_tokens} out, "
        f"cache_read: {usage.cache_read_input_tokens}, "
        f"cache_write: {usage.cache_creation_input_tokens}]"
    )


def main() -> int:
    load_dotenv()
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ANTHROPIC_API_KEY not set. Copy .env.example to .env and fill it in.")
        return 1

    client = anthropic.Anthropic()
    collection = load_collection()

    print("MITRE ATT&CK RAG Assistant")
    print(f"Loaded collection '{COLLECTION_NAME}' with {collection.count()} documents.")
    print("Ask a security question. Type 'exit' or Ctrl-C to quit.\n")

    while True:
        try:
            question = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if not question:
            continue
        if question.lower() in {"exit", "quit"}:
            return 0
        ask(client, collection, question)
        print()


if __name__ == "__main__":
    sys.exit(main())
