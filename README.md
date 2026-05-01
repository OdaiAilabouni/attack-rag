# MITRE ATT&CK RAG Assistant

A demo of the **expert-knowledge-encoding pattern**: a retrieval-augmented assistant grounded in the MITRE ATT&CK framework and a small set of analyst-authored runbooks, citing back to source material so analysts trust the output.

The thesis: the next generation of security tooling will not replace analysts. It will let them encode their institutional knowledge — how *this* organization triages *this* technique — and let an LLM apply that knowledge consistently and at scale across the team.

## What it does

You ask a security question in natural language. The assistant retrieves relevant ATT&CK techniques and internal runbooks, then asks Claude to synthesize a grounded answer with inline citations to technique IDs (e.g. T1003.001) and runbook filenames.

Example questions it answers well:

- "What is T1003.006 and how should I respond if my EDR flags it?"
- "An EDR alert is showing LSASS access by a non-Microsoft binary. What's our procedure?"
- "Which techniques fall under the Lateral Movement tactic on Windows?"
- "If I see Pass-the-Hash, what krbtgt rotation procedure should I follow?"

## Architecture

```
   ATT&CK STIX (mitre/cti)        runbooks/*.md
            \                          /
             \                        /
              v                      v
              +----- ChromaDB -------+
                       |
                       | retrieve top-K relevant chunks
                       v
                  +---------+
   user query -->| Claude  |--> grounded answer with citations
                  +---------+
```

- **Embeddings**: ChromaDB's default (all-MiniLM-L6-v2, runs locally).
- **LLM**: Claude Opus 4.7 via the official `anthropic` Python SDK, with prompt caching on the system prompt.
- **Knowledge sources**: enterprise ATT&CK STIX bundle + Markdown runbooks in `runbooks/`.

## Setup

Requires Python 3.10 or newer.

```powershell
# 1. Clone or copy this folder, then:
cd attack-rag

# 2. Create a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies (the embedding model downloads on first run, ~80 MB)
pip install -r requirements.txt

# 4. Configure your API key
copy .env.example .env
# then edit .env and paste your Anthropic API key

# 5. Build the index (downloads the ATT&CK STIX bundle, ~30 MB)
python src/ingest.py

# 6. Ask questions
python src/chat.py
```

## Project layout

```
attack-rag/
├── src/
│   ├── ingest.py        # download ATT&CK STIX, parse, embed into ChromaDB
│   └── chat.py          # interactive RAG loop using Claude
├── runbooks/            # analyst-authored response procedures
│   ├── lateral_movement_triage.md
│   └── credential_dumping_response.md
├── data/                # ATT&CK STIX cache (gitignored)
├── chroma_db/           # vector store (gitignored)
├── requirements.txt
├── .env.example
└── README.md
```

## Why this design

The interesting question for security tooling is not "can an LLM recite ATT&CK." It can. The interesting question is whether you can give an LLM your *organization's* expertise — the procedures your senior analysts have refined over years — and get it to apply that expertise consistently for everyone on the team.

This project demonstrates that pattern at small scale: ATT&CK provides the shared vocabulary, runbooks encode the institutional knowledge layered on top, and the retrieval step grounds every answer in citable sources so analysts can verify the assistant's reasoning. The same pattern scales to larger knowledge bases: detection rules, threat-actor profiles, post-incident reviews, control mappings, vendor playbooks.

## Limitations

- The ATT&CK STIX bundle is downloaded once; rerun `python src/ingest.py` to refresh it.
- The default embedding model is small and English-only. For production use, evaluate larger models or domain-tuned embeddings.
- Retrieval is dense-only with no reranking — adding a reranker (e.g. Cohere Rerank or a cross-encoder) would noticeably improve answer quality on ambiguous queries.
- The two sample runbooks are illustrative, not exhaustive. Real deployments would have dozens.

## Extending

A few directions that would meaningfully strengthen this:

- **Add detection rules** (Sigma, Splunk SPL, KQL) as a third knowledge source so the assistant can suggest hunts and detection logic, not just response procedures.
- **Wire in real threat intel feeds** (MISP, OTX, CISA advisories) to pull current campaign context in alongside the static framework knowledge.
- **Add an evaluation harness**: a set of held-out questions with expected technique citations, so changes to the prompt, retrieval, or model can be measured rather than guessed at.
- **Tool use**: give the assistant a `lookup_technique(tid)` tool so it can pull a specific technique on demand instead of relying purely on similarity search.
