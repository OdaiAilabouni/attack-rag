"""Download MITRE ATT&CK STIX data and runbooks, embed into a local ChromaDB store."""

import json
import os
import sys
from pathlib import Path

import chromadb
import requests

ATTACK_STIX_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
RUNBOOKS_DIR = PROJECT_ROOT / "runbooks"
CHROMA_DIR = PROJECT_ROOT / "chroma_db"
COLLECTION_NAME = "attack_knowledge"


def download_stix() -> Path:
    DATA_DIR.mkdir(exist_ok=True)
    stix_path = DATA_DIR / "enterprise-attack.json"
    if stix_path.exists():
        print(f"STIX already cached at {stix_path}")
        return stix_path

    print(f"Downloading ATT&CK STIX from {ATTACK_STIX_URL} ...")
    response = requests.get(ATTACK_STIX_URL, timeout=120)
    response.raise_for_status()
    stix_path.write_bytes(response.content)
    print(f"Saved to {stix_path} ({stix_path.stat().st_size // 1024} KB)")
    return stix_path


def technique_id(obj: dict) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def parse_techniques(stix_path: Path) -> list[dict]:
    bundle = json.loads(stix_path.read_text(encoding="utf-8"))
    chunks = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        tid = technique_id(obj)
        if not tid:
            continue

        name = obj.get("name", "")
        description = obj.get("description", "")
        platforms = ", ".join(obj.get("x_mitre_platforms", []))
        tactics = ", ".join(
            kc.get("phase_name", "")
            for kc in obj.get("kill_chain_phases", [])
            if kc.get("kill_chain_name") == "mitre-attack"
        )

        text = (
            f"Technique {tid}: {name}\n"
            f"Tactics: {tactics}\n"
            f"Platforms: {platforms}\n\n"
            f"{description}"
        )

        chunks.append(
            {
                "id": f"attack-{tid}",
                "text": text,
                "metadata": {
                    "source": "mitre-attack",
                    "technique_id": tid,
                    "name": name,
                    "tactics": tactics,
                },
            }
        )
    return chunks


def parse_runbooks() -> list[dict]:
    if not RUNBOOKS_DIR.exists():
        return []
    chunks = []
    for path in sorted(RUNBOOKS_DIR.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        chunks.append(
            {
                "id": f"runbook-{path.stem}",
                "text": text,
                "metadata": {
                    "source": "runbook",
                    "filename": path.name,
                },
            }
        )
    return chunks


def build_collection(chunks: list[dict]) -> None:
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))
    try:
        client.delete_collection(COLLECTION_NAME)
    except Exception:
        pass
    collection = client.create_collection(name=COLLECTION_NAME)

    batch_size = 100
    for i in range(0, len(chunks), batch_size):
        batch = chunks[i : i + batch_size]
        collection.add(
            ids=[c["id"] for c in batch],
            documents=[c["text"] for c in batch],
            metadatas=[c["metadata"] for c in batch],
        )
        print(f"  embedded {min(i + batch_size, len(chunks))} / {len(chunks)}")

    print(f"\nCollection '{COLLECTION_NAME}' built at {CHROMA_DIR}")
    print(f"Total chunks: {collection.count()}")


def main() -> int:
    stix_path = download_stix()
    technique_chunks = parse_techniques(stix_path)
    runbook_chunks = parse_runbooks()

    print(f"\nParsed {len(technique_chunks)} ATT&CK techniques")
    print(f"Parsed {len(runbook_chunks)} runbook documents")
    print("\nEmbedding into ChromaDB (first run downloads the embedding model)...")

    build_collection(technique_chunks + runbook_chunks)
    return 0


if __name__ == "__main__":
    sys.exit(main())
