---
name: assessing-vector-and-embedding-weaknesses
description: Test RAG vector stores (Pinecone, Qdrant, Weaviate, Chroma, pgvector, FAISS) for embedding inversion, cross-tenant data leakage, and data poisoning per OWASP LLM08:2025. Use when performing an authorized security assessment of a RAG pipeline's retrieval layer or auditing multi-tenant vector-store isolation. Do not use for probing the RAG generation flow with poisoned retrieved documents to test injected-instruction following - use testing-prompt-injection-in-rag-pipelines.
domain: cybersecurity
subdomain: ai-security
tags:
- ai-security
- vector-database
- embedding-inversion
- rag-security
- owasp-llm08
- multi-tenant-isolation
- data-poisoning
- retrieval-augmented-generation
version: '1.0'
author: mahipal
license: Apache-2.0
nist_ai_rmf:
- MEASURE-2.7
atlas_techniques:
- AML.T0024
---
# Assessing Vector and Embedding Weaknesses

> **Authorized use only:** These tests interact with vector stores and embedding models in RAG systems you own or are authorized to assess. Embedding inversion and cross-tenant probing against systems you do not control may expose third-party data and is prohibited without authorization.

## Overview

Retrieval-Augmented Generation (RAG) systems convert documents into embedding vectors stored in a vector database (Pinecone, Qdrant, Weaviate, Chroma, pgvector, FAISS) and retrieve the nearest vectors to ground LLM responses. OWASP **LLM08:2025 Vector and Embedding Weaknesses** covers the security risks unique to this layer:

- **Embedding inversion** — embeddings are not one-way. A trained inversion model (or a black-box reconstruction attack) can recover substantial portions of the original text from its vector, leaking source documents (maps to MITRE ATLAS **AML.T0024.001 Invert ML Model**).
- **Membership inference** — querying whether a specific record contributed to the corpus (AML.T0024.000).
- **Cross-tenant / multi-tenant leakage** — when one namespace/collection is shared or filter isolation is missing, a tenant retrieves another tenant's chunks.
- **Knowledge-base poisoning** — an attacker who can write to the corpus inserts crafted chunks that dominate retrieval (high cosine similarity to expected queries) and carry indirect prompt-injection payloads.
- **Retrieval manipulation** — adversarial documents tuned to be retrieved for many unrelated queries ("retrieval hijacking").

The parent technique is **AML.T0024 — Exfiltration via ML Inference API**: an attacker uses legitimate inference/query access to exfiltrate data (source text via inversion, membership, or model extraction). This skill provides a repeatable assessment of all five weakness classes.

## When to Use

- During a security assessment of any RAG / vector-search application (OWASP LLM08 coverage).
- When a vector store is multi-tenant and you must prove namespace/metadata isolation.
- When the corpus accepts user-supplied or third-party documents (poisoning surface).
- When the embedding endpoint is externally reachable (inversion/membership surface).
- When validating retrieval-filtering controls before go-live.

## Prerequisites

- Authorization and scope covering the target embedding endpoint and vector store.
- Python 3.10+.
- Read (and, for poisoning tests, write) access to a test collection — never the production corpus.

```bash
# Vector DB clients + embeddings + similarity tooling
python -m pip install numpy scikit-learn sentence-transformers
python -m pip install qdrant-client chromadb pinecone-client weaviate-client
# (optional) text-embedding inversion research baseline
python -m pip install vec2text
```

## Objectives

- Measure embedding-inversion exposure on the target embedding model.
- Run a membership-inference probe against the corpus.
- Test multi-tenant isolation (namespace, metadata filter, RBAC) for cross-tenant leakage.
- Inject benign poisoned chunks into a *test* collection and measure retrieval dominance.
- Detect indirect prompt-injection content surviving in retrieved chunks.
- Recommend controls: tenant-scoped filters, content validation, embedding-access limits.

## MITRE ATT&CK Mapping

| ID | Tactic | Official Technique Name | Role in this skill |
|----|--------|-------------------------|--------------------|
| AML.T0024 | ATLAS: Exfiltration | Exfiltration via ML Inference API | Using query/embedding access to exfiltrate source data |
| AML.T0024.000 | ATLAS: Exfiltration | Infer Training Data Membership | Membership-inference probe against the corpus |
| AML.T0024.001 | ATLAS: Exfiltration | Invert ML Model | Embedding-inversion reconstruction of source text |
| AML.T0020 | ATLAS: Resource Development | Poison Training Data | Knowledge-base poisoning of the corpus |
| AML.T0051.001 | ATLAS: Initial Access | LLM Prompt Injection: Indirect | Injection payloads embedded in retrieved chunks |

## Workflow

### Step 1: Inventory the RAG pipeline

Document the embedding model + dimensions, the vector store and its tenancy model, the chunking strategy, retrieval `top_k` and similarity metric (cosine/dot/L2), and any metadata filters applied at query time.

```python
# Example: inspect a Qdrant collection
from qdrant_client import QdrantClient
client = QdrantClient(url="http://localhost:6333")
info = client.get_collection("docs")
print(info.config.params.vectors)   # size + distance metric
print(client.count("docs"))         # corpus size
```

### Step 2: Test embedding-inversion exposure

Embeddings of similar text are close; an attacker with the embedding endpoint can iteratively reconstruct text whose embedding matches a target vector. Measure how much a nearest-neighbour-in-embedding-space recovers, using cosine similarity between candidate reconstructions and the target.

```python
import numpy as np
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity

model = SentenceTransformer("all-MiniLM-L6-v2")
secret = "Patient John Doe, MRN 553120, diagnosed with hypertension."
target_vec = model.encode([secret])

# Attacker has only target_vec and the embedding endpoint. Hill-climb candidate text.
candidates = [
    "Patient name and medical record number with a diagnosis.",
    "John Doe medical record hypertension diagnosis",
    "Patient John Doe MRN diagnosed hypertension",
]
cand_vecs = model.encode(candidates)
sims = cosine_similarity(target_vec, cand_vecs)[0]
for c, s in sorted(zip(candidates, sims), key=lambda x: -x[1]):
    print(f"{s:.3f}  {c}")
# High similarity for a near-verbatim guess => inversion risk is real for this model.
```

For a research-grade reconstruction baseline, `vec2text` can be used against compatible embedding models to demonstrate full-text recovery.

### Step 3: Membership inference

Determine whether a specific document is in the corpus by measuring the top-1 retrieval similarity for an exact-quote query: in-corpus items return a markedly higher max similarity than out-of-corpus controls.

```python
def membership_score(client, collection, embed, text):
    vec = embed([text])[0].tolist()
    hits = client.search(collection_name=collection, query_vector=vec, limit=1)
    return hits[0].score if hits else 0.0

in_corpus = membership_score(client, "docs", model.encode, "<exact quote from a known chunk>")
control  = membership_score(client, "docs", model.encode, "An unrelated random sentence.")
print(f"in-corpus={in_corpus:.3f}  control={control:.3f}  delta={in_corpus-control:.3f}")
# A large positive delta indicates the item is in the corpus (membership leak).
```

### Step 4: Test multi-tenant isolation

Confirm that tenant B cannot retrieve tenant A's chunks. Issue tenant-B-authenticated queries that *should* be filtered, and verify no tenant-A `tenant_id` appears in results.

```python
# Query as tenant B; expect ONLY tenant_id == "B" results.
from qdrant_client.models import Filter, FieldCondition, MatchValue

vec = model.encode(["confidential salary information"])[0].tolist()
hits = client.search(
    collection_name="docs",
    query_vector=vec,
    limit=10,
    query_filter=Filter(must=[FieldCondition(key="tenant_id", match=MatchValue(value="B"))]),
)
leaked = [h for h in hits if h.payload.get("tenant_id") != "B"]
print("CROSS-TENANT LEAK" if leaked else "isolation OK", "->", len(leaked), "foreign rows")

# Critical test: repeat WITHOUT the filter to confirm the server, not the client,
# enforces isolation. If unfiltered queries return tenant A data, isolation is client-side only.
hits_nofilter = client.search(collection_name="docs", query_vector=vec, limit=10)
print("server-side isolation FAILS" if any(h.payload.get("tenant_id") != "B" for h in hits_nofilter) else "OK")
```

### Step 5: Knowledge-base poisoning (test collection only)

Insert a benign poisoned chunk crafted to be retrieved for many unrelated queries, then measure how often it appears in `top_k`.

```python
from qdrant_client.models import PointStruct

# Benign marker payload (no real injection) to measure retrieval dominance.
poison = "POISON-CANARY. " + " ".join(
    ["password reset billing refund account login support error help"] * 8
)
client.upsert("docs_test", points=[
    PointStruct(id=999999, vector=model.encode([poison])[0].tolist(),
                payload={"tenant_id": "B", "source": "poison-test"})
])

queries = ["how do I get a refund", "reset my password", "what is the weather"]
for q in queries:
    hits = client.search("docs_test", model.encode([q])[0].tolist(), limit=5)
    dominated = any(h.payload.get("source") == "poison-test" for h in hits)
    print(f"{'POISON in top5' if dominated else 'clean'}: {q}")
```

### Step 6: Detect indirect prompt injection in retrieved chunks

Scan retrieved chunk text for injection markers before it is concatenated into the prompt.

```python
import re
INJECTION_PATTERNS = [
    r"ignore (all|previous|the above) instructions",
    r"system prompt", r"you are now", r"disregard", r"</?(system|instructions)>",
]
def chunk_is_injection(text):
    low = text.lower()
    return [p for p in INJECTION_PATTERNS if re.search(p, low)]

for hit in client.search("docs", model.encode(["help"])[0].tolist(), limit=10):
    flags = chunk_is_injection(hit.payload.get("text", ""))
    if flags:
        print("INDIRECT INJECTION in chunk", hit.id, flags)
```

### Step 7: Report and remediate

- **Inversion/membership:** rate-limit and authenticate the embedding endpoint; avoid returning raw similarity scores; restrict who can query embeddings.
- **Cross-tenant:** enforce tenant filters server-side (separate collections/namespaces per tenant where feasible); never rely on client-supplied filters.
- **Poisoning:** validate and provenance-tag every ingested chunk; scan inputs for injection; cap any single source's share of retrieval.
- **Indirect injection:** sanitize retrieved chunks and apply output guardrails (see `defending-llms-with-guardrails`).

## Tools and Resources

| Tool | Purpose | Primary Source |
|------|---------|----------------|
| OWASP LLM08 | Vector and Embedding Weaknesses guidance | https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/ |
| sentence-transformers | Embedding generation for testing | https://www.sbert.net/ |
| Qdrant client | Vector store + filtered search | https://qdrant.tech/documentation/ |
| Chroma / Weaviate / Pinecone | Alternative vector stores | https://docs.trychroma.com/ |
| vec2text | Embedding-inversion research baseline | https://github.com/jxmorris12/vec2text |
| MITRE ATLAS | AML.T0024 Exfiltration via ML Inference API | https://atlas.mitre.org/ |

## Validation Criteria

- [ ] RAG pipeline inventoried (embedding model, store, tenancy, metric, top_k, filters).
- [ ] Embedding-inversion exposure measured and rated.
- [ ] Membership-inference delta computed for in-corpus vs control items.
- [ ] Multi-tenant isolation tested both with and without client filters (server-side enforcement confirmed).
- [ ] Poisoning dominance measured in a test collection only.
- [ ] Retrieved chunks scanned for indirect-injection content.
- [ ] Findings reported with remediation for each weakness class.
- [ ] No production corpus modified during the assessment.
