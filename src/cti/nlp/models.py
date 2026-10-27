"""Pinned SecureBERT 2.0 models: one-time download, then offline, verified loading.

Every model is pinned to a Hugging Face commit and to the SHA-256 of its weights. Only
``*.json`` and ``*.safetensors`` files are fetched (no pickle weights), ``trust_remote_code``
is never set (ModernBERT is built into transformers), and loading runs with
``local_files_only``, so after ``cti models fetch`` nothing touches the network. The weights
are re-hashed on load; a cache that doesn't match the pin is refused.

Inference is CPU only, in eval mode, with a fixed thread count. Scores are rounded before
they are stored, because float results can differ in the last digits across thread counts
and BLAS builds.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

THREADS = 8


@dataclass(frozen=True, slots=True)
class ModelSpec:
    repo: str
    revision: str
    weights_sha256: str  # model.safetensors


NER = ModelSpec(
    "cisco-ai/SecureBERT2.0-NER",
    "792db5b533118afee8c3fab86db119d09ab77ff6",
    "b51c0e57b125250d02513d8c603e0cd8898d6e743fe1925840dff285a9f07719",
)
BIENCODER = ModelSpec(
    "cisco-ai/SecureBERT2.0-biencoder",
    "b42d43ac3167e9e4d6ec6afb4f27cba791a2f6a0",
    "ab97ffc3039e63cde330b9e83b6c359fbbd4cb3eb59c05d804ca29000486ef9e",
)
MODELS = {"ner": NER, "biencoder": BIENCODER}
_PATTERNS = ["*.json", "*.safetensors"]


def fetch(spec: ModelSpec) -> Path:
    """Download one pinned model into the Hugging Face cache (network; run once)."""
    from huggingface_hub import snapshot_download

    path = Path(snapshot_download(spec.repo, revision=spec.revision, allow_patterns=_PATTERNS))
    verify(spec, path)
    return path


def local_path(spec: ModelSpec) -> Path:
    from huggingface_hub import snapshot_download

    return Path(
        snapshot_download(
            spec.repo, revision=spec.revision, allow_patterns=_PATTERNS, local_files_only=True
        )
    )


def verify(spec: ModelSpec, path: Path) -> None:
    digest = hashlib.sha256()
    with (path / "model.safetensors").open("rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    if digest.hexdigest() != spec.weights_sha256:
        raise ValueError(f"{spec.repo}@{spec.revision}: weights do not match the pinned SHA-256")


def _setup_torch():
    import torch

    torch.set_num_threads(THREADS)
    torch.manual_seed(0)
    return torch


def load_encoder(spec: ModelSpec = BIENCODER):
    torch = _setup_torch()
    from transformers import AutoModel, AutoTokenizer

    path = local_path(spec)
    verify(spec, path)
    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True)
    model = AutoModel.from_pretrained(path, local_files_only=True, use_safetensors=True)
    if not tokenizer.is_fast:
        raise ValueError(f"{spec.repo}: expected a fast tokenizer (offsets are needed)")
    return torch, tokenizer, model.eval()


def load_token_classifier(spec: ModelSpec = NER):
    torch = _setup_torch()
    from transformers import AutoModelForTokenClassification, AutoTokenizer

    path = local_path(spec)
    verify(spec, path)
    tokenizer = AutoTokenizer.from_pretrained(path, local_files_only=True)
    model = AutoModelForTokenClassification.from_pretrained(
        path, local_files_only=True, use_safetensors=True
    )
    if not tokenizer.is_fast:
        raise ValueError(f"{spec.repo}: expected a fast tokenizer (offsets are needed)")
    return torch, tokenizer, model.eval()
