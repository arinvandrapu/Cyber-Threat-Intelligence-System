"""Pinned SecureBERT 2.0 models: one-time download, then offline, verified loading.

Every model is pinned to a Hugging Face commit and to the SHA-256 of every file it loads
(weights, config, tokenizer). Only ``*.json`` and ``*.safetensors`` files are fetched (no
pickle weights), ``trust_remote_code`` is never set (ModernBERT is built into
transformers), and loading runs with ``local_files_only``, so after ``cti models fetch``
nothing touches the network. Every file is re-hashed on load; a cache that doesn't match
the pin is refused.

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
    # path in the snapshot -> SHA-256. These are public hashes of public files; the
    # tokenizer lines carry gitleaks:allow because "token" + 64 hex chars looks like a key.
    files: dict[str, str]


_TOKENIZER = {
    "special_tokens_map.json": (
        "ea97ecdbcc73713039d8d64dbb05e3689495c96657fbd9a18f5bed381be81049"  # gitleaks:allow
    ),
}
NER = ModelSpec(
    "cisco-ai/SecureBERT2.0-NER",
    "792db5b533118afee8c3fab86db119d09ab77ff6",
    {
        "model.safetensors": "b51c0e57b125250d02513d8c603e0cd8898d6e743fe1925840dff285a9f07719",
        "config.json": "76a07de1d10b1d2ac5b4c2795215eed3335f3e087029bfe287403076dff9a52d",
        "tokenizer.json": (
            "6c8aaa9a542084f2457eab775d4eeb51f92a70c0fd9de28d5edb0ddec3c08d30"  # gitleaks:allow
        ),
        "tokenizer_config.json": (
            "c16f1b07f93d05be753ec0acf8cb511d895a8bdb09669f6b156df81e3f96c2eb"  # gitleaks:allow
        ),
        **_TOKENIZER,
    },
)
BIENCODER = ModelSpec(
    "cisco-ai/SecureBERT2.0-biencoder",
    "b42d43ac3167e9e4d6ec6afb4f27cba791a2f6a0",
    {
        "model.safetensors": "ab97ffc3039e63cde330b9e83b6c359fbbd4cb3eb59c05d804ca29000486ef9e",
        "config.json": "7939c4542cdf9dc371c2bfb84e10c199dd3196e0dbeeb5f7ec641944b3410b7e",
        "tokenizer.json": (
            "b18211964db7d0ae2a8d2c4a4c00e271c13905859726fe980622488d95db75af"  # gitleaks:allow
        ),
        "tokenizer_config.json": (
            "234b4cc1fd763b657ec4612d29ff3a7843e5f755e994db7ab6b1a5813b745e1a"  # gitleaks:allow
        ),
        "1_Pooling/config.json": "35bbd47d7fdf1e378db6130bcc668b09d1aa67a7bbf7c8f89a9c71f4cc8ebcc6",
        "modules.json": "8f4b264b80206c830bebbdcae377e137925650a433b689343a63bdc9b3145460",
        **_TOKENIZER,
    },
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
    for name, expected in spec.files.items():
        digest = hashlib.sha256()
        with (path / name).open("rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                digest.update(block)
        if digest.hexdigest() != expected:
            raise ValueError(
                f"{spec.repo}@{spec.revision}: {name} does not match the pinned SHA-256"
            )


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
