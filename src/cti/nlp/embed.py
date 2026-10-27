"""Sentence embeddings with the SecureBERT 2.0 bi-encoder.

Attention-masked mean pooling over the last hidden state, then L2 normalization, which
reproduces the model's sentence-transformers config (``1_Pooling``: mean) without that
dependency. Texts are batched in length order (less padding), and results are returned in
input order.
"""

from __future__ import annotations

from collections.abc import Sequence

import numpy as np

from cti.nlp import models

MAX_TOKENS = 1024  # the bi-encoder's training length
BATCH = 32


class Encoder:
    def __init__(self, spec: models.ModelSpec = models.BIENCODER, max_tokens: int = MAX_TOKENS):
        self.torch, self.tokenizer, self.model = models.load_encoder(spec)
        self.spec = spec
        self.max_tokens = max_tokens

    def encode(self, texts: Sequence[str], batch: int = BATCH, progress=None) -> np.ndarray:
        torch = self.torch
        order = sorted(range(len(texts)), key=lambda i: len(texts[i]))
        out = np.zeros((len(texts), self.model.config.hidden_size), dtype=np.float32)
        with torch.inference_mode():
            for start in range(0, len(order), batch):
                idx = order[start : start + batch]
                enc = self.tokenizer(
                    [texts[i] for i in idx],
                    padding=True,
                    truncation=True,
                    max_length=self.max_tokens,
                    return_tensors="pt",
                )
                hidden = self.model(**enc).last_hidden_state
                mask = enc["attention_mask"].unsqueeze(-1).to(hidden.dtype)
                pooled = (hidden * mask).sum(1) / mask.sum(1).clamp(min=1)
                pooled = torch.nn.functional.normalize(pooled, dim=-1)
                out[idx] = pooled.numpy()
                if progress:
                    progress(min(start + batch, len(order)), len(order))
        return out


class BiencoderRanker:
    """Cosine similarity between CVE and technique embeddings (techniques embedded once)."""

    def __init__(self, techniques, encoder: Encoder):
        from cti.nlp.attack_eval import rank_parents

        self._rank_parents = rank_parents
        self.techniques = list(techniques)
        self.encoder = encoder
        self.matrix = encoder.encode([t.text for t in self.techniques])

    def scores(self, texts: Sequence[str]) -> np.ndarray:
        return self.encoder.encode(list(texts)) @ self.matrix.T

    def rank(self, texts: Sequence[str]) -> list[list[str]]:
        return self._rank_parents(self.scores(texts), self.techniques)
