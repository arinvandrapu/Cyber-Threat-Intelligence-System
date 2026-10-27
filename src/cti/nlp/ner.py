"""Named-entity recognition with SecureBERT 2.0 NER (``cisco-ai/SecureBERT2.0-NER``).

Labels: Indicator, Malware, Organization, System, Vulnerability (BIO tags). The
transformers pipeline's "simple" aggregation splits words at byte-level BPE boundaries
(``X`` / ``-`` / ``Agent``), so spans are built here from the raw token predictions:

1. Long texts are split into windows of ``MAX_TOKENS`` with ``STRIDE`` tokens of overlap.
   Each token keeps the prediction from the window where it sits furthest from an edge.
2. Tokens group into a span while the label type stays the same and the tag is ``I-``, or
   the next token continues the same word (no whitespace between).
3. Spans snap to whole words (``CVE-2024-21413``, not ``-2024``). Overlapping spans then
   merge, keeping the label that covers more characters.

The entity text is stored defanged (an Indicator span can be a live URL or address); the
offsets index the original text.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass

import numpy as np

from cti.nlp import models

MAX_TOKENS = 1024  # the length the model was fine-tuned at
STRIDE = 128
BATCH = 8
LABELS = ("Indicator", "Malware", "Organization", "System", "Vulnerability")
_WORD_EDGE = re.compile(r"[\s,;:()\[\]{}\"'<>]")
_SCHEME = re.compile(r"\b(h)tt(ps?)://", re.IGNORECASE)
_INNER_DOT = re.compile(r"(?<=\w)\.(?=\w)")


def inert(text: str) -> str:
    return _INNER_DOT.sub("[.]", _SCHEME.sub(r"\1xx\2[:]//", text))


@dataclass(frozen=True, slots=True)
class Entity:
    label: str
    start: int
    end: int
    text: str  # defanged
    score: float  # mean token probability, rounded

    def as_dict(self) -> dict:
        return asdict(self)


def _snap(text: str, start: int, end: int) -> tuple[int, int]:
    # byte-level BPE offsets include a token's leading space: drop it before snapping
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    if start == end:
        return start, end
    while start > 0 and not _WORD_EDGE.match(text[start - 1]):
        start -= 1
    while end < len(text) and not _WORD_EDGE.match(text[end]):
        end += 1
    while end > start and (text[end - 1] in ".,;:-" or text[end - 1].isspace()):
        end -= 1  # trailing punctuation, a dangling dash
    return start, end


def group(text: str, tokens: list[tuple[int, int, str, float]]) -> list[Entity]:
    """Tokens ``(start, end, tag, prob)`` in text order -> word-snapped entities."""
    spans: list[list] = []  # [label, start, end, probs]
    for start, end, tag, prob in tokens:
        if tag == "O":
            spans.append(None)
            continue
        prefix, label = tag.split("-", 1)
        prev = spans[-1] if spans else None
        # a BPE fragment of the same word: touches the previous token, no leading space
        same_word = prev is not None and prev[2] == start and not text[start].isspace()
        if prev is not None and prev[0] == label and (prefix == "I" or same_word):
            prev[2] = end
            prev[3].append(prob)
        else:
            spans.append([label, start, end, [prob]])
    snapped = []
    for span in filter(None, spans):
        s, e = _snap(text, span[1], span[2])
        if e > s:
            snapped.append([span[0], s, e, span[3], {span[0]: span[2] - span[1]}])
    merged: list[list] = []
    for span in sorted(snapped, key=lambda x: (x[1], x[2])):
        if merged and span[1] < merged[-1][2]:  # same word(s): one entity
            last = merged[-1]
            last[2] = max(last[2], span[2])
            last[3] += span[3]
            for label, n in span[4].items():
                last[4][label] = last[4].get(label, 0) + n
        else:
            merged.append(span)
    return [
        Entity(
            max(sorted(m[4]), key=lambda lab: m[4][lab]),
            m[1],
            m[2],
            inert(text[m[1] : m[2]]),
            round(float(np.mean(m[3])), 4),
        )
        for m in merged
    ]


class Tagger:
    def __init__(self, spec: models.ModelSpec = models.NER):
        self.torch, self.tokenizer, self.model = models.load_token_classifier(spec)
        self.spec = spec
        self.id2label = self.model.config.id2label

    def _windows(self, texts: Sequence[str]):
        enc = self.tokenizer(
            list(texts),
            truncation=True,
            max_length=MAX_TOKENS,
            stride=STRIDE,
            return_overflowing_tokens=True,
            return_offsets_mapping=True,
        )
        return enc["input_ids"], enc["offset_mapping"], enc["overflow_to_sample_mapping"]

    def tag(self, texts: Sequence[str], progress=None) -> list[list[Entity]]:
        torch = self.torch
        ids, offsets, owner = self._windows(texts)
        # per text: (start, end) -> (margin to the window edge, tag, prob)
        best: list[dict] = [{} for _ in texts]
        order = sorted(range(len(ids)), key=lambda i: len(ids[i]))
        pad = self.tokenizer.pad_token_id
        with torch.inference_mode():
            for b in range(0, len(order), BATCH):
                idx = order[b : b + BATCH]
                width = max(len(ids[i]) for i in idx)
                input_ids = torch.full((len(idx), width), pad, dtype=torch.long)
                mask = torch.zeros((len(idx), width), dtype=torch.long)
                for row, i in enumerate(idx):
                    input_ids[row, : len(ids[i])] = torch.tensor(ids[i])
                    mask[row, : len(ids[i])] = 1
                probs = torch.softmax(
                    self.model(input_ids=input_ids, attention_mask=mask).logits, -1
                )
                conf, label = probs.max(-1)
                for row, i in enumerate(idx):
                    real = [k for k, (s, e) in enumerate(offsets[i]) if e > s]
                    if not real:
                        continue
                    first, last = real[0], real[-1]
                    for k in real:
                        span = tuple(offsets[i][k])
                        margin = min(k - first, last - k)
                        seen = best[owner[i]].get(span)
                        if seen is None or margin > seen[0]:
                            tag = self.id2label[int(label[row, k])]
                            best[owner[i]][span] = (margin, tag, float(conf[row, k]))
                if progress:
                    progress(min(b + BATCH, len(order)), len(order))
        return [
            group(text, [(s, e, t, p) for (s, e), (_, t, p) in sorted(best[n].items())])
            for n, text in enumerate(texts)
        ]
