"""Offline NLP extraction over the snapshot's free text (``cti extract``).

Outputs go to ``data/extracted/<date>/`` with the same deterministic writers as
``cti enrich``. Every row carries its ``origin`` (``reference_page`` or
``nvd_description``): page text is snapshot-time and KEV-biased, so page-derived output is
never a risk feature (``vault/risk-scoring-design.md``).
"""
