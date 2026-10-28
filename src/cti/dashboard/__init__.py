"""The local dashboard's data contract, export and server (Phase 8).

- ``schema``: pydantic models for every exported JSON file (the dashboard's types mirror them).
- ``export``: ``cti export``, pipeline outputs -> ``data/export/<date>/*.json``.
- ``serve``: ``cti serve``, a read-only static server on 127.0.0.1 with strict headers.
"""
