"""Command-line interface: ``cti probe | ingest | status | parse``."""

from __future__ import annotations

import argparse
import gzip
import logging
import sys
from collections import Counter
from datetime import date
from pathlib import Path

from cti import gold
from cti.config import ConfigError, Settings
from cti.http.client import make_client
from cti.ingest import IngestResult, ingest, refetch
from cti.snapshot import Snapshot, SnapshotExistsError
from cti.sources.registry import select
from cti.storage import LocalStorage

log = logging.getLogger("cti")


def _snapshots(settings: Settings) -> LocalStorage:
    return LocalStorage(settings.data_dir / "snapshots")


def _check_requirements(sources, settings: Settings) -> None:
    missing = {name for s in sources for name in s.requires if not getattr(settings, name)}
    if missing:
        names = ", ".join(sorted(s.name for s in sources if set(s.requires) & missing))
        raise ConfigError(
            f"sources {names} need {', '.join(f'CTI_{m.upper()}' for m in sorted(missing))}; "
            "set it or exclude them with --only"
        )


def cmd_probe(args, settings: Settings) -> int:
    sources = select(settings, args.only)
    failures = 0
    with make_client(settings.user_agent) as client:
        for source in sources:
            try:
                _check_requirements([source], settings)
                url = source.probe_url()
                with client.stream("GET", url) as response:
                    status = str(response.status_code)
                    ok = response.is_success
            except ConfigError as exc:  # safe to show: names the missing setting only
                status, ok = str(exc), False
            except Exception as exc:  # type only: messages could contain URLs with keys
                status, ok = type(exc).__name__, False
            failures += not ok
            print(f"{'OK ' if ok else 'ERR'}  {source.name:<13} {status}")
    return 1 if failures else 0


def _report(result: IngestResult) -> int:
    print(f"snapshot {result.snapshot_id}")
    for name in result.completed:
        print(f"  done     {name}")
    for name in result.skipped:
        print(f"  skipped  {name} (already complete)")
    for name, error in result.failed.items():
        print(f"  FAILED   {name}: {error}")
    if not result.ok:
        print("Fix the cause, then run `cti ingest --resume --date ...`.")
    return 0 if result.ok else 1


def cmd_ingest(args, settings: Settings) -> int:
    sources = select(settings, args.only)
    if not args.refetch:
        _check_requirements(sources, settings)
    today = date.today()
    snapshot_date = date.fromisoformat(args.date) if args.date else today
    if snapshot_date != today and not args.allow_date_mismatch:
        # "latest" feeds (KEV, NVD, abuse.ch) would be fetched on a different day than the
        # snapshot claims; refuse unless explicitly allowed (fetch times are in the manifest).
        raise ConfigError(
            f"snapshot date {snapshot_date} is not today ({today}); "
            "pass --allow-date-mismatch to fetch anyway"
        )
    storage = _snapshots(settings)
    with make_client(settings.user_agent) as client:
        if args.refetch:
            if not args.reason:
                raise ConfigError("--refetch needs --reason")
            [source] = select(settings, [args.refetch])
            _check_requirements([source], settings)
            result = refetch(
                storage, settings, snapshot_date.isoformat(), source, args.reason, client
            )
        else:
            result = ingest(storage, settings, snapshot_date, sources, client, resume=args.resume)
    return _report(result)


def cmd_status(args, settings: Settings) -> int:
    snap = Snapshot.open(_snapshots(settings), args.date)
    m = snap.manifest
    print(f"snapshot {m.snapshot_id} created {m.created_at:%Y-%m-%d %H:%M} UTC")
    for source in sorted({e.source for e in m.entries} | set(m.completed)):
        entries = snap.entries(source)
        size = sum(e.bytes for e in entries)
        state = "complete" if snap.is_complete(source) else "INCOMPLETE"
        versions = ", ".join(sorted({(e.source_version or "-")[:12] for e in entries}))
        print(f"  {source:<13} {state:<10} {len(entries)} file(s) {size / 1e6:8.1f} MB  {versions}")
    for r in m.refetches:
        print(f"  refetch {r.source} attempt {r.attempt}: {r.reason}")
    return 0


def cmd_parse(args, settings: Settings) -> int:
    snap = Snapshot.open(_snapshots(settings), args.date)
    out_dir = settings.data_dir / "processed" / args.date
    out_dir.mkdir(parents=True, exist_ok=True)
    for source in select(settings, args.only):
        if not snap.is_complete(source.name):
            print(f"  skip     {source.name} (not complete in snapshot)")
            continue
        counts: Counter[str] = Counter()
        path = out_dir / f"{source.name}.jsonl.gz"
        with gzip.open(path, "wt", encoding="utf-8") as fh:
            for record in source.parse(snap):
                fh.write(record.model_dump_json() + "\n")
                counts[getattr(record, "as_of", "documents")] += 1
        summary = ", ".join(f"{k}={v:,}" for k, v in sorted(counts.items())) or "0 records"
        print(f"  parsed   {source.name:<13} {summary}  -> {path}")
    return 0


def cmd_gold_import(args, settings: Settings) -> int:
    records, report = gold.import_legacy(Path(args.gold), Path(args.entities), Path(args.corpus))
    out = Path(args.out) if args.out else settings.data_dir / "gold" / "gold.jsonl.gz"
    if out.exists():
        raise ConfigError(f"{out} already exists; the gold set is frozen")
    sha = gold.write_fixture(records, out)
    print(f"records        {report.records}")
    print(f"duplicates     {len(report.duplicate_ids)} dropped {report.duplicate_ids}")
    print(f"missing text   {len(report.missing_text)} {report.missing_text}")
    print(f"entities       {report.entities_kept} kept, {report.entities_dropped} dropped")
    print(f"labels         {dict(report.labels.most_common())}")
    print(f"sources        {dict(report.sources.most_common())}")
    print(f"derivations    {dict(report.derivations.most_common())}")
    print(f"wrote {out}\nsha256 {sha}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cti", description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    def only(p):
        p.add_argument("--only", type=lambda s: s.split(","), help="comma-separated sources")

    p = sub.add_parser("probe", help="cheap reachability/key check for each source")
    only(p)
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("ingest", help="the one-time fetch into a new snapshot")
    p.add_argument("--date", help="snapshot date YYYY-MM-DD (default: today)")
    p.add_argument("--resume", action="store_true", help="continue a failed run")
    p.add_argument("--refetch", metavar="SOURCE", help="re-download one completed source")
    p.add_argument("--reason", help="why a refetch is needed (required with --refetch)")
    p.add_argument(
        "--allow-date-mismatch",
        action="store_true",
        help="fetch into a snapshot dated other than today (e.g. resuming the next day)",
    )
    only(p)
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("status", help="show a snapshot's manifest")
    p.add_argument("--date", required=True)
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("parse", help="parse a snapshot offline into JSONL")
    p.add_argument("--date", required=True)
    only(p)
    p.set_defaults(func=cmd_parse)
    p = sub.add_parser("gold-import", help="freeze the gold set from the prototype's files")
    p.add_argument("--gold", required=True, help="labels JSONL")
    p.add_argument("--entities", required=True, help="entity spans JSONL")
    p.add_argument("--corpus", required=True, help="corpus JSONL with full text")
    p.add_argument("--out", help="default: <data_dir>/gold/gold.jsonl.gz")
    p.set_defaults(func=cmd_gold_import)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    # request URLs and redirect headers may carry keys
    for noisy in ("httpx", "httpcore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
    try:
        return args.func(args, Settings())
    except (ConfigError, ValueError, FileNotFoundError, SnapshotExistsError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
