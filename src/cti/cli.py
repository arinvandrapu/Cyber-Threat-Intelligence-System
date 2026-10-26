"""Command-line interface: ``cti probe | ingest | status | parse | enrich | upload``."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import logging
import sys
from collections import Counter
from datetime import date, timedelta
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError

from cti import gold
from cti.config import ConfigError, Settings
from cti.enrich import cves as cve_join
from cti.enrich import read_jsonl, write_json, write_jsonl
from cti.enrich.cwe import load_catalog
from cti.http.client import make_client
from cti.ingest import IngestResult, ingest, refetch
from cti.snapshot import Snapshot, SnapshotExistsError
from cti.sources.cwe import CWESource
from cti.sources.registry import select
from cti.storage import LocalStorage, S3Storage
from cti.upload import upload_gold, upload_snapshot

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


def _as_of_dates(snap: Snapshot, processed: Path, settings: Settings) -> dict[str, str]:
    """Dates of the as_of labels. The cutoff comes from the data itself (the EPSS cutoff
    file's score date) and must match the configured cutoff, so labels can never be
    paired with a different cutoff than the one the snapshot was pinned at."""
    expected = (snap.date - timedelta(days=settings.cutoff_days)).isoformat()
    pinned = next(
        (
            (r["values"].get("score_date") or "")[:10]
            for r in read_jsonl(processed / "epss.jsonl.gz")
            if r.get("as_of") == "cutoff"
        ),
        None,
    )
    if not pinned:
        raise ConfigError("no dated EPSS cutoff rows; the cutoff date can't be determined")
    if pinned != expected:
        raise ConfigError(
            f"snapshot cutoff is {pinned}, but CTI_CUTOFF_DAYS={settings.cutoff_days} "
            f"gives {expected}"
        )
    return {"cutoff": pinned, "snapshot": snap.id}


ENRICH_STEPS = ("cves",)


def cmd_enrich(args, settings: Settings) -> int:
    wanted = args.only or list(ENRICH_STEPS)
    if unknown := sorted(set(wanted) - set(ENRICH_STEPS)):
        raise ConfigError(f"unknown enrich steps {unknown}; choose from {ENRICH_STEPS}")
    processed = settings.data_dir / "processed" / args.date
    out_dir = settings.data_dir / "enriched" / args.date
    snap = Snapshot.open(_snapshots(settings), args.date)
    if "cves" in wanted:
        needed = ["nvd", "kev", "references", *cve_join.SIGNAL_SOURCES]
        if missing := [n for n in needed if not (processed / f"{n}.jsonl.gz").exists()]:
            raise ConfigError(f"missing parsed sources {missing}; run `cti parse` first")
        with CWESource(settings).open_xml(snap) as fh:
            catalog = load_catalog(fh)
        as_of_dates = _as_of_dates(snap, processed, settings)
        rows, summary = cve_join.build(processed, catalog, as_of_dates)
        write_jsonl(out_dir / "cves.jsonl.gz", rows)
        # ties the summary to the exact data file it describes
        summary["cves_sha256"] = hashlib.sha256(
            (out_dir / "cves.jsonl.gz").read_bytes()
        ).hexdigest()
        write_json(out_dir / "cves-summary.json", summary)
        print(
            f"  enriched cves          {summary['cves']:,} CVEs, eligible {summary['eligible']}, "
            f"KEV positives {summary['kev_positives']}  -> {out_dir / 'cves.jsonl.gz'}"
        )
    return 0


def _s3(settings: Settings, prefix: str) -> S3Storage:
    if not settings.s3_bucket:
        raise ConfigError("upload needs CTI_S3_BUCKET")
    return S3Storage(settings.s3_bucket, prefix, profile=settings.aws_profile)


def cmd_upload(args, settings: Settings) -> int:
    if not (args.date or args.gold):
        raise ConfigError("upload needs --date, --gold, or both")
    ok = True
    if args.gold:
        path = settings.data_dir / "gold" / "gold.jsonl.gz"
        wrote = upload_gold(path, _s3(settings, "gold"))
        print(f"gold     {'uploaded' if wrote else 'already present'}")
    if args.date:
        result = upload_snapshot(_snapshots(settings), _s3(settings, settings.s3_prefix), args.date)
        print(
            f"snapshot {result.snapshot_id}: {result.uploaded} uploaded "
            f"({result.bytes_uploaded / 1e6:.1f} MB), {result.already_present} already present, "
            f"manifest {'updated' if result.manifest_updated else 'unchanged'}"
        )
        for key in result.missing:
            print(f"  MISSING  {key}")
        ok = result.ok
    return 0 if ok else 1


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

    p = sub.add_parser("enrich", help="offline joins and cleaning into data/enriched/<date>/")
    p.add_argument("--date", required=True)
    p.add_argument("--only", type=lambda s: s.split(","), help=f"subset of {ENRICH_STEPS}")
    p.set_defaults(func=cmd_enrich)

    p = sub.add_parser("upload", help="copy a finished snapshot and/or the gold set to S3")
    p.add_argument("--date", help="snapshot to upload")
    p.add_argument("--gold", action="store_true", help="upload the frozen gold fixture")
    p.set_defaults(func=cmd_upload)

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
    except (
        ConfigError,
        ValueError,
        FileNotFoundError,
        FileExistsError,
        SnapshotExistsError,
    ) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (BotoCoreError, ClientError) as exc:  # AWS errors carry no secrets
        print(f"aws error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
