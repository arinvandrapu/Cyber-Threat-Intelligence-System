"""Command-line interface: ``cti probe | ingest | status | parse | enrich | extract | upload``."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import importlib.util
import json
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
from cti.enrich import references as ref_clean
from cti.enrich.cwe import load_catalog
from cti.http.client import make_client
from cti.ingest import IngestResult, ingest, refetch
from cti.nlp import evaluate as extract_eval
from cti.nlp import extract
from cti.snapshot import Snapshot, SnapshotExistsError
from cti.sources.cwe import CWESource
from cti.sources.nvd import NVDArchiveSource
from cti.sources.registry import select
from cti.storage import LocalStorage, S3Storage
from cti.upload import upload_gold, upload_snapshot

log = logging.getLogger("cti")


def _snapshots(settings: Settings) -> LocalStorage:
    return LocalStorage(settings.data_dir / "snapshots")


def _reference_snapshots(settings: Settings) -> LocalStorage:
    """Reference-only fetches (e.g. old NVD feeds); local and gitignored, never uploaded."""
    return LocalStorage(settings.data_dir / "reference-snapshots")


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


def _report(result: IngestResult, command: str = "cti ingest") -> int:
    print(f"snapshot {result.snapshot_id}")
    for name in result.completed:
        print(f"  done     {name}")
    for name in result.skipped:
        print(f"  skipped  {name} (already complete)")
    for name, error in result.failed.items():
        print(f"  FAILED   {name}: {error}")
    if not result.ok:
        print(f"Fix the cause, then run `{command} --resume --date ...`.")
    return 0 if result.ok else 1


def cmd_ingest(args, settings: Settings) -> int:
    sources = select(settings, args.only)
    if args.new_dates_only and not args.refetch:
        raise ConfigError("--new-dates-only needs --refetch")
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
                storage,
                settings,
                snapshot_date.isoformat(),
                source,
                args.reason,
                client,
                new_dates_only=args.new_dates_only,
            )
        else:
            result = ingest(storage, settings, snapshot_date, sources, client, resume=args.resume)
    return _report(result)


def cmd_fetch_nvd_archive(args, settings: Settings) -> int:
    snapshot_date = date.fromisoformat(args.date) if args.date else date.today()
    source = NVDArchiveSource(settings)
    with make_client(settings.user_agent) as client:
        result = ingest(
            _reference_snapshots(settings),
            settings,
            snapshot_date,
            [source],
            client,
            resume=args.resume,
        )
    return _report(result, "cti fetch-nvd-archive")


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
    """Dates of the as_of labels. Each cutoff date comes from the data itself (that EPSS
    file's score date) and must match snapshot - k * CTI_CUTOFF_DAYS, so labels can never
    be paired with a different cutoff than the one the snapshot was pinned at."""
    pinned: dict[str, str] = {}
    for r in read_jsonl(processed / "epss.jsonl.gz"):
        label = r.get("as_of", "")
        if label.startswith("cutoff") and label not in pinned:
            pinned[label] = (r["values"].get("score_date") or "")[:10]
    if not pinned.get("cutoff"):
        raise ConfigError("no dated EPSS cutoff rows; the cutoff date can't be determined")
    for label, day in pinned.items():
        k = int(label.removeprefix("cutoff") or 1)
        expected = (snap.date - k * timedelta(days=settings.cutoff_days)).isoformat()
        if day != expected:
            raise ConfigError(
                f"snapshot {label} is {day or 'undated'}, but "
                f"CTI_CUTOFF_DAYS={settings.cutoff_days} gives {expected}"
            )
    return {**dict(sorted(pinned.items(), key=lambda kv: kv[1])), "snapshot": snap.id}


ENRICH_STEPS = ("cves", "references")


def _write_enriched(out_dir: Path, name: str, rows: list[dict], summary: dict) -> Path:
    path = out_dir / f"{name}.jsonl.gz"
    write_jsonl(path, rows)
    # ties the summary to the exact data file it describes
    summary[f"{name}_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    write_json(out_dir / f"{name}-summary.json", summary)
    return path


def cmd_enrich(args, settings: Settings) -> int:
    wanted = args.only or list(ENRICH_STEPS)
    if unknown := sorted(set(wanted) - set(ENRICH_STEPS)):
        raise ConfigError(f"unknown enrich steps {unknown}; choose from {ENRICH_STEPS}")
    if "references" in wanted and importlib.util.find_spec("trafilatura") is None:
        raise ConfigError("cleaning references needs the enrich extra: pip install -e '.[enrich]'")
    processed = settings.data_dir / "processed" / args.date
    out_dir = settings.data_dir / "enriched" / args.date
    snap = Snapshot.open(_snapshots(settings), args.date)
    if "cves" in wanted:
        needed = ["nvd", "kev", "references", *cve_join.SIGNAL_SOURCES]
        if missing := [n for n in needed if not (processed / f"{n}.jsonl.gz").exists()]:
            raise ConfigError(f"missing parsed sources {missing}; run `cti parse` first")
        if incomplete := [n for n in cve_join.SIGNAL_SOURCES if not snap.is_complete(n)]:
            raise ConfigError(f"sources {incomplete} are incomplete in the snapshot; refetch them")
        with CWESource(settings).open_xml(snap) as fh:
            catalog = load_catalog(fh)
        as_of_dates = _as_of_dates(snap, processed, settings)
        rows, summary = cve_join.build(processed, catalog, as_of_dates)
        path = _write_enriched(out_dir, "cves", rows, summary)
        print(
            f"  enriched cves          {summary['cves']:,} CVEs, eligible {summary['eligible']}, "
            f"KEV positives {summary['kev_positives']}  -> {path}"
        )
    if "references" in wanted:
        rows, summary = ref_clean.build(snap)
        path = _write_enriched(out_dir, "references", rows, summary)
        print(
            f"  enriched references    {summary['pages']:,} pages, {summary['in_corpus']:,} in "
            f"corpus, flags {summary['flags']}  -> {path}"
        )
    return 0


EXTRACT_STEPS = ("iocs", "aliases")


def _extract_inputs(settings: Settings, day: str) -> tuple[Path, Path]:
    date.fromisoformat(day)  # a path component: reject anything but YYYY-MM-DD
    processed = settings.data_dir / "processed" / day
    enriched = settings.data_dir / "enriched" / day
    needed = [processed / f"{n}.jsonl.gz" for n in ("nvd", "attack", "threatfox")]
    needed.append(enriched / "references.jsonl.gz")
    if missing := [str(p) for p in needed if not p.exists()]:
        raise ConfigError(f"missing inputs {missing}; run `cti parse` and `cti enrich` first")
    return processed, enriched


def cmd_extract(args, settings: Settings) -> int:
    wanted = args.only or list(EXTRACT_STEPS)
    if unknown := sorted(set(wanted) - set(EXTRACT_STEPS)):
        raise ConfigError(f"unknown extract steps {unknown}; choose from {EXTRACT_STEPS}")
    processed, enriched = _extract_inputs(settings, args.date)
    out_dir = settings.data_dir / "extracted" / args.date
    if "iocs" in wanted:
        rows, summary = extract.build_iocs(processed, enriched)
        path = _write_enriched(out_dir, "iocs", rows, summary)
        head = summary["iocs"].get(extract.HEADLINE_ORIGIN, {})
        print(f"  extracted iocs         {sum(head.values()):,} from pages {head}  -> {path}")
    if "aliases" in wanted:
        rows, summary = extract.build_aliases(processed, enriched)
        path = _write_enriched(out_dir, "aliases", rows, summary)
        print(
            f"  extracted aliases      {summary['matches']} mentions, "
            f"{summary['ambiguous_matches']} ambiguous  -> {path}"
        )
    return 0


def cmd_extract_eval(args, settings: Settings) -> int:
    processed, enriched = _extract_inputs(settings, args.date)
    iocs_path = settings.data_dir / "extracted" / args.date / "iocs.jsonl.gz"
    if not iocs_path.exists():
        raise ConfigError(f"missing {iocs_path}; run `cti extract` first")
    rows = list(read_jsonl(iocs_path))
    eval_dir = settings.data_dir / "eval" / args.date
    if args.sample is not None:
        if args.sample < 1:
            raise ConfigError("--sample needs a positive number of IOCs")
        if args.labels:
            raise ConfigError("--sample writes a new sheet; score labels in a separate run")
        sheet = eval_dir / f"ioc-review-sample-seed{args.seed}.csv"
        if sheet.exists():  # it may already hold labels
            raise ConfigError(f"{sheet} already exists; move it or pick another --seed")
        sample = extract_eval.draw_sample(rows, args.sample, args.seed)
        wanted = {row["doc_id"] for row, _ in sample}
        texts = {d: t for d, _, _, t in extract.iter_texts(processed, enriched) if d in wanted}
        extract_eval.write_review_sheet(sheet, sample, texts)
        print(f"  review sheet           {len(sample)} IOCs  -> {sheet}")
        return 0
    result: dict = {"iocs_sha256": hashlib.sha256(iocs_path.read_bytes()).hexdigest()}
    gold_path = settings.data_dir / "gold" / "gold.jsonl.gz"
    if gold_path.exists():
        result["gold"] = extract_eval.gold_eval(gold.load_gold(gold_path))
        print(f"  gold set               {result['gold']['scores']}")
    if args.labels:
        labels = extract_eval.read_labels(Path(args.labels))
        result["review"] = extract_eval.score_review(rows, labels)
        result["review"]["labels"] = args.labels
        result["review"]["labels_sha256"] = hashlib.sha256(
            Path(args.labels).read_bytes()
        ).hexdigest()
        print(f"  review sample          {result['review']['overall']}")
    out = eval_dir / "extract-eval.json"
    write_json(out, result)
    print(f"  wrote {out}")
    return 0


ATTACK_METHODS = ("tfidf", "biencoder")


def cmd_attack_eval(args, settings: Settings) -> int:
    if importlib.util.find_spec("sklearn") is None:
        raise ConfigError("ATT&CK grading needs the ml extra: pip install -e '.[ml]'")
    from cti.nlp import attack_catalog, attack_eval

    # default: every method whose extra is installed (the output records which ran)
    has_torch = importlib.util.find_spec("torch") is not None
    wanted = args.methods or [m for m in ATTACK_METHODS if m != "biencoder" or has_torch]
    if unknown := sorted(set(wanted) - set(ATTACK_METHODS)):
        raise ConfigError(f"unknown methods {unknown}; choose from {ATTACK_METHODS}")
    if "biencoder" in wanted and importlib.util.find_spec("torch") is None:
        raise ConfigError("the biencoder method needs the nlp extra: pip install -e '.[nlp]'")
    date.fromisoformat(args.date)
    processed = settings.data_dir / "processed" / args.date
    if missing := [
        n for n in ("nvd", "kev", "attack") if not (processed / f"{n}.jsonl.gz").exists()
    ]:
        raise ConfigError(f"missing parsed sources {missing}; run `cti parse` first")
    snap = Snapshot.open(_snapshots(settings), args.date)
    techniques = attack_catalog.load_techniques(processed)
    revoked = attack_catalog.revocations(snap)
    ctid_path = Path(args.ctid) if args.ctid else settings.data_dir / attack_eval.CTID_FILE
    gold_rows = attack_eval.load_ctid(ctid_path)
    gold_set, remapped = attack_eval.gold_labels(gold_rows, revoked)
    texts = attack_eval.cve_texts(processed, set(gold_set))
    rankers = {}
    if "tfidf" in wanted:
        rankers["tfidf"] = attack_eval.TfidfRanker(techniques).scores
    if "biencoder" in wanted:
        from cti.nlp import embed

        rankers["biencoder"] = embed.BiencoderRanker(techniques, embed.Encoder()).scores
    result = attack_eval.evaluate(gold_set, texts, techniques, rankers)
    result |= {
        "ctid": {
            "file": str(ctid_path),
            "sha256": hashlib.sha256(ctid_path.read_bytes()).hexdigest(),
            "rows": len(gold_rows),
            "cves": len(gold_set),
            "revoked_rows_remapped": remapped,
        },
        "candidates": {
            "techniques": len(techniques),
            "parents": len({attack_catalog.parent(t.id) for t in techniques}),
        },
    }
    out = settings.data_dir / "eval" / args.date / "attack-eval.json"
    write_json(out, result)
    primary = result["results"]["test"]["nvd"]
    for name in result["methods"]:
        cell = primary[name][attack_eval.PRIMARY_TYPE]
        print(
            f"  {name:<10} test/nvd {attack_eval.PRIMARY_TYPE}: n={cell['cves']} "
            f"hit@5 {cell['hit@5']['value']} {cell['hit@5']['ci95']}  mrr {cell['mrr']['value']}"
        )
    print(f"  wrote {out}")
    return 0


def cmd_cwe_eval(args, settings: Settings) -> int:
    if importlib.util.find_spec("sklearn") is None:
        raise ConfigError("CWE evaluation needs the ml extra: pip install -e '.[ml]'")
    import numpy as np

    from cti.nlp import cwe_eval

    date.fromisoformat(args.date)
    processed = settings.data_dir / "processed" / args.date
    extracted = settings.data_dir / "extracted" / args.date
    needed = [
        processed / "nvd.jsonl.gz",
        extracted / "nvd-embeddings.npy",
        extracted / "nvd-embeddings-masked.npy",
    ]
    if missing := [str(p) for p in needed if not p.exists()]:
        raise ConfigError(
            f"missing {missing}; run `cti parse`, `cti embed`, `cti embed --cwe-id-masked`"
        )
    snap = Snapshot.open(_snapshots(settings), args.date)
    with CWESource(settings).open_xml(snap) as fh:
        catalog = load_catalog(fh)
    examples = cwe_eval.load_examples(processed, catalog)
    full = np.load(extracted / "nvd-embeddings.npy", mmap_mode="r")
    rows = {r["cve"]: r["row"] for r in read_jsonl(extracted / "nvd-embeddings-index.jsonl.gz")}
    masked = np.load(extracted / "nvd-embeddings-masked.npy")
    masked_rows = {
        r["cve"]: r["row"] for r in read_jsonl(extracted / "nvd-embeddings-masked-index.jsonl.gz")
    }

    def vectors(cves, use_masked):
        out = np.asarray(full[[rows[c] for c in cves]], dtype=np.float32)
        if use_masked:
            for i, c in enumerate(cves):
                if c in masked_rows:
                    out[i] = masked[masked_rows[c]]
        return out

    result = cwe_eval.run(examples, vectors, catalog, log=print)
    result["inputs"] = {
        name: hashlib.sha256((extracted / f"{name}-index.jsonl.gz").read_bytes()).hexdigest()
        for name in ("nvd-embeddings", "nvd-embeddings-masked")
    }
    gold_path = settings.data_dir / "gold" / "gold.jsonl.gz"
    if gold_path.exists():
        result["gold_sanity_check"] = cwe_eval.gold_check(gold.load_gold(gold_path))
    out = settings.data_dir / "eval" / args.date / "cwe-eval.json"
    write_json(out, result)
    head = result["test"]
    for method, cell in head.items():
        m = cell["name_absent"]
        print(f"  {method:<10} test name-absent macro-F1 {m['macro_f1']} {m['macro_f1_ci95']}")
    print(f"  wrote {out}")
    return 0


def _git_state(here: Path | None = None) -> dict:
    """The checked-out commit and whether tracked files under src/ differ from it."""
    import shutil
    import subprocess

    here = here or Path(__file__).parent
    if (git := shutil.which("git")) is None:
        return {"commit": None, "dirty": None}

    def run(*args: str) -> str:
        return subprocess.run(  # noqa: S603 - fixed argv
            [git, *args], cwd=here, capture_output=True, text=True, check=True, timeout=10
        ).stdout.strip()

    try:
        return {
            "commit": run("rev-parse", "HEAD"),
            # ":(top)" anchors the pathspec at the repo root (git runs from src/cti)
            "dirty": bool(run("status", "--porcelain", "--untracked-files=no", "--", ":(top)src")),
        }
    except (OSError, subprocess.SubprocessError):
        return {"commit": None, "dirty": None}


def cmd_risk_eval(args, settings: Settings) -> int:
    if importlib.util.find_spec("sklearn") is None:
        raise ConfigError("risk evaluation needs the ml extra: pip install -e '.[ml]'")
    import numpy as np

    from cti.nlp import risk_config, risk_eval

    date.fromisoformat(args.date)
    enriched = settings.data_dir / "enriched" / args.date
    extracted = settings.data_dir / "extracted" / args.date
    needed = [
        enriched / "cves.jsonl.gz",
        enriched / "cves-summary.json",
        extracted / "nvd-embeddings.npy",
        extracted / "nvd-embeddings-index.jsonl.gz",
    ]
    if missing := [str(p) for p in needed if not p.exists()]:
        raise ConfigError(f"missing {missing}; run `cti enrich` and `cti embed` first")
    summary = json.loads((enriched / "cves-summary.json").read_text())
    if absent := [c for c in risk_config.CUTOFFS if c not in summary["as_of_dates"]]:
        raise ConfigError(f"enriched data has no {absent}; refetch with extra cutoffs")
    windows = risk_eval.build_windows(
        read_jsonl(enriched / "cves.jsonl.gz"), summary["as_of_dates"]
    )
    index = list(read_jsonl(extracted / "nvd-embeddings-index.jsonl.gz"))
    rows = {r["cve"]: r["row"] for r in index}
    kev_language = {r["cve"] for r in index if r["kev_language"]}
    full = np.load(extracted / "nvd-embeddings.npy", mmap_mode="r")

    def vectors(cves):
        return np.asarray(full[[rows[c] for c in cves]], dtype=np.float32)

    pooled_positives = sum(int(windows[f].y.sum()) for f in risk_config.FOLDS)
    if pooled_positives != 68:  # the number named in the pre-registered headline
        print(f"  WARNING: {pooled_positives} test positives, pre-registration expects 68")
    result = risk_eval.run(windows, vectors, kev_language, log=print)
    import sklearn

    config_path = Path(risk_config.__file__)
    result["provenance"] = {
        "config_sha256": hashlib.sha256(config_path.read_bytes()).hexdigest(),
        "git": _git_state(),
        "versions": {"numpy": np.__version__, "scikit-learn": sklearn.__version__},
        "test_positives_expected": 68,
        "test_positives_found": pooled_positives,
        "cves_sha256": summary.get("cves_sha256"),
        "embeddings_index_sha256": hashlib.sha256(
            (extracted / "nvd-embeddings-index.jsonl.gz").read_bytes()
        ).hexdigest(),
        "kev_catalog_version": risk_config.KEV_CATALOG_VERSION,
    }
    out = settings.data_dir / "eval" / args.date / "risk-eval.json"
    write_json(out, result)
    for method, cell in result["methods"].items():
        pooled = cell["pooled"]
        print(
            f"  {method:<10} pooled recall@100 {pooled['recall@100']} "
            f"{pooled['recall@100_wilson95']}  mean AP {pooled['mean_average_precision']}"
        )
    d = result["decision"]
    print(f"  decision: {d['verdict']} {d['logistic_minus_epss_hits@100']}")
    print(f"  wrote {out}")
    return 0


def cmd_threats_sheet(args, settings: Settings) -> int:
    from cti.threats import review
    from cti.threats.config import CATEGORIES, LABEL_SEPARATOR

    iocs = settings.data_dir / "processed" / args.date / "threatfox.jsonl.gz"
    path = settings.data_dir / "reference" / f"threat-categories-{args.date}.csv"
    fams = review.families(read_jsonl(iocs))
    top = review.write_sheet(path, fams)
    named = sum(f.rows for f in fams if review.is_named(f))
    share = sum(f.rows for f in top) / named if named else 0.0
    print(f"wrote {path}: top {len(top)} named families, {share:.1%} of named rows")
    print(f"Fill `categories` (several allowed, separated by '{LABEL_SEPARATOR}') from:")
    print("  " + " ".join(CATEGORIES))
    return 0


def cmd_threats(args, settings: Settings) -> int:
    from cti import reference
    from cti.nlp import attack_catalog
    from cti.threats import catalog, review
    from cti.threats import config as threat_cfg

    processed = settings.data_dir / "processed" / args.date
    aliases = settings.data_dir / "extracted" / args.date / "aliases.jsonl.gz"
    risk = settings.data_dir / "export" / args.date / "risk.json"
    sheet = settings.data_dir / "reference" / f"threat-categories-{args.date}.csv"
    for path, step in ((aliases, "cti extract"), (risk, "cti export")):
        if not path.exists():
            raise ConfigError(f"missing {path}; run `{step} --date {args.date}` first")
    review_status = review.status(sheet)
    owner = review.read_labels(sheet) if review_status == "labelled" else {}
    clusters = {
        name: json.loads(reference.read_pinned(settings.data_dir, f"misp-galaxy/{name}.json"))
        for name in reference.MISP_CATEGORIES
    }
    snap = Snapshot.open(_snapshots(settings), args.date)
    tactics = {
        r["source_id"]: tuple(r["metadata"]["tactics"])
        for r in read_jsonl(processed / "attack.jsonl.gz")
        if r["metadata"]["stix_type"] == "attack-pattern"
    }
    result = catalog.build(
        iocs=list(read_jsonl(processed / "threatfox.jsonl.gz")),
        clusters=clusters,
        attack_docs=read_jsonl(processed / "attack.jsonl.gz"),
        uses=attack_catalog.uses(snap),
        tactics=tactics,
        alias_rows=read_jsonl(aliases),
        kev=read_jsonl(processed / "kev.jsonl.gz"),
        tiers={r["cve"]: r["tier"] for r in json.loads(risk.read_text())["rows"]},
        owner=owner,
        day=date.fromisoformat(args.date),
    )
    auto = {f["family"]: tuple(f["misp_categories"]) for f in result["families"]}
    link_sheet = settings.data_dir / "reference" / f"threat-links-{args.date}.csv"
    if not link_sheet.exists():
        urls = {
            r["id"]: r["final_url"]
            for r in read_jsonl(settings.data_dir / "enriched" / args.date / "references.jsonl.gz")
        }
        links = [
            {
                "family": f["family"],
                "cve": c["cve"],
                "via": c["via"],
                "surface": " | ".join(sorted({e["surface"] for e in c["evidence"]})),
                "evidence_url": " | ".join(sorted(urls[e["doc_id"]] for e in c["evidence"]))
                or f"https://threatfox.abuse.ch/browse/tag/{c['cve']}/",
            }
            for f in result["families"]
            for c in f["cves"]
        ]
        print(f"wrote {link_sheet}: {review.write_link_sheet(link_sheet, links)} links to review")
    link_status = review.status(link_sheet, "correct")
    current = {(f["family"], c["cve"], c["via"]) for f in result["families"] for c in f["cves"]}
    if review.link_keys(link_sheet) != current:
        # written by an earlier run with other links: its marks would score other links
        link_status = "stale"
        print(f"  warning: {link_sheet} lists other links than this run; not scored")
    result["review"] = {
        "categories": {
            "sheet": str(sheet.relative_to(settings.data_dir)),
            "status": review_status,
            "not_in_snapshot": sorted(set(owner) - set(auto)),
            "agreement": catalog.agreement(owner, auto) if owner else None,
        },
        "links": {
            "sheet": str(link_sheet.relative_to(settings.data_dir)),
            "status": link_status,
            "precision": catalog.link_precision(review.read_link_labels(link_sheet))
            if link_status == "labelled"
            else None,
        },
    }
    result["provenance"] = {
        "config_sha256": hashlib.sha256(Path(threat_cfg.__file__).read_bytes()).hexdigest(),
        "git": _git_state(),
        "misp_sha256": {n: reference.PINNED[f"misp-galaxy/{n}.json"] for n in clusters},
    }
    out = settings.data_dir / "threats" / args.date / "threats.json"
    write_json(out, result)
    s = result["summary"]
    # counts only: per-family categories stay out of the terminal until the owner's blind
    # labels are committed (vault/threat-layer.md)
    print(f"wrote {out}")
    print(f"  {s['named_families']} named families, {s['ioc_rows']:,} IOC rows")
    print(f"  category source {s['category_source']}; category review: {review_status}")
    print(f"  link review: {link_status}")
    print(f"  ATT&CK software {s['with_attack_software']}; CVE links {s['cve_links']}")
    return 0


def cmd_export(args, settings: Settings) -> int:
    if importlib.util.find_spec("sklearn") is None:
        raise ConfigError("the export refits the risk model: pip install -e '.[ml]'")
    from cti.dashboard import export
    from cti.nlp import attack_catalog

    date.fromisoformat(args.date)
    paths = export.inputs(settings.data_dir, args.date)
    revoked = attack_catalog.revocations(Snapshot.open(_snapshots(settings), args.date))
    files = export.run(paths, revoked, _git_state())
    out = settings.data_dir / "export" / args.date
    for name, size in export.write(out, files).items():
        print(f"  wrote {out / name} ({size / 1e6:.1f} MB)")
    return 0


def cmd_serve(args, settings: Settings) -> int:
    from cti.dashboard import serve

    root = settings.data_dir / "export"
    if args.export_dir and args.date:
        raise ConfigError("use --date or --export-dir, not both")
    if args.export_dir:
        export_dir = Path(args.export_dir)
    elif args.date:
        date.fromisoformat(args.date)
        export_dir = root / args.date
    else:
        days = (
            sorted(p.name for p in root.glob("????-??-??") if p.is_dir()) if root.exists() else []
        )
        if not days:
            raise ConfigError("no dashboard export; run `cti export --date <snapshot date>`")
        export_dir = root / days[-1]
    day = export_dir.name
    if not (export_dir / "meta.json").exists():
        raise ConfigError(f"no export for {day}; run `cti export --date {day}`")
    server = serve.make_server(Path(args.dist), export_dir, args.port)
    host, port = server.server_address[:2]
    print(f"  serving the {day} export at http://{host}:{port}/ (Ctrl-C to stop)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _need_nlp() -> None:
    if (
        importlib.util.find_spec("torch") is None
        or importlib.util.find_spec("transformers") is None
    ):
        raise ConfigError("this command needs the nlp extra: pip install -e '.[nlp]'")


def _progress(label: str):
    def report(done: int, total: int) -> None:
        if done == total or done % 2000 < 32:
            print(f"  {label:<22} {done:,}/{total:,}", flush=True)

    return report


def cmd_models(args, settings: Settings) -> int:
    _need_nlp()
    from cti.nlp import models

    for name, spec in models.MODELS.items():
        if args.action == "fetch":
            path = models.fetch(spec)
        else:
            path = models.local_path(spec)
            models.verify(spec, path)
        print(f"  {name:<10} {spec.repo}@{spec.revision[:7]}  verified  {path}")
    return 0


def cmd_ner(args, settings: Settings) -> int:
    _need_nlp()
    from cti.nlp import ner, semantic

    processed, enriched = _extract_inputs(settings, args.date)
    tagger = ner.Tagger()
    rows, summary = semantic.build_entities(
        enriched, tagger, extract.alias_index(processed), progress=_progress("ner windows")
    )
    path = _write_enriched(settings.data_dir / "extracted" / args.date, "entities", rows, summary)
    print(f"  entities               {summary['entities']}  -> {path}")
    return 0


def cmd_ner_eval(args, settings: Settings) -> int:
    _need_nlp()
    from cti.nlp import ner, semantic

    date.fromisoformat(args.date)
    gold_path = settings.data_dir / "gold" / "gold.jsonl.gz"
    records = gold.load_gold(gold_path)
    tagger = ner.Tagger()
    result = {
        "model": {"repo": tagger.spec.repo, "revision": tagger.spec.revision},
        "all_spans": semantic.ner_gold_eval(records, tagger),
        "text_derived_spans": semantic.ner_gold_eval(records, tagger, text_only=True),
    }
    out = settings.data_dir / "eval" / args.date / "ner-eval.json"
    write_json(out, result)
    for label, m in result["text_derived_spans"]["overlap"].items():
        print(f"  {label:<14} overlap P {m['precision']}  R {m['recall']}  F1 {m['f1']}")
    print(f"  wrote {out}")
    return 0


def cmd_embed(args, settings: Settings) -> int:
    _need_nlp()
    import numpy as np

    from cti.nlp import embed, semantic

    date.fromisoformat(args.date)
    processed = settings.data_dir / "processed" / args.date
    if not (processed / "nvd.jsonl.gz").exists():
        raise ConfigError("missing parsed nvd; run `cti parse` first")
    if args.cwe_id_masked:
        vectors, index, summary = semantic.build_masked_embeddings(processed, embed.Encoder())
        name = "nvd-embeddings-masked"
    else:
        vectors, index, summary = semantic.build_embeddings(
            processed, embed.Encoder(), progress=_progress("embedded")
        )
        name = "nvd-embeddings"
    out_dir = settings.data_dir / "extracted" / args.date
    out_dir.mkdir(parents=True, exist_ok=True)
    npy = out_dir / f"{name}.npy"
    tmp = npy.with_name(f".{npy.name}.tmp")
    with tmp.open("wb") as fh:
        np.save(fh, vectors)
    tmp.replace(npy)
    path = _write_enriched(out_dir, f"{name}-index", index, summary)
    print(f"  embeddings             {summary['rows']:,} x {summary['dim']}  -> {npy}, {path}")
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
        "--new-dates-only",
        action="store_true",
        help="with --refetch: keep the dated files already held, fetch only missing dates",
    )
    p.add_argument(
        "--allow-date-mismatch",
        action="store_true",
        help="fetch into a snapshot dated other than today (e.g. resuming the next day)",
    )
    only(p)
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser(
        "fetch-nvd-archive",
        help="NVD feeds from 2002 up to the main source's first feed (2002-2022 by default), "
        "for Phase 10b (into data/reference-snapshots/; never uploaded)",
    )
    p.add_argument("--date", help="reference snapshot date YYYY-MM-DD (default: today)")
    p.add_argument("--resume", action="store_true", help="continue a failed run")
    p.set_defaults(func=cmd_fetch_nvd_archive)

    p = sub.add_parser(
        "threats-sheet", help="blank blind-review sheet of the top ThreatFox families (10a)"
    )
    p.add_argument("--date", required=True)
    p.set_defaults(func=cmd_threats_sheet)

    p = sub.add_parser("threats", help="threat catalog: categories, ATT&CK, CVE links, priority")
    p.add_argument("--date", required=True)
    p.set_defaults(func=cmd_threats)

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

    p = sub.add_parser("extract", help="regex IOCs and alias mentions into data/extracted/<date>/")
    p.add_argument("--date", required=True)
    p.add_argument("--only", type=lambda s: s.split(","), help=f"subset of {EXTRACT_STEPS}")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("extract-eval", help="score the IOC extractor (gold set, review sample)")
    p.add_argument("--date", required=True)
    p.add_argument("--sample", type=int, metavar="N", help="write a review sheet of N IOCs")
    p.add_argument("--seed", type=int, default=20261027, help="sampling seed")
    p.add_argument("--labels", help="labelled review CSV to score")
    p.set_defaults(func=cmd_extract_eval)

    p = sub.add_parser("attack-eval", help="grade CVE -> ATT&CK ranking on CTID KEV mappings")
    p.add_argument("--date", required=True)
    p.add_argument("--methods", type=lambda s: s.split(","), help=f"subset of {ATTACK_METHODS}")
    p.add_argument(
        "--ctid",
        help="a relocated copy of the pinned CTID file (default: <data_dir>/reference/ctid/); "
        "its SHA-256 must match",
    )
    p.set_defaults(func=cmd_attack_eval)

    p = sub.add_parser("cwe-eval", help="classify NVD descriptions into CWEs (Phase 6)")
    p.add_argument("--date", required=True)
    p.set_defaults(func=cmd_cwe_eval)

    p = sub.add_parser("risk-eval", help="forward-looking KEV prediction (Phase 7b)")
    p.add_argument("--date", required=True)
    p.set_defaults(func=cmd_risk_eval)

    p = sub.add_parser("export", help="dashboard data into data/export/<date>/ (Phase 8)")
    p.add_argument("--date", required=True)
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("serve", help="the dashboard on 127.0.0.1, read-only")
    p.add_argument("--date", help="export to serve (default: the newest)")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--dist", default="web/dist", help="built dashboard (npm run build)")
    p.add_argument("--export-dir", help="serve this export folder (e.g. web/fixtures)")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("models", help="SecureBERT 2.0 models: one-time fetch, or verify")
    p.add_argument("action", choices=("fetch", "verify"))
    p.set_defaults(func=cmd_models)

    p = sub.add_parser("ner", help="SecureBERT NER over the reference corpus")
    p.add_argument("--date", required=True)
    p.set_defaults(func=cmd_ner)

    p = sub.add_parser("ner-eval", help="score SecureBERT NER against the gold set")
    p.add_argument("--date", required=True, help="where to write the result (data/eval/<date>/)")
    p.set_defaults(func=cmd_ner_eval)

    p = sub.add_parser("embed", help="SecureBERT bi-encoder embeddings of NVD descriptions")
    p.add_argument("--date", required=True)
    p.add_argument(
        "--cwe-id-masked",
        action="store_true",
        help="only descriptions with a literal CWE-<n>, embedded with the ID masked",
    )
    p.set_defaults(func=cmd_embed)

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
