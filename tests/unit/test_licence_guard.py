"""abuse.ch terms of use §7.3: ThreatFox and URLhaus data may not train or improve AI models.

Static guards so a new code path can't start fitting on that data unnoticed. Each allowed
use is listed with the reason it is not training; adding one needs a conscious review.
"""

import ast
import re
from pathlib import Path

from cti import gold

SRC = Path(__file__).resolve().parents[2] / "src" / "cti"

# Modules that may name the abuse.ch feeds (and so read them), and why that isn't training.
FEED_READERS = {
    "gold.py": "defines NO_TRAINING_SOURCES",
    "sources/abusech.py": "fetches and parses the feeds",
    "nlp/aliases.py": "tags lookup-list entities that come from ThreatFox family names",
    "nlp/extract.py": "builds the alias lookup list from family names",
    "dashboard/export.py": "publishes aggregate counts only",
    "threats/catalog.py": "counts families and looks them up; nothing is fitted",
    "cli.py": "checks `cti extract` inputs; `cti threats-sheet` counts families (lookup)",
}

# Functions that load the gold set without fitting on it (or filter before fitting).
GOLD_LOADERS = {
    "cmd_extract_eval": "regex extraction scored against gold spans; nothing is fitted",
    "cmd_ner_eval": "inference with a pinned, frozen model; nothing is fitted",
    "cmd_cwe_eval": "gold_check drops NO_TRAINING_SOURCES (test_cwe_eval spies on the fit)",
}

FEED_NAME = re.compile(r"^(threatfox|urlhaus)(\.jsonl\.gz)?$")


def _modules():
    for path in sorted(SRC.rglob("*.py")):
        yield path.relative_to(SRC).as_posix(), path.read_text()


def test_no_training_sources_cover_both_abusech_feeds():
    assert {"threatfox", "urlhaus"} <= gold.NO_TRAINING_SOURCES


def test_only_listed_modules_read_abusech_feeds():
    readers = {
        name
        for name, text in _modules()
        for node in ast.walk(ast.parse(text))
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
        if FEED_NAME.match(node.value)
    }
    assert readers <= set(FEED_READERS), sorted(readers - set(FEED_READERS))


def test_gold_loads_are_filtered_or_listed():
    offenders = []
    for name, text in _modules():
        tree = ast.parse(text)
        for func in ast.walk(tree):
            if not isinstance(func, ast.FunctionDef | ast.AsyncFunctionDef):
                continue
            for node in ast.walk(func):
                if not (isinstance(node, ast.Call) and _called(node) == "load_gold"):
                    continue
                if func.name in GOLD_LOADERS or _wrapped_in_trainable(func, node):
                    continue
                offenders.append(f"{name}:{node.lineno} in {func.name}")
    assert not offenders, offenders


def _called(call: ast.Call) -> str | None:
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)


def _wrapped_in_trainable(func: ast.AST, target: ast.Call) -> bool:
    return any(
        isinstance(n, ast.Call) and _called(n) == "trainable" and target in n.args
        for n in ast.walk(func)
    )


def test_trainable_drops_abusech_records():
    def rec(source):
        return gold.GoldRecord(
            id=f"{source}:1",
            source=source,
            title="t",
            text="x",
            labels=["l"],
            primary_label="l",
            label_signals=[],
            entities=[],
        )

    kept = gold.trainable([rec("threatfox"), rec("urlhaus"), rec("nvd_ref")])
    assert [r.source for r in kept] == ["nvd_ref"]
