"""Small, dependency-light helpers shared across the package."""

from __future__ import annotations

import json
import logging
import os
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

import yaml
from rich.logging import RichHandler

# --------------------------------------------------------------------------- #
# Project layout
# --------------------------------------------------------------------------- #
# src/socrepo/utils.py -> repo root is three parents up.
REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
DETECTIONS_DIR = REPO_ROOT / "detections" / "sigma"
CONFIG_DIR = REPO_ROOT / "config"
DOCS_DIR = REPO_ROOT / "docs"

_LOG_CONFIGURED = False


def get_logger(name: str = "socrepo") -> logging.Logger:
    """Return a Rich-formatted logger, configured once, level from env."""
    global _LOG_CONFIGURED
    if not _LOG_CONFIGURED:
        level = os.environ.get("SOCREPO_LOG_LEVEL", "INFO").upper()
        logging.basicConfig(
            level=level,
            format="%(message)s",
            datefmt="[%X]",
            handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
        )
        _LOG_CONFIGURED = True
    return logging.getLogger(name)


# --------------------------------------------------------------------------- #
# IO
# --------------------------------------------------------------------------- #
def read_yaml(path: str | Path) -> Any:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def read_yaml_all(path: str | Path) -> list[Any]:
    """Read a multi-document YAML file (Sigma rules can be multi-doc)."""
    with open(path, encoding="utf-8") as fh:
        return [d for d in yaml.safe_load_all(fh) if d is not None]


def write_yaml(path: str | Path, obj: Any) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        yaml.safe_dump(obj, fh, sort_keys=False, allow_unicode=True)


def read_jsonl(path: str | Path) -> Iterator[dict[str, Any]]:
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                yield json.loads(line)


def write_jsonl(path: str | Path, rows: Iterable[dict[str, Any]]) -> int:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(path, "w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row, default=str) + "\n")
            n += 1
    return n


def iter_sigma_files(directory: str | Path = DETECTIONS_DIR) -> Iterator[Path]:
    for p in sorted(Path(directory).glob("*.yml")):
        yield p
    for p in sorted(Path(directory).glob("*.yaml")):
        yield p
