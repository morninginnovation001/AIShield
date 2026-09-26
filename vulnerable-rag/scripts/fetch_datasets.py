#!/usr/bin/env python3
"""
Fetch and normalize public prompt-injection datasets into JSONL under data/attack_payloads/.

Sources:
  - pint           : Lakera PINT (GitHub repo example dataset)
  - hf-qualifire   : qualifire/prompt-injections-benchmark (Hugging Face; gated)
  - hf-deepset     : deepset/prompt-injections (Hugging Face)
  - injecagent     : uiuc-kang-lab/InjecAgent attacker cases (GitHub)

Each JSONL line:
  {"id": str, "dataset": str, "split": str, "category": str|None, "text": str, "label": str|None}

Usage:
  source venv/bin/activate
  python scripts/fetch_datasets.py --source pint --output data/attack_payloads/pint.jsonl --limit 200
  python scripts/fetch_datasets.py --source hf-qualifire --output data/attack_payloads/qualifire.jsonl
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import requests
from datasets import load_dataset  # type: ignore
import yaml  # type: ignore


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def normalize_records(records: Iterable[Dict[str, Any]], dataset_name: str, split: str = "train",
                      limit: Optional[int] = None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for i, rec in enumerate(records):
        if limit is not None and i >= limit:
            break
        text = rec.get("prompt") or rec.get("text") or rec.get("instruction") or rec.get("content") or ""
        cat = rec.get("category") or rec.get("type") or rec.get("label") or None
        lbl = rec.get("label") if isinstance(rec.get("label"), str) else None
        out.append({
            "id": str(rec.get("id") or f"{dataset_name}-{split}-{i}"),
            "dataset": dataset_name,
            "split": split,
            "category": cat,
            "text": text,
            "label": lbl,
        })
    return out


def load_pint_repo(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    """Load PINT example dataset (structure reference) from repo YAML.

    Note: The full PINT benchmark dataset is not public; we use the example YAML
    to obtain a small, structured set for testing.
    """
    raw_url = "https://raw.githubusercontent.com/lakeraai/pint-benchmark/main/benchmark/data/example-dataset.yaml"
    r = requests.get(raw_url, timeout=30)
    r.raise_for_status()
    data = yaml.safe_load(r.text)
    if not isinstance(data, list):
        return []
    # Each entry typically has 'text', 'category', 'label'
    return normalize_records(data, dataset_name="pint-example", split="train", limit=limit)


def load_hf_dataset(ds_name: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
    ds = load_dataset(ds_name)
    records: List[Dict[str, Any]] = []
    for split in ds.keys():
        raw = ds[split]
        items = [raw[i] for i in range(len(raw))]
        records.extend(normalize_records(items, dataset_name=ds_name, split=split, limit=None))
    return records[: limit or len(records)]


def load_injecagent(limit: Optional[int] = None) -> List[Dict[str, Any]]:
    base = "https://raw.githubusercontent.com/uiuc-kang-lab/InjecAgent/main/data/"
    files = [
        ("attacker_cases_ds.jsonl", "injecagent-ds"),
        ("attacker_cases_dh.jsonl", "injecagent-dh"),
        ("user_cases.jsonl", "injecagent-user"),
    ]
    merged: List[Dict[str, Any]] = []
    for fname, tag in files:
        url = base + fname
        r = requests.get(url, timeout=30)
        if r.status_code != 200:
            continue
        for i, line in enumerate(r.text.splitlines()):
            try:
                obj = json.loads(line)
            except Exception:
                continue
            # Prefer Attacker Instruction; fallback to 'prompt' or any text-like field
            text = obj.get('Attacker Instruction') or obj.get('prompt') or obj.get('instruction') or obj.get('text')
            if not text:
                continue
            merged.append({
                'id': f'{tag}-{i}',
                'dataset': tag,
                'split': 'train',
                'category': obj.get('Attacker Tools') or None,
                'text': text,
                'label': None,
            })
    return merged[: limit or len(merged)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, choices=["pint", "hf-qualifire", "hf-deepset", "injecagent"], help="Dataset source")
    ap.add_argument("--output", required=True, help="Output JSONL path")
    ap.add_argument("--limit", type=int, default=None, help="Optional limit for quick runs")
    args = ap.parse_args()

    if args.source == "pint":
        records = load_pint_repo(limit=args.limit)
    elif args.source == "hf-qualifire":
        records = load_hf_dataset("qualifire/prompt-injections-benchmark", limit=args.limit)
    elif args.source == "hf-deepset":
        records = load_hf_dataset("deepset/prompt-injections", limit=args.limit)
    elif args.source == "injecagent":
        records = load_injecagent(limit=args.limit)
    else:
        raise ValueError("Unsupported source")

    out_path = Path(args.output)
    ensure_parent(out_path)
    with out_path.open("w", encoding="utf-8") as f:
        for rec in records:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"Wrote {len(records)} records to {out_path}")


if __name__ == "__main__":
    main()
