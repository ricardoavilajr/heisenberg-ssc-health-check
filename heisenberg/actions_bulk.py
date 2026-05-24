# heisenberg/actions_bulk.py

import argparse
import csv
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

from .config import Settings
from .actions_parser import extract_actions_from_repo
from .actions_checker import assess_action

_settings = Settings()

DEFAULT_ORG = _settings.org
MAX_WORKERS = _settings.max_workers
SHARED_ACTIONS_REPO = _settings.shared_actions_repo

CSV_HEADER = [
    "repo",
    "workflow_file",
    "resolved_via",
    "full_action",
    "owner",
    "action_repo",
    "ref",
    "is_sha_pinned",
    "action_type",
    "stars",
    "forks",
    "archived",
    "disabled",
    "last_push",
    "action_description",
    "advisories",
    "repo_error",
]


def _process_repo(org: str, repo: str, token: str, shared_actions_repo: str) -> list[list]:
    print(f"[INFO] {repo}: fetching workflow files...")
    action_refs = extract_actions_from_repo(org, repo, token, shared_actions_repo=shared_actions_repo)
    print(f"[INFO] {repo}: found {len(action_refs)} action refs, fetching metadata...")

    seen = {}

    for i, ref in enumerate(action_refs, 1):
        assessed = assess_action(ref, token)
        key = (
            assessed.get("repo"),
            assessed.get("workflow_file"),
            assessed.get("full_action"),
            assessed.get("resolved_via"),
        )
        seen[key] = [assessed.get(col, "N/A") for col in CSV_HEADER]
        if i % 10 == 0:
            print(f"[INFO] {repo}: assessed {i}/{len(action_refs)} action refs...")
    
    return list(seen.values())

# Always include the shared actions repo so its own workflows are assessed too
def run_actions_bulk(
    org: str, repos: list[str], output_path: str, token: str,
    shared_actions_repo: str, targets: set[str] | None = None,
    fmt: str = "csv",
) -> None:
    full_action_idx = CSV_HEADER.index("full_action")

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        if fmt == "csv":
            writer = csv.writer(f)
            writer.writerow(CSV_HEADER)
        # NDJSON has no header row.

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(_process_repo, org, repo, token, shared_actions_repo): repo
                for repo in repos
            }
            for future in as_completed(futures):
                repo = futures[future]
                try:
                    rows = future.result()
                    if targets:
                        rows = [r for r in rows if str(r[full_action_idx]).lower() in targets]
                    for row in rows:
                        if fmt == "csv":
                            writer.writerow(row)
                        else:
                            f.write(json.dumps(
                                _row_to_dict(row), ensure_ascii=False,
                            ) + "\n")
                    print(f"[INFO] {repo}: {len(rows)} action references written")
                except Exception as e:
                    print(f"[ERROR] {repo}: {e}")


def _row_to_dict(row):
    """Map a list-shaped row to a CSV_HEADER-keyed dict for NDJSON output."""
    out = dict(zip(CSV_HEADER, row, strict=False))
    # Coerce known boolean / list-shaped fields when they're carried as
    # strings in the legacy row tuple.
    for key in ("is_sha_pinned", "archived", "disabled"):
        v = out.get(key)
        if isinstance(v, str):
            lv = v.strip().lower()
            if lv in ("true", "yes", "1"):
                out[key] = True
            elif lv in ("false", "no", "0", ""):
                out[key] = False
    adv = out.get("advisories")
    if isinstance(adv, str):
        out["advisories"] = [s.strip() for s in adv.split(",") if s.strip()] or None
    return out

# Needed for investigations during analyze stage
def _load_targets(args) -> set[str] | None:
    targets = set()
    if getattr(args, "pkg", None):
        targets.update(x.strip().lower() for x in args.pkg.split(",") if x.strip())
    if getattr(args, "file", None):
        with open(args.file, "r", encoding="utf-8") as f:
            targets.update(line.strip().lower() for line in f if line.strip() and not line.startswith("#"))
    return targets if targets else None

def add_arguments(parser: argparse.ArgumentParser) -> None:
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("-r", "--repos", help="Comma-separated repo list, e.g. repo1,repo2")
    g.add_argument("-a", "--all", action="store_true", help="Use repos from --repos-file")
    parser.add_argument("--org", default=DEFAULT_ORG, help="GitHub org name")
    parser.add_argument("--repos-file", default="repos.txt", help="Path to repos.txt (used with -a)")
    parser.add_argument("-o", "--output", default="actions_results.csv", help="Output path")
    parser.add_argument(
        "--format", choices=("csv", "ndjson"), default="csv",
        help="Output format. csv = legacy default; ndjson = one JSON object per line.",
    )
    # filter during investigation stage for actions
    filter_group = parser.add_mutually_exclusive_group()
    filter_group.add_argument("-pkg", "--pkg", help="Comma-separated action names to match, e.g. tj-actions/changed-files")
    filter_group.add_argument("-file", "--file", help="Text file of action names to match (one per line)")


def cli(args=None) -> None:
    if args is None:
        p = argparse.ArgumentParser(description="Check GitHub Actions supply chain health")
        add_arguments(p)
        args = p.parse_args()

    token = os.getenv("GITHUB_TOKEN")
    if not token:
        print("[ERROR] GITHUB_TOKEN env var not set")
        return

    if not args.org:
        print("[ERROR] No org specified. Set GITHUB_ORG or pass --org.")
        return

    if args.all:
        with open(args.repos_file) as f:
            repos = [line.strip() for line in f if line.strip()]
    else:
        repos = [r.strip() for r in args.repos.split(",") if r.strip()]

    if not repos:
        print("[ERROR] No repos provided.")
        return

    targets = _load_targets(args)
    if targets:                                                                                                          
        print(f"[INFO] Filtering output to {len(targets)} target action(s)")                                             
    fmt = getattr(args, "format", "csv")
    run_actions_bulk(
        args.org, repos, args.output, token, SHARED_ACTIONS_REPO,
        targets=targets, fmt=fmt,
    )
    print(f"[INFO] Done. Results ({fmt}) saved to {args.output}")


if __name__ == "__main__":
    cli()