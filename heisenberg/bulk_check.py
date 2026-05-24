# heisenberg/bulk_check.py

import csv
import json
import os
import subprocess
import sys

from concurrent.futures import ThreadPoolExecutor, as_completed
import time

import argparse

from .config import Settings

from .sbom_utils import (
    write_repos_file, load_repos_from_file,
    run_github_sbom_script, iter_selected_sboms,
    cleanup_sbom_dir
)


DEPS_MODULE = "heisenberg.heisenberg_depsdev" 

_settings = Settings()  

DEFAULT_ORG = _settings.org
SBOM_DIR = _settings.sbom_dir        
OUTPUT_CSV = _settings.output_csv    
TIMEOUT = _settings.timeout 

REPOS_FILE_NAME = _settings.repos_file_name  

MAX_WORKERS = _settings.max_workers  
PAUSE_EVERY = _settings.pause_every  
PAUSE = _settings.pause   

LABEL_MAP = {
    "Package Health Score": "health_score",
    "Description": "description",
    "Popularity (Stars)": "popularity_info_stars",
    "Popularity (Forks)": "popularity_info_forks",
    "Maintained Score": "maintenance_info",
    "Dependents": "dependents",
    "Security Advisory Count": "security_info",
    "Security Advisory IDs": "security_advisories",
    "Security Score (Vulnerabilities)": "security_score",
    "Deprecated": "deprecated",
    "Custom Health Score": "custom_health_score",
    # Cross-check URLs
    "deps.dev": "deps_url",
    "Snyk": "snyk_url",
    "Socket.dev": "socket_url",
}

def parse_output(stdout):
    data = {
       "health_score": "N/A",
       "description": "N/A",
       "popularity_info_stars": "N/A",
       "popularity_info_forks": "N/A",
      "maintenance_info": "N/A",
       "dependents": "N/A",
       "security_info": "N/A",
       "security_advisories": "N/A",
       "security_score": "N/A",
       "deprecated": "N/A",
       "custom_health_score": "N/A",
       "deps_url": "N/A",
       "snyk_url": "N/A",
       "socket_url": "N/A",
    }
    
    for line in stdout.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        field = LABEL_MAP.get(key)
        if field:
            data[field] = value or data[field]
    return data



def run_check(package_manager, package, version):
    try:
        
        cmd = [
            sys.executable, "-m",  
            "heisenberg.heisenberg_depsdev",  
            "main_package",
            "-mgmt", package_manager,
            "-pkg", package,
            "-v", version
        ]
        print(f"Running: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=TIMEOUT
        )

        print("STDOUT:", result.stdout)
        print("STDERR:", result.stderr)

        parsed = parse_output(result.stdout)

        return parsed

    except subprocess.TimeoutExpired:
        return {k: "Timeout" for k in [
            "health_score", "description", "popularity_info_stars", "popularity_info_forks",
            "maintenance_info", "dependents", "security_info", "security_advisories",
            "security_score", "custom_health_score", "deprecated"
        ]}
    except Exception as e:
        return {k: f"Error: {e}" for k in [
            "health_score", "description", "popularity_info_stars", "popularity_info_forks",
            "maintenance_info", "dependents", "security_info", "security_advisories",
            "security_score", "custom_health_score", "deprecated"
        ]}
    

CSV_HEADER = [
    "repo_name", "package", "version", "language", "license", "health_score", "custom_health_score", "description",
    "popularity_info_stars", "popularity_info_forks", "maintenance_info", "dependents",
    "security_info", "security_advisories", "security_score", "deprecated",
    "deps_url", "snyk_url", "socket_url"
]


# ---------------------------------------------------------------------------
# Output abstraction — CSV (default, back-compat) and NDJSON (richer types)
# ---------------------------------------------------------------------------


class CsvEmitter:
    """Wraps csv.writer to expose the same write_row(dict) interface as
    NdjsonEmitter so callers don't branch."""

    def __init__(self, fh):
        self._writer = csv.writer(fh)
        self._writer.writerow(CSV_HEADER)

    def write_row(self, row_dict):
        self._writer.writerow([row_dict.get(col, "") for col in CSV_HEADER])


class NdjsonEmitter:
    """One JSON object per line. Consumers stream-parse without loading
    the whole file. Carries richer types than CSV: security_advisories
    becomes a list, numeric scores become floats/ints where possible."""

    def __init__(self, fh):
        self._fh = fh

    def write_row(self, row_dict):
        normalized = _normalize_for_json(row_dict)
        self._fh.write(json.dumps(normalized, ensure_ascii=False) + "\n")


def _normalize_for_json(row):
    """Coerce N/A strings to nulls and parse known typed fields."""
    out = {}
    for k, v in row.items():
        if v == "N/A" or v is None or v == "":
            out[k] = None
            continue
        # Numeric coercion for the score-shaped fields
        if k in (
            "health_score", "custom_health_score", "security_score",
            "maintenance_info",
        ):
            try:
                out[k] = float(v)
                continue
            except (TypeError, ValueError):
                pass
        # Integer coercion for count-shaped fields
        if k in ("popularity_info_stars", "popularity_info_forks",
                 "security_info", "dependents"):
            try:
                out[k] = int(v)
                continue
            except (TypeError, ValueError):
                pass
        # security_advisories is a comma-separated string in CSV;
        # in NDJSON it becomes an array.
        if k == "security_advisories":
            ids = [s.strip() for s in str(v).split(",") if s.strip()]
            out[k] = ids if ids else None
            continue
        out[k] = v
    return out


def make_emitter(fh, fmt):
    """Factory: 'csv' or 'ndjson'. Defaults to CSV for back-compat."""
    if fmt == "ndjson":
        return NdjsonEmitter(fh)
    return CsvEmitter(fh)


def build_row(repo_name, name, version, package_manager, license_info="N/A"):
    """Build a row as a dict keyed by CSV_HEADER columns. Replaces the
    older build_csv_row that returned a list."""
    result = run_check(package_manager, name, version)
    return {
        "repo_name": repo_name,
        "package": name,
        "version": version,
        "language": package_manager,
        "license": license_info,
        "health_score": result.get("health_score", "N/A"),
        "custom_health_score": result.get("custom_health_score", "N/A"),
        "description": result.get("description", "N/A"),
        "popularity_info_stars": result.get("popularity_info_stars", "N/A"),
        "popularity_info_forks": result.get("popularity_info_forks", "N/A"),
        "maintenance_info": result.get("maintenance_info", "N/A"),
        "dependents": result.get("dependents", "N/A"),
        "security_info": result.get("security_info", "N/A"),
        "security_advisories": result.get("security_advisories", "N/A"),
        "security_score": result.get("security_score", "N/A"),
        "deprecated": result.get("deprecated", "N/A"),
        "deps_url": result.get("deps_url", "N/A"),
        "snyk_url": result.get("snyk_url", "N/A"),
        "socket_url": result.get("socket_url", "N/A"),
    }


# Back-compat alias for any external callers still importing the
# list-shaped row builder.
def build_csv_row(repo_name, name, version, package_manager, license_info="N/A"):
    row_dict = build_row(repo_name, name, version, package_manager, license_info)
    return [row_dict.get(col, "") for col in CSV_HEADER]


def _error_row(repo_name, name, version, package_manager):
    return {
        "repo_name": repo_name,
        "package": name,
        "version": version,
        "language": package_manager,
        "license": "N/A",
        **{col: "Error" for col in CSV_HEADER if col not in (
            "repo_name", "package", "version", "language", "license",
        )},
    }


def process_tasks(tasks, emitter):
    """Run health-checks for each task; write each result row to `emitter`.

    `emitter` may be a CsvEmitter, NdjsonEmitter, or anything else that
    exposes a `.write_row(dict)` method. For backward compat, also
    accepts a raw csv.writer object (gets wrapped on the fly).
    """
    # Back-compat: callers passing a raw csv.writer (the old API) get
    # an inline shim. New callers pass a CsvEmitter / NdjsonEmitter.
    if not hasattr(emitter, "write_row") or _looks_like_csv_writer(emitter):
        emitter = _CsvWriterAdapter(emitter)

    launch_count = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_pkg = {}
        for repo_name, name, version, package_manager, license_info in tasks:
            future = executor.submit(build_row, repo_name, name, version, package_manager, license_info)
            future_to_pkg[future] = (repo_name, name, version, package_manager)

            launch_count += 1
            if launch_count % PAUSE_EVERY == 0:
                time.sleep(PAUSE)

        for future in as_completed(future_to_pkg):
            repo_name, name, version, package_manager = future_to_pkg[future]
            try:
                row_out = future.result()
            except Exception as e:
                print(f"[ERROR] Failed {name} {version} ({package_manager}): {e}")
                row_out = _error_row(repo_name, name, version, package_manager)
            emitter.write_row(row_out)


def _looks_like_csv_writer(obj):
    """Heuristic for the legacy csv.writer-passed-as-emitter case."""
    return hasattr(obj, "writerow") and not hasattr(obj, "_fh")


class _CsvWriterAdapter:
    """Wrap a raw csv.writer into the emitter interface for back-compat."""

    def __init__(self, csv_writer):
        self._w = csv_writer

    def write_row(self, row_dict):
        self._w.writerow([row_dict.get(col, "") for col in CSV_HEADER])

def process_sbom_file(input_file, repo_name, writer): 
    tasks = []
    with open(input_file, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            name = row.get("package", "").strip()
            version = row.get("version", "").strip()
            package_manager = row.get("language", "").strip().lower()
            license_info = row.get("license", "N/A").strip()

            if package_manager == "golang":
                package_manager = "go"

            if not name or not version or not package_manager:
                print(f"Skipping incomplete row: {row}")
                continue

            print(f"Queueing: {name} {version} ({package_manager})")
            tasks.append((repo_name, name, version, package_manager, license_info))

    process_tasks(tasks, writer)

def add_arguments(parser):
    g = parser.add_mutually_exclusive_group(required=True)
    g.add_argument("-a", "--all", action="store_true", help="Use repos from repos.txt")
    g.add_argument("-r", "--repos", help="Comma-separated repo list, e.g. repo1,repo2")
    parser.add_argument("--org", default=DEFAULT_ORG, help="GitHub org name (passed to github_sbom)")
    parser.add_argument("--repos-file", default="repos.txt", help="Path to repos.txt (used with -a)")
    parser.add_argument("--sbom-dir", default=SBOM_DIR, help="SBOM directory")
    parser.add_argument("-o", "--output", "--out", dest="output", default=OUTPUT_CSV, help="Output path")
    parser.add_argument(
        "--format", choices=("csv", "ndjson"), default="csv",
        help="Output format. csv = legacy default; ndjson = one JSON object per line.",
    )

def parse_cli():  
    p = argparse.ArgumentParser(description="Run bulk health checks from SBOMs.")
    add_arguments(p)  
    return p.parse_args()

def run_bulk(sbom_dir, selected_repos, output_path, fmt="csv"):
    with open(output_path, "w", newline="", encoding="utf-8") as out:
        emitter = make_emitter(out, fmt)
        for repo_name, input_file in iter_selected_sboms(sbom_dir, selected_repos):
            print(f"[INFO] Processing {input_file} (repo: {repo_name})")
            process_sbom_file(input_file, repo_name, emitter)


def run_bulk_for_repos(repos, sbom_dir=None, output_csv=None, org=DEFAULT_ORG, fmt="csv"):
    sbom_dir = sbom_dir or SBOM_DIR
    output_csv = output_csv or OUTPUT_CSV
    write_repos_file(sbom_dir, repos, REPOS_FILE_NAME)
    if not run_github_sbom_script(sbom_dir, org, REPOS_FILE_NAME):
        print("[WARN] SBOM generation failed; aborting.")
        return
    run_bulk(sbom_dir, repos, output_csv, fmt=fmt)


def main(args=None):
    if args is None:                       
        args = parse_cli() 
           
    if args.all:
        selected_repos = load_repos_from_file(args.repos_file)
    else:
        selected_repos = [r.strip() for r in args.repos.split(",") if r.strip()]

    if not selected_repos:
        print("[ERROR] No repositories selected.")
        return

    write_repos_file(args.sbom_dir, selected_repos, REPOS_FILE_NAME)
    
    if not run_github_sbom_script(args.sbom_dir, args.org, REPOS_FILE_NAME): 
        print("[WARN] SBOM generation failed; aborting.")
        cleanup_sbom_dir(args.sbom_dir)
        return

    try:
        fmt = getattr(args, "format", "csv")
        run_bulk(args.sbom_dir, selected_repos, args.output, fmt=fmt)
        print(f"[INFO] Done. Results ({fmt}) saved to {args.output}")
    finally:
        cleanup_sbom_dir(args.sbom_dir)

def cli(args=None):
    return main(args)

if __name__ == "__main__":
    main()
