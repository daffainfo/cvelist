#!/usr/bin/env python3

import argparse
import gzip
import json
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"
START_YEAR = 2002
CURRENT_YEAR = datetime.now(timezone.utc).year

ROOT = Path(__file__).resolve().parents[1]
CVES_DIR = ROOT / "cves"
META_DIR = ROOT / ".sync-meta"


def cve_path(cve_id: str) -> Path:
    # CVE-2019-3494 -> cves/2019/3xxx/CVE-2019-3494.json
    _, year, number = cve_id.split("-")
    bucket = f"{number[:-3]}xxx" if len(number) > 3 else "0xxx"
    return CVES_DIR / year / bucket / f"{cve_id}.json"


def download(url: str, dest: Path) -> None:
    print(f"Downloading {url}", flush=True)

    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "nvd-cvelist-sync/1.0",
            "Accept": "application/gzip, application/octet-stream, */*",
        },
    )

    with urllib.request.urlopen(req, timeout=180) as response:
        with dest.open("wb") as f:
            shutil.copyfileobj(response, f)


def load_gzip_json(path: Path) -> dict:
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return json.load(f)


def write_json_if_changed(path: Path, data: dict) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)

    new_content = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"

    if path.exists() and path.read_text(encoding="utf-8") == new_content:
        return False

    path.write_text(new_content, encoding="utf-8")
    return True


def process_feed(feed: dict, source_url: str) -> tuple[int, int]:
    vulnerabilities = feed.get("vulnerabilities", [])

    total = 0
    changed = 0

    for item in vulnerabilities:
        cve = item.get("cve")
        if not cve:
            continue

        cve_id = cve.get("id")
        if not cve_id:
            continue

        output_path = cve_path(cve_id)

        if write_json_if_changed(output_path, item):
            changed += 1

        total += 1

    META_DIR.mkdir(parents=True, exist_ok=True)

    feed_name = source_url.rsplit("/", 1)[-1].replace(".json.gz", "")
    write_json_if_changed(
        META_DIR / f"{feed_name}.json",
        {
            "source": source_url,
            "format": feed.get("format"),
            "version": feed.get("version"),
            "timestamp": feed.get("timestamp"),
            "resultsPerPage": feed.get("resultsPerPage"),
            "totalResults": feed.get("totalResults"),
            "syncedAt": datetime.now(timezone.utc).isoformat(),
        },
    )

    return total, changed


def sync_url(url: str, max_attempts: int = 5) -> tuple[int, int]:
    last_error: Exception | None = None

    for attempt in range(1, max_attempts + 1):
        try:
            with tempfile.TemporaryDirectory() as tmp:
                gz_path = Path(tmp) / url.rsplit("/", 1)[-1]

                print(f"Attempt {attempt}/{max_attempts}", flush=True)
                download(url, gz_path)

                size = gz_path.stat().st_size
                print(f"Downloaded {size} bytes", flush=True)

                if size == 0:
                    raise RuntimeError("Downloaded file is empty")

                feed = load_gzip_json(gz_path)
                return process_feed(feed, url)

        except (
            EOFError,
            OSError,
            TimeoutError,
            urllib.error.URLError,
            urllib.error.HTTPError,
            json.JSONDecodeError,
            RuntimeError,
        ) as exc:
            last_error = exc
            print(f"Download/read failed: {exc}", flush=True)

            if attempt < max_attempts:
                sleep_seconds = attempt * 10
                print(f"Retrying in {sleep_seconds}s...", flush=True)
                time.sleep(sleep_seconds)

    raise RuntimeError(f"Failed after {max_attempts} attempts: {url}") from last_error


def sync_full() -> None:
    grand_total = 0
    grand_changed = 0

    years = list(range(START_YEAR, CURRENT_YEAR + 1))
    years.reverse()  # start from newest

    for year in years:
        url = f"{BASE_URL}/nvdcve-2.0-{year}.json.gz"

        total, changed = sync_url(url)

        grand_total += total
        grand_changed += changed

        print(f"{year}: {total} CVEs, {changed} changed", flush=True)

    print(
        f"Full sync done: {grand_total} CVEs processed, {grand_changed} changed",
        flush=True,
    )


def sync_modified() -> None:
    url = f"{BASE_URL}/nvdcve-2.0-modified.json.gz"

    total, changed = sync_url(url)

    print(
        f"Modified sync done: {total} CVEs processed, {changed} changed",
        flush=True,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=["full", "modified"],
        required=True,
        help="full = yearly feeds from 2002-current year; modified = NVD modified feed only",
    )

    args = parser.parse_args()

    if args.mode == "full":
        sync_full()
    elif args.mode == "modified":
        sync_modified()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())