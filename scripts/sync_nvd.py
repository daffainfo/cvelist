#!/usr/bin/env python3

import gzip
import json
import shutil
import sys
import tempfile
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
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "nvd-cvelist-sync/1.0"},
    )
    with urllib.request.urlopen(req, timeout=120) as response:
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


def sync_year(year: int) -> tuple[int, int]:
    url = f"{BASE_URL}/nvdcve-2.0-{year}.json.gz"

    with tempfile.TemporaryDirectory() as tmp:
        gz_path = Path(tmp) / f"nvdcve-2.0-{year}.json.gz"

        print(f"Downloading {url}")
        download(url, gz_path)

        feed = load_gzip_json(gz_path)
        vulnerabilities = feed.get("vulnerabilities", [])

        changed = 0
        total = 0

        for item in vulnerabilities:
            cve = item.get("cve")
            if not cve:
                continue

            cve_id = cve.get("id")
            if not cve_id:
                continue

            output_path = cve_path(cve_id)

            # Store the same per-entry object shape NVD uses:
            # { "cve": { ... } }
            if write_json_if_changed(output_path, item):
                changed += 1

            total += 1

        META_DIR.mkdir(parents=True, exist_ok=True)
        write_json_if_changed(
            META_DIR / f"{year}.json",
            {
                "year": year,
                "source": url,
                "format": feed.get("format"),
                "version": feed.get("version"),
                "timestamp": feed.get("timestamp"),
                "resultsPerPage": feed.get("resultsPerPage"),
                "totalResults": feed.get("totalResults"),
                "syncedAt": datetime.now(timezone.utc).isoformat(),
            },
        )

        return total, changed


def main() -> int:
    years = range(START_YEAR, CURRENT_YEAR + 1)

    grand_total = 0
    grand_changed = 0

    for year in years:
        try:
            total, changed = sync_year(year)
            grand_total += total
            grand_changed += changed
            print(f"{year}: {total} CVEs, {changed} changed")
        except Exception as exc:
            print(f"ERROR syncing {year}: {exc}", file=sys.stderr)
            return 1

    print(f"Done. {grand_total} CVEs processed, {grand_changed} files changed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())