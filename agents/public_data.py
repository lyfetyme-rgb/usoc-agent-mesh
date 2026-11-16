"""Isolated, read-only analysis of Washington's public breach notifications.

The two Socrata tables are related views, not independent threat sources.
This module does not instantiate the mesh, policy engine, or action runtime.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

BASE = "https://data.wa.gov/resource/"
TABLES = {"notifications": "sb4j-ca4h", "information_types": "padd-mby7"}
MAX_BYTES = 4_000_000
MAX_DETAIL_ROWS = 5000


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_rows(table: str, params: dict[str, str | int]) -> list[dict]:
    if table not in TABLES:
        raise ValueError("unknown public dataset")
    url = BASE + TABLES[table] + ".json?" + urlencode(params)
    request = Request(url, headers={"Accept": "application/json", "User-Agent": "usoc-public-data-test/1.0"})
    with build_opener(NoRedirect).open(request, timeout=20) as response:
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("dataset response exceeded size limit")
    rows = json.loads(data)
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("unexpected dataset response")
    return rows


def analyze(notifications: list[dict], details: list[dict], *, requested: int) -> dict:
    """Join by publisher ID; preserve multiple information types per notice."""
    by_id: dict[str, dict] = {}
    for row in notifications:
        identifier = str(row.get("id", ""))
        if not re.fullmatch(r"\d+", identifier):
            raise ValueError("notification has missing or invalid ID")
        if identifier in by_id:
            raise ValueError("duplicate notification ID")
        by_id[identifier] = row
    types: dict[str, set[str]] = {key: set() for key in by_id}
    unmatched_detail_rows = 0
    for row in details:
        identifier = str(row.get("id", ""))
        if identifier not in types:
            unmatched_detail_rows += 1
            continue
        value = row.get("informationtype")
        if isinstance(value, str) and value.strip():
            types[identifier].add(value.strip())
    joined = []
    for identifier, row in by_id.items():
        joined.append({
            "notification_id": identifier,
            "organization": row.get("name"),
            "submitted": row.get("datesubmitted"),
            "cause": row.get("databreachcause"),
            "attack_type": row.get("cyberattacktype"),
            "affected_range": row.get("washingtoniansaffectedrange"),
            "information_types": sorted(types[identifier]),
        })
    cause_counts = Counter(str(row.get("databreachcause") or "Unknown") for row in by_id.values())
    type_counts = Counter(kind for values in types.values() for kind in values)
    return {
        "mode": "historical_read_only",
        "source_relationship": "Two related tables from the same publisher; not independent corroboration.",
        "match_method": "Exact publisher notification ID",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "requested_notifications": requested,
        "notification_count": len(by_id),
        "detail_rows": len(details),
        "notifications_with_details": sum(bool(value) for value in types.values()),
        "notifications_without_details": sum(not value for value in types.values()),
        "unmatched_detail_rows": unmatched_detail_rows,
        "sample_limited": len(notifications) >= requested,
        "detail_limit_reached": len(details) >= MAX_DETAIL_ROWS,
        "causes": dict(sorted(cause_counts.items())),
        "information_type_counts": dict(sorted(type_counts.items())),
        "records": joined,
    }


def run(limit: int) -> dict:
    if not 1 <= limit <= 100:
        raise ValueError("limit must be between 1 and 100")
    notifications = fetch_rows("notifications", {
        "$select": "id,name,datesubmitted,databreachcause,cyberattacktype,washingtoniansaffectedrange",
        "$order": "datesubmitted DESC,id DESC",
        "$limit": limit,
    })
    identifiers = [str(row.get("id", "")) for row in notifications]
    if any(not re.fullmatch(r"\d+", identifier) for identifier in identifiers):
        raise ValueError("notification has missing or invalid ID")
    details = []
    if identifiers:
        where = "id in (" + ",".join("'" + identifier + "'" for identifier in identifiers) + ")"
        details = fetch_rows("information_types", {
            "$select": "id,informationtype",
            "$where": where,
            "$order": "id,informationtype",
            "$limit": MAX_DETAIL_ROWS,
        })
    return analyze(notifications, details, requested=limit)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--limit", type=int, default=100, help="recent notifications (1–100)")
    parser.add_argument("--examples", type=int, default=5, help="number of joined examples to display")
    args = parser.parse_args()
    if not 0 <= args.examples <= 100:
        parser.error("--examples must be between 0 and 100")
    try:
        result = run(args.limit)
    except (OSError, ValueError) as exc:
        print(f"Public data analysis failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    result["records"] = result["records"][:args.examples]
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
