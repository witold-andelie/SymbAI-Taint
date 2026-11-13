#!/usr/bin/env python3
"""Apply an explicitly reviewed raw-prediction/use-site mapping; never guess by name."""

import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.dont_write_bytecode = True
from src.selective_analysis.contracts import Query, file_hash
from src.selective_analysis.workspace import configure_workspace


def map_candidates(raw, queries, mapping):
    if raw.get("schema") != "symbai.tygr_raw.v1" or raw.get("provenance", {}).get("source") != "tygr_glowgnn":
        raise ValueError("Expected genuine raw TYGR artifact")
    predictions = {r["prediction_id"]: r for r in raw["records"]}
    if len(predictions) != len(raw["records"]):
        raise ValueError("Duplicate raw prediction identity")
    by_site = {q.use_site_id: q for q in queries}
    records, seen = [], set()
    for link in mapping["mappings"]:
        site = link["use_site_id"]
        if site in seen or not link.get("reviewed_by") or not link.get("evidence"):
            raise ValueError("Mapping must be unique and include an explicit review/evidence reference")
        query = by_site[site]
        if query.binary_sha256 != raw["binary_sha256"]:
            raise ValueError("Cross-binary/debug-stripped mappings require a separate equivalence check")
        prediction = predictions[link["prediction_id"]]
        expected = link.get("expected_identity")
        if expected is not None:
            fields = ("low_pc", "high_pc", "location_class", "location_register", "location_argument")
            actual_locations = [{key: location.get(key) for key in fields} for location in prediction.get("locations", [])]
            expected_locations = [{key: location.get(key) for key in fields} for location in expected["locations"]]
            if prediction.get("function_address") != expected["function_address"] or actual_locations != expected_locations:
                raise ValueError("Fresh prediction differs from the reviewed function/location identity")
        records.append({**prediction, "use_site_id": site, "binary_sha256": query.binary_sha256,
                        "mapping_status": "reviewed", "mapping_review": dict(link)})
        seen.add(site)
    if not records:
        raise ValueError("Mapping contains no reviewed sites")
    return {"schema": "symbai.mapped_types.v1", "provenance": raw["provenance"], "records": records}


def main():
    configure_workspace()
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("raw", "manifest", "mapping", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    raw = json.loads(args.raw.read_text(encoding="utf-8"))
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    queries = [Query.from_dict(q, args.manifest.parent) for q in manifest["queries"]]
    result = map_candidates(raw, queries, json.loads(args.mapping.read_text(encoding="utf-8")))
    result["raw_artifact_sha256"] = file_hash(args.raw)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(f"Mapped {len(result['records'])} reviewed use sites")


if __name__ == "__main__":
    main()
