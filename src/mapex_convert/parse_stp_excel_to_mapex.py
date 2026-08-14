import argparse
import json
from pathlib import Path

import pandas as pd
import requests

ATTACK_STIX_URLS = [
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
]


COLUMN_MAPPING = {
    "EventID": "capability_id",
    "ATT&CK Data Component": "capability_description",
    "Field": "log_field",
    "ATT&CK Technique": "attack_object_id",
}


def load_attack_lookup(local_attack_json=None):
    if local_attack_json:
        with open(local_attack_json, "r", encoding="utf-8") as f:
            bundle = json.load(f)
    else:
        bundle = None
        last_error = None
        for url in ATTACK_STIX_URLS:
            try:
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                bundle = response.json()
                break
            except Exception as e:
                last_error = e
        if bundle is None:
            raise RuntimeError(f"Unable to download ATT&CK data: {last_error}")

    lookup = {}

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
            continue

        technique_name = obj.get("name")
        for ref in obj.get("external_references", []):
            source_name = ref.get("source_name", "")
            external_id = ref.get("external_id", "")
            if source_name in {
                "mitre-attack",
                "mitre-mobile-attack",
                "mitre-ics-attack",
            } and external_id.startswith("T"):
                lookup[external_id] = technique_name

    return lookup


def clean_value(value):
    if pd.isna(value):
        return None

    if isinstance(value, float) and value.is_integer():
        return int(value)

    return value


def build_records(df, log_source, attack_lookup):
    records = []

    filtered = df[
        df["Log Source"].astype(str).str.strip().str.lower() == log_source.lower()
    ]

    for _, row in filtered.iterrows():
        record = {}

        for source_col, target_key in COLUMN_MAPPING.items():
            if source_col in row.index:
                record[target_key] = clean_value(row[source_col])

        attack_id = record.get("attack_object_id")
        record["attack_object_description"] = attack_lookup.get(attack_id)

        records.append(record)

    return records


def write_json_file(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def main():
    parser = argparse.ArgumentParser(
        description="Convert Excel ATT&CK mapping sheet into sysmon.json and "
        "windows.json"
    )
    parser.add_argument("excel_file", help="Path to the Excel file")
    parser.add_argument(
        "--sheet-name", default=0, help="Excel sheet name or index to read"
    )
    parser.add_argument("--attack-json", help="Optional local ATT&CK STIX JSON file")
    parser.add_argument(
        "--out-dir", default=".", help="Output directory for JSON files"
    )
    args = parser.parse_args()

    df = pd.read_excel(args.excel_file, sheet_name=args.sheet_name)

    required_columns = [
        "Log Source",
        "EventID",
        "ATT&CK Data Component",
        "Field",
        "ATT&CK Technique",
    ]
    missing = [col for col in required_columns if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns: {missing}")

    attack_lookup = load_attack_lookup(args.attack_json)

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    sysmon_records = build_records(df, "sysmon", attack_lookup)
    windows_records = build_records(df, "windows", attack_lookup)

    write_json_file(out_dir / "sysmon.json", sysmon_records)
    write_json_file(out_dir / "windows.json", windows_records)

    print(f"Wrote {len(sysmon_records)} records to {out_dir / 'sysmon.json'}")
    print(f"Wrote {len(windows_records)} records to {out_dir / 'windows.json'}")


if __name__ == "__main__":
    main()
