import argparse
import json
import os

import requests
from jsonschema import validate
from mapex.write_parsed_mappings import (
    write_parsed_mappings_csv,
    write_parsed_mappings_navigator_layer,
    write_parsed_mappings_stix,
    write_parsed_mappings_yaml,
)

ROOT_DIR = os.path.abspath(os.curdir)
PARSED_MAPPINGS_DIR = f"{ROOT_DIR}/mappings"
MAPEX_DIR = f"{ROOT_DIR}/src/mapex"


def main():
    """Main entry point for `mapex` command line."""
    args = _parse_args()
    input_file = args.input_file
    if args.command == "export":
        output_file = args.output_file
        file_type = args.file_type
        if os.path.isfile(input_file):
            metadata_key = 0
            export_file(input_file, output_file, file_type, metadata_key)
        else:
            print("Input file must be a valid file")
    elif args.command == "validate":
        validate_file(input_file)


def _parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(help="commands", dest="command")

    export_parser = subparsers.add_parser("export")
    export_parser.add_argument("input_file")
    export_parser.add_argument("output_file")
    export_parser.add_argument(
        "--file-type", choices=["csv", "yaml", "navigator-layer", "stix"]
    )

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("input_file")

    args: argparse.Namespace = parser.parse_args()
    return args


def read_json_file(filepath):
    with open(filepath, encoding="UTF-8") as user_file:
        mappings = user_file.read()
        return json.loads(mappings)


def export_file(input_file, output_file, file_type, metadata_key):
    parsed_mappings = read_json_file(input_file)
    if file_type is None:
        write_parsed_mappings_yaml(parsed_mappings, output_file)
        write_parsed_mappings_csv(parsed_mappings, output_file, metadata_key)
        write_parsed_mappings_navigator_layer(parsed_mappings, output_file)
        write_parsed_mappings_stix(parsed_mappings, output_file)
    elif file_type == "yaml":
        write_parsed_mappings_yaml(parsed_mappings, output_file)
    elif file_type == "csv":
        write_parsed_mappings_csv(parsed_mappings, output_file, metadata_key)
    elif file_type == "navigator-layer":
        write_parsed_mappings_navigator_layer(parsed_mappings, output_file)
    elif file_type == "stix":
        write_parsed_mappings_stix(parsed_mappings, output_file)
    else:
        print("Please enter a correct filetype")


def validate_file(input_file):
    parsed_mappings = read_json_file(input_file)
    schema_filepath = f"{ROOT_DIR}/schema/mapex-unified-data-schema.json"
    schema = json.loads(open(schema_filepath, "r", encoding="UTF-8").read())
    validation_errors = validate(instance=parsed_mappings, schema=schema)
    if validation_errors is None:
        print("successfully validated")


def load_attack_json():
    BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"

    # load enterprise attack stix json to map technique ids to names
    enterpise_attack_url = f"{BASE_URL}/enterprise-attack/enterprise-attack-9.0.json"
    response = requests.get(enterpise_attack_url)
    enterprise_attack_data = json.loads(response.text)

    # load mobile attack stix json to map technique ids to names
    enterpise_attack_url = f"{BASE_URL}/mobile-attack/mobile-attack-9.0.json"
    response = requests.get(enterpise_attack_url)
    mobile_attack_data = json.loads(response.text)

    # load ics attack stix json to map technique ids to names
    enterpise_attack_url = f"{BASE_URL}/ics-attack/ics-attack-9.0.json"
    response = requests.get(enterpise_attack_url)
    ics_attack_data = json.loads(response.text)

    domains = ["enterprise", "mobile", "ics"]
    domain_data = [enterprise_attack_data, mobile_attack_data, ics_attack_data]

    attack_object_id_to_name = {}
    for idx, domain_data in enumerate(domain_data):
        domain = domains[idx]
        for attack_object in domain_data["objects"]:
            if not domain_data["type"] == "relationship":
                # skip objects without IDs
                if not attack_object.get("external_references"):
                    continue
                # skip deprecated and revoked objects
                # Note: False is the default value if the property is not present
                if attack_object.get("revoked", False):
                    continue
                # Note: False is the default value if the property is not present
                if attack_object.get("x_mitre_deprecated", False):
                    continue
                # map attackID to stixID
                if attack_object["external_references"][0].get(
                    "external_id"
                ) and attack_object.get("name"):
                    attack_object_id_to_name[
                        attack_object["external_references"][0]["external_id"]
                    ] = attack_object["target_ref"]

    return attack_object_id_to_name
