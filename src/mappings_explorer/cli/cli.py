import argparse
import csv
import json
import os

import pandas as pd
import requests
import yaml

from mappings_explorer.cli.parse_cve_mappings import configure_cve_mappings
from mappings_explorer.cli.parse_nist_mappings import configure_nist_mappings
from mappings_explorer.cli.parse_security_stack_mappings import (
    configure_security_stack_mappings,
)
from mappings_explorer.cli.parse_veris_mappings import configure_veris_mappings

ROOT_DIR = os.path.abspath(os.curdir)


def main():
    """Main entry point for `mapex` command line."""
    args = _parse_args()
    if args.mappings == "cve":
        parse_cve_mappings()
    elif args.mappings == "nist":
        parse_nist_mappings()
    elif args.mappings == "veris":
        parse_veris_mappings()
    elif args.mappings == "security-stack":
        parse_security_stack_mappings()


def _parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mappings",
        type=str,
        required=True,
        help="""Set of mappings to parse
                        Options: cve, nist, veris, security-stack
                        """,
    )
    args: argparse.Namespace = parser.parse_args()
    return args


def load_attack_json():
    BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"

    # load enterprise attack stix json to map technique ids to names
    enterpise_attack_url = f"{BASE_URL}/enterprise-attack/enterprise-attack-9.0.json"
    response = requests.get(enterpise_attack_url)
    enterprise_attack_data = json.loads(response.text)

    # load mobile attack stix json to map technique ids to names
    enterpise_attack_url = f"{BASE_URL}/mobile-attack/mobile-attack-9.0.json"
    response = requests.get(enterpise_attack_url, verify=False)
    mobile_attack_data = json.loads(response.text)

    # load ics attack stix json to map technique ids to names
    enterpise_attack_url = f"{BASE_URL}/ics-attack/ics-attack-9.0.json"
    response = requests.get(enterpise_attack_url, verify=False)
    ics_attack_data = json.loads(response.text)

    attack_object_id_to_name = {}
    for domain_data in [enterprise_attack_data, mobile_attack_data, ics_attack_data]:
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
                    ] = attack_object["name"]

    return attack_object_id_to_name


def parse_cve_mappings():
    attack_object_id_to_name = load_attack_json()
    cve_filepath = f"{ROOT_DIR}/mappings/Att&ckToCveMappings.csv"
    datareader = read_csv_file(cve_filepath)
    parsed_mappings = configure_cve_mappings(datareader, attack_object_id_to_name)
    print(yaml.dump(parsed_mappings))


def read_csv_file(filepath):
    cve_mappings = open(filepath, "r", encoding="UTF-8")
    datareader = csv.reader(cve_mappings, delimiter=",", quotechar='"')
    return datareader


def parse_nist_mappings():
    # read in tsv files
    directory = f"{ROOT_DIR}/mappings/NIST_800-53"

    parsed_mappings = []
    # iterate through all nist mapping files in the directory
    for filename in os.listdir(directory):
        file = os.path.join(directory, filename)

        # checking if it is a file
        if os.path.isfile(file):
            dataframe = read_excel_file(file)
            attack_version = filename[
                filename.rfind("-") + 1 : filename.index("mappings")
            ].replace("_", ".")
            mappings_version = filename[filename.index("r") : filename.index("r") + 2]
            parsed_mappings = configure_nist_mappings(
                dataframe, parsed_mappings, attack_version, mappings_version
            )

    print(yaml.dump(parsed_mappings))


def read_excel_file(filepath):
    df = pd.read_excel(filepath)
    return df


def parse_veris_mappings():
    directory = f"{ROOT_DIR}/mappings/Veris"
    parsed_mappings = []
    for filename in os.listdir(directory):
        file = os.path.join(directory, filename)
        # checking if it is a file
        if os.path.isfile(file):
            veris_mappings = read_json_file(file)
            parsed_mappings = configure_veris_mappings(veris_mappings, parsed_mappings)
    print(yaml.dump(parsed_mappings))


def read_json_file(filepath):
    with open(filepath, encoding="UTF-8") as user_file:
        veris_mappings = user_file.read()
        return json.loads(veris_mappings)


def parse_security_stack_mappings():
    rootdir = f"{ROOT_DIR}/mappings/SecurityStack"

    # read in all files in SecurityStack directory
    for subdir, _, files in os.walk(rootdir):
        parsed_mappings = []
        for file in files:
            filepath = os.path.join(subdir, file)
            data = read_yaml(filepath)
            parsed_mappings = configure_security_stack_mappings(data, parsed_mappings)

    print(yaml.dump(parsed_mappings))


def read_yaml(filepath):
    with open(filepath, encoding="UTF-8") as file:
        return yaml.safe_load(file)
