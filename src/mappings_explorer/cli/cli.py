import argparse
import json
import os

import requests

from mappings_explorer.cli.parse_cve_mappings import configure_cve_mappings
from mappings_explorer.cli.parse_nist_mappings import configure_nist_mappings
from mappings_explorer.cli.parse_security_stack_mappings import (
    configure_security_stack_mappings,
)
from mappings_explorer.cli.parse_veris_mappings import configure_veris_mappings
from mappings_explorer.cli.read_files import (
    read_csv_file,
    read_excel_file,
    read_json_file,
    read_yaml_file,
)
from mappings_explorer.cli.write_parsed_mappings import (
    write_parsed_mappings_csv,
    write_parsed_mappings_json,
    write_parsed_mappings_yaml,
)

ROOT_DIR = os.path.abspath(os.curdir)
PARSED_MAPPINGS_DIR = f"{ROOT_DIR}/src/mappings_explorer/cli/parsed_mappings/"


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
                    ] = {"name": attack_object["name"], "domain": domain}

    return attack_object_id_to_name


def parse_cve_mappings():
    attack_object_id_to_name = load_attack_json()
    cve_filepath = f"{ROOT_DIR}/mappings/Att&ckToCveMappings.csv"
    datareader = read_csv_file(cve_filepath)
    parsed_mappings = configure_cve_mappings(datareader, attack_object_id_to_name)

    filepath = f"{PARSED_MAPPINGS_DIR}cve/parsed_cve_mappings"

    # write parsed mappings to yaml file
    write_parsed_mappings_yaml(parsed_mappings, filepath)

    # write parsed mappings to json file
    write_parsed_mappings_json(parsed_mappings, filepath)

    # write parsed mappings to csv file
    write_parsed_mappings_csv(parsed_mappings, filepath)


def parse_nist_mappings():
    # read in tsv files
    directory = f"{ROOT_DIR}/mappings/NIST_800-53"

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
                dataframe, attack_version, mappings_version
            )

            # set up directories
            mapped_filename = f"parsed_{filename[0: filename.index('.')]}"
            attack_version_path = f"{PARSED_MAPPINGS_DIR}nist/{attack_version}/"
            attack_version_path_exists = os.path.exists(attack_version_path)
            if not attack_version_path_exists:
                os.makedirs(attack_version_path)
            nist_dir = f"nist/{attack_version}/{mappings_version}/"
            mappings_version_path = f"{PARSED_MAPPINGS_DIR}{nist_dir}"
            mappings_version_path_exists = os.path.exists(mappings_version_path)
            if not mappings_version_path_exists:
                os.makedirs(mappings_version_path)

            filepath = f"{mappings_version_path}/{mapped_filename}"

            # write parsed mappings to yaml file
            write_parsed_mappings_yaml(parsed_mappings, filepath)

            # write parsed mappings to json file
            write_parsed_mappings_json(parsed_mappings, filepath)

            # write parsed mappings to csv file
            write_parsed_mappings_csv(parsed_mappings, filepath)


def parse_veris_mappings():
    directory = f"{ROOT_DIR}/mappings/Veris"
    for filename in os.listdir(directory):
        file = os.path.join(directory, filename)
        # checking if it is a file
        if os.path.isfile(file):
            veris_mappings = read_json_file(file)

            veris_version = "1.3.7" if "1_3_7" in filename else "1.3.5"
            domain = (
                "enterprise"
                if veris_version == "1.3.5"
                else filename[filename.rindex("-") + 1 : filename.index(".")]
            )

            parsed_mappings = configure_veris_mappings(veris_mappings, domain)
            filename = filename[0 : filename.index(".")]
            filepath = f"{PARSED_MAPPINGS_DIR}veris/{veris_version}/mapped_{filename}"

            # write parsed mappings to yaml file
            write_parsed_mappings_yaml(parsed_mappings, filepath)

            # write parsed mappings to json file
            write_parsed_mappings_json(parsed_mappings, filepath)

            # write parsed mappings to csv file
            write_parsed_mappings_csv(parsed_mappings, filepath)


def parse_security_stack_mappings():
    rootdir = f"{ROOT_DIR}/mappings/SecurityStack"
    # read in all files in SecurityStack directory
    for _, directories, _ in os.walk(rootdir):
        for directory in directories:
            parsed_mappings = []
            for file in os.listdir(f"{rootdir}/{directory}"):
                filepath = f"{rootdir}/{directory}/{file}"
                data = read_yaml_file(filepath)
                configure_security_stack_mappings(data, parsed_mappings)

            # define directory parsed data goes into
            security_stack_folder_path = (
                f"{PARSED_MAPPINGS_DIR}security_stack/{directory}"
            )
            security_stack_folder_path_exists = os.path.exists(
                security_stack_folder_path
            )
            if not security_stack_folder_path_exists:
                os.makedirs(security_stack_folder_path)
            filepath = f"{security_stack_folder_path}/mapped_{directory}"

            # write parsed data to a csv file
            write_parsed_mappings_yaml(parsed_mappings, filepath)

            # write parsed data to a json file
            write_parsed_mappings_json(parsed_mappings, filepath)

            # write parsed mappings to csv file
            write_parsed_mappings_csv(parsed_mappings, filepath)
