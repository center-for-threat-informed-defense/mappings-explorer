import argparse
import json
import os
from pathlib import Path

import requests
from mapex_convert.parse_cve_mappings import (
    configure_cve_mappings,
)
from mapex_convert.parse_nist_mappings import (
    configure_nist_mappings,
)
from mapex_convert.parse_security_stack_mappings import (
    configure_security_stack_mappings,
)
from mapex_convert.parse_veris_mappings import (
    configure_veris_mappings,
)
from mapex_convert.read_files import (
    read_csv_file,
    read_excel_file,
    read_json_file,
    read_yaml_file,
)

ROOT_DIR = Path.cwd()
PARSED_MAPPINGS_DIR = ROOT_DIR / "mappings"
MAPPINGS_DIR = ROOT_DIR / "src" / "mapex_convert" / "mappings"


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
    response = requests.get(enterpise_attack_url, verify=False)
    enterprise_attack_data = json.loads(response.text)

    # load mobile attack stix json to map technique ids to names
    enterpise_attack_url = f"{BASE_URL}/mobile-attack/mobile-attack-9.0.json"
    response = requests.get(enterpise_attack_url, verify=False)
    mobile_attack_data = json.loads(response.text)

    # load ics attack stix json to map technique ids to names
    enterpise_attack_url = f"{BASE_URL}/ics-attack/ics-attack-9.0.json"
    response = requests.get(enterpise_attack_url, verify=False)
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
    # create dictionary of technique ids and names
    attack_object_id_to_name = load_attack_json()

    # read un-parsed mappings
    cve_filepath = MAPPINGS_DIR / "Att&ckToCveMappings.csv"
    df = read_csv_file(cve_filepath)

    # parse mappings
    parsed_mappings = configure_cve_mappings(df, attack_object_id_to_name)

    # write parsed mappings to json file
    filename_version_string = get_filename_version_string(parsed_mappings)
    output_filepath = PARSED_MAPPINGS_DIR / "cve" / f"cve{filename_version_string}"
    write_parsed_mappings_json(parsed_mappings, output_filepath)


def parse_nist_mappings():
    directory = MAPPINGS_DIR / "NIST_800-53"

    # iterate through all nist mapping files in the directory
    for filename in os.listdir(directory):
        file = os.path.join(directory, filename)

        # checking if it is a file
        if os.path.isfile(file):
            # read un-parsed mappings
            dataframe = read_excel_file(file)

            # parse mappings
            attack_version = filename[
                filename.rfind("-") + 1 : filename.index("mappings")
            ].replace("_", ".")
            mapping_framework_version = filename[
                filename.index("r") : filename.index("r") + 2
            ]
            parsed_mappings = configure_nist_mappings(
                dataframe, attack_version, mapping_framework_version
            )

            # write parsed mappings to json file

            # get output filepath
            filename_version_string = get_filename_version_string(parsed_mappings)
            mapped_filename = f"nist-800{filename_version_string}"
            output_filepath = (
                PARSED_MAPPINGS_DIR
                / "nist"
                / attack_version
                / mapping_framework_version
            )
            output_filepath.mkdir(parents=True, exist_ok=True)
            write_parsed_mappings_json(
                parsed_mappings, output_filepath / mapped_filename
            )


def parse_veris_mappings():
    directory = MAPPINGS_DIR / "Veris"

    # iterate through mappings files
    for filename in os.listdir(directory):
        file = os.path.join(directory, filename)
        if os.path.isfile(file):
            # read un-parsed mappings
            veris_mappings = read_json_file(file)

            # parse mappings
            veris_version = "1.3.7" if "1_3_7" in filename else "1.3.5"
            domain = (
                "enterprise"
                if veris_version == "1.3.5"
                else filename[filename.rindex("-") + 1 : filename.index(".")]
            )
            parsed_mappings = configure_veris_mappings(veris_mappings, domain)

            # write parsed mappings to a json file
            output_filepath = PARSED_MAPPINGS_DIR / "veris" / veris_version
            output_filepath.mkdir(parents=True, exist_ok=True)
            filename_version_string = get_filename_version_string(parsed_mappings)
            filename = f"veris{filename_version_string}"
            filepath = output_filepath / filename
            write_parsed_mappings_json(parsed_mappings, filepath)


def parse_security_stack_mappings():
    rootdir = MAPPINGS_DIR / "SecurityStack"

    # iterate through mappings files
    for _, directories, _ in os.walk(rootdir):
        for directory in directories:
            parsed_mappings = {}
            for file in os.listdir(rootdir / directory):
                filepath = rootdir / directory / file

                # read un-mapping filed
                data = read_yaml_file(filepath)

                # parse mappings
                configure_security_stack_mappings(data, parsed_mappings)

            # write parsed data to json file
            security_stack_folder_path = (
                PARSED_MAPPINGS_DIR / "security_stack" / directory
            )
            security_stack_folder_path.mkdir(parents=True, exist_ok=True)
            filename_version_string = get_filename_version_string(parsed_mappings)
            filename = f"{directory}{filename_version_string}"
            filepath = security_stack_folder_path / filename

            write_parsed_mappings_json(parsed_mappings, filepath)


def write_parsed_mappings_json(parsed_mappings, filepath):
    result_json_file = open(
        f"{filepath}.json",
        "w",
        encoding="UTF-8",
    )
    json.dump(parsed_mappings, fp=result_json_file)


def get_filename_version_string(parsed_mappings):
    mapping_framework_version = parsed_mappings["metadata"]["mapping_framework_version"]
    mapping_framework_version_string = (
        f"-{mapping_framework_version}" if mapping_framework_version else ""
    )
    attack_version = parsed_mappings["metadata"]["attack_version"]
    return f"{mapping_framework_version_string}_attack-{attack_version}"
