import argparse
import json
import os

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

ROOT_DIR = os.path.abspath(os.curdir)
PARSED_MAPPINGS_DIR = f"{ROOT_DIR}/mappings"
MAPPINGS_DIR = f"{ROOT_DIR}/src/mapex_convert/mappings"


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
    cve_filepath = f"{MAPPINGS_DIR}/Att&ckToCveMappings.csv"
    df = read_csv_file(cve_filepath)

    # parse mappings
    parsed_mappings = configure_cve_mappings(df, attack_object_id_to_name)

    # write parsed mappings to json file
    attack_version = parsed_mappings["metadata"]["attack_version"]
    output_filepath = f"{PARSED_MAPPINGS_DIR}/cve/cve_attack-{attack_version}"
    write_parsed_mappings_json(parsed_mappings, output_filepath)


def parse_nist_mappings():
    directory = f"{MAPPINGS_DIR}/NIST_800-53"

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
            mappings_version = filename[filename.index("r") : filename.index("r") + 2]
            parsed_mappings = configure_nist_mappings(
                dataframe, attack_version, mappings_version
            )

            # write parsed mappings to json file
            mapped_filename = f"nist-800-{mappings_version}_attack-{attack_version}"
            attack_version_path = f"{PARSED_MAPPINGS_DIR}/nist/{attack_version}/"
            attack_version_path_exists = os.path.exists(attack_version_path)
            if not attack_version_path_exists:
                os.makedirs(attack_version_path)
            nist_dir = f"nist/{attack_version}/{mappings_version}/"
            mappings_version_path = f"{PARSED_MAPPINGS_DIR}/{nist_dir}"
            mappings_version_path_exists = os.path.exists(mappings_version_path)
            if not mappings_version_path_exists:
                os.makedirs(mappings_version_path)
            filepath = f"{mappings_version_path}/{mapped_filename}"
            write_parsed_mappings_json(parsed_mappings, filepath)


def parse_veris_mappings():
    directory = f"{MAPPINGS_DIR}/Veris"

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
            attack_version = parsed_mappings["metadata"]["attack_version"]

            # write parsed mappings to a json file
            veris_version_path = f"{PARSED_MAPPINGS_DIR}/veris/{veris_version}"
            veris_version_path_exists = os.path.exists(veris_version_path)
            if not veris_version_path_exists:
                os.makedirs(veris_version_path)
            filename = f"veris-{veris_version}_attack-{attack_version}"
            filepath = f"{PARSED_MAPPINGS_DIR}/veris/{veris_version}/{filename}"
            write_parsed_mappings_json(parsed_mappings, filepath)


def parse_security_stack_mappings():
    rootdir = f"{MAPPINGS_DIR}/SecurityStack"

    # iterate through mappings files
    for _, directories, _ in os.walk(rootdir):
        for directory in directories:
            parsed_mappings = {}
            for file in os.listdir(f"{rootdir}/{directory}"):
                filepath = f"{rootdir}/{directory}/{file}"

                # read un-mapping filed
                data = read_yaml_file(filepath)

                # parse mappings
                configure_security_stack_mappings(data, parsed_mappings)

            # write parsed data to json file
            security_stack_folder_path = (
                f"{PARSED_MAPPINGS_DIR}/security_stack/{directory}"
            )
            security_stack_folder_path_exists = os.path.exists(
                security_stack_folder_path
            )
            if not security_stack_folder_path_exists:
                os.makedirs(security_stack_folder_path)
            attack_version = parsed_mappings["metadata"]["attack_version"]
            filename = f"{directory}_attack-{attack_version}"
            filepath = f"{security_stack_folder_path}/{filename}"

            write_parsed_mappings_json(parsed_mappings, filepath)


def write_parsed_mappings_json(parsed_mappings, filepath):
    result_json_file = open(
        f"{filepath}.json",
        "w",
        encoding="UTF-8",
    )
    json.dump(parsed_mappings, fp=result_json_file)
