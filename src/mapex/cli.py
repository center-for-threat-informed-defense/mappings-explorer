import argparse
import json
import os

from mappings_explorer.cli.mapex.write_parsed_mappings import (
    write_parsed_mappings_csv,
    write_parsed_mappings_navigator_layer,
    write_parsed_mappings_yaml,
)

ROOT_DIR = os.path.abspath(os.curdir)
CLI_DIR = f"{ROOT_DIR}/src/mappings_explorer/cli"
PARSED_MAPPINGS_DIR = f"{CLI_DIR}/parsed_mappings"
MAPEX_DIR = f"{CLI_DIR}/mapex"


def main():
    """Main entry point for `mapex` command line."""
    args = _parse_args()
    if args.mappings == "cve":
        write_parsed_cve_mappings()
    elif args.mappings == "nist":
        write_parsed_nist_mappings()
    elif args.mappings == "veris":
        write_parsed_veris_mappings()
    elif args.mappings == "security-stack":
        write_parsed_security_stack_mappings()


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


def read_json_file(filepath):
    with open(filepath, encoding="UTF-8") as user_file:
        mappings = user_file.read()
        return json.loads(mappings)


def write_parsed_cve_mappings():
    parsed_mappings_filepath = f"{PARSED_MAPPINGS_DIR}/cve/parsed_cve_mappings.json"
    output_filepath = f"{MAPEX_DIR}/cve_files/parsed_cve_mappings"
    parsed_mappings = read_json_file(parsed_mappings_filepath)

    # write parsed mappings to a yaml file
    write_parsed_mappings_yaml(parsed_mappings, output_filepath)

    # key that connects the metadata csv file and the attack objects csv file
    metadata_key = 0
    # write parsed mappings to a csv file
    write_parsed_mappings_csv(parsed_mappings, output_filepath, metadata_key)

    # write parse mappings to navigator layer
    write_parsed_mappings_navigator_layer(parsed_mappings, output_filepath, "cve")


def write_parsed_nist_mappings():
    nist_parsed_mappings_dir = f"{PARSED_MAPPINGS_DIR}/nist/"

    # key that connects the metadata csv file and the attack objects csv file
    metadata_key = 0
    for subdir, _, files in os.walk(nist_parsed_mappings_dir):
        for file in files:
            # read parsed mappings
            parsed_mappings_filepath = os.path.join(subdir, file)
            parsed_mappings = read_json_file(parsed_mappings_filepath)

            # create the proper directories
            nist_files_output_dir = f"{MAPEX_DIR}/nist_files/"
            directories = parsed_mappings_filepath.split("/")
            nist_version_directory = directories[-2]
            attack_version_directory = directories[-3]
            attack_version_filepath = (
                f"{nist_files_output_dir}{attack_version_directory}"
            )
            attack_version_filepath_exists = os.path.exists(attack_version_filepath)
            if not attack_version_filepath_exists:
                os.makedirs(attack_version_filepath)

            nist_version_filepath = (
                f"{attack_version_filepath}/{nist_version_directory}"
            )
            nist_version_filepath_exists = os.path.exists(nist_version_filepath)

            if not nist_version_filepath_exists:
                os.makedirs(nist_version_filepath)

            version_dir = f"{attack_version_directory}/{nist_version_directory}"
            output_directory = f"{nist_files_output_dir}{version_dir}"
            output_filepath = f"{output_directory}/parsed_nist_mappings"
            # writ parsed mappings to yaml
            write_parsed_mappings_yaml(parsed_mappings, output_filepath)

            # write parsed mappings to csv
            write_parsed_mappings_csv(parsed_mappings, output_filepath, metadata_key)
            metadata_key += 1

            # write parsed mappings to navigator layer
            write_parsed_mappings_navigator_layer(
                parsed_mappings, output_filepath, "nist"
            )


def write_parsed_veris_mappings():
    veris_parsed_mappings_dir = f"{PARSED_MAPPINGS_DIR}/veris"

    metadata_key = 0

    for subdir, _, files in os.walk(veris_parsed_mappings_dir):
        for file in files:
            # read parsed mappings
            parsed_mappings_filepath = os.path.join(subdir, file)
            parsed_mappings = read_json_file(parsed_mappings_filepath)

            # create the proper directories
            veris_files_output_dir = f"{MAPEX_DIR}/veris_files/"
            directories = parsed_mappings_filepath.split("/")
            veris_version_directory = directories[-2]
            veris_version_filepath = (
                f"{veris_files_output_dir}{veris_version_directory}"
            )

            veris_version_filepath_exists = os.path.exists(veris_version_filepath)
            if not veris_version_filepath_exists:
                os.makedirs(veris_version_filepath)

            output_dir = f"{veris_files_output_dir}{veris_version_directory}"
            output_filepath = f"{output_dir}/parsed_veris_mappings"
            # writ parsed mappings to yaml
            write_parsed_mappings_yaml(parsed_mappings, output_filepath)

            # write parsed mappings to csv
            write_parsed_mappings_csv(parsed_mappings, output_filepath, metadata_key)
            metadata_key += 1

            # write parsed mappings to navigator layer
            write_parsed_mappings_navigator_layer(
                parsed_mappings, output_filepath, "veris"
            )


def write_parsed_security_stack_mappings():
    security_stack_dir = f"{PARSED_MAPPINGS_DIR}/security_stack"

    metadata_key = 0

    for subdir, _, files in os.walk(security_stack_dir):
        for file in files:
            # read parsed mappings
            parsed_mappings_filepath = os.path.join(subdir, file)
            parsed_mappings = read_json_file(parsed_mappings_filepath)

            # create the proper directories
            security_stack_files_output_dir = f"{MAPEX_DIR}/security_stack_files/"
            directories = parsed_mappings_filepath.split("/")
            security_stack_type = directories[-2]
            security_stack_filepath = (
                f"{security_stack_files_output_dir}{security_stack_type}"
            )

            security_stack_filepath_exists = os.path.exists(security_stack_filepath)
            if not security_stack_filepath_exists:
                os.makedirs(security_stack_filepath)

            output_filepath = (
                f"{security_stack_filepath}/parsed_security_stack_mappings"
            )
            # writ parsed mappings to yaml
            write_parsed_mappings_yaml(parsed_mappings, output_filepath)

            # write parsed mappings to csv
            write_parsed_mappings_csv(parsed_mappings, output_filepath, metadata_key)
            metadata_key += 1

            # write parsed mappings to navigator layer
            write_parsed_mappings_navigator_layer(
                parsed_mappings, output_filepath, "security stack"
            )
