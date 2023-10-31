import argparse
import json
import os
import sys

from jsonschema import validate
from mapex.write_parsed_mappings import (
    write_parsed_mappings_csv,
    write_parsed_mappings_navigator_layer,
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
        if os.path.isfile(input_file):
            validation_errors = validate_file(input_file)
            if validation_errors is not None:
                sys.exit(1)

        elif os.path.isdir(input_file):
            for dirpath, _, filenames in os.walk(input_file):
                for file in filenames:
                    input_filepath = f"{dirpath}/{file}"
                    validation_errors = validate_file(input_filepath)
                    if validation_errors is not None:
                        sys.exit(1)

        print("succesfully validated")
        sys.exit(0)


def _parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(help="commands", dest="command")

    export_parser = subparsers.add_parser("export")
    export_parser.add_argument("input_file")
    export_parser.add_argument("output_file")
    export_parser.add_argument(
        "--file-type", choices=["csv", "yaml", "navigator-layer"]
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
    elif file_type == "yaml":
        write_parsed_mappings_yaml(parsed_mappings, output_file)
    elif file_type == "csv":
        write_parsed_mappings_csv(parsed_mappings, output_file, metadata_key)
    elif file_type == "navigator-layer":
        write_parsed_mappings_navigator_layer(parsed_mappings, output_file)
    else:
        print("Please enter a correct filetype")


def validate_file(input_file):
    parsed_mappings = read_json_file(input_file)
    schema_filepath = f"{ROOT_DIR}/schema/mapex-unified-data-schema.json"
    schema = json.loads(open(schema_filepath, "r", encoding="UTF-8").read())
    return validate(instance=parsed_mappings, schema=schema)
