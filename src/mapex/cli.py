import argparse
import json
import os
import shutil
import sys

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

        # ensure that output filepath is a valid directory
        # script will assign output filename based on input filename
        if os.path.isfile(output_file):
            print("Please enter valid directory for output files")
            sys.exit(1)
        elif not os.path.exists(output_file):
            os.makedirs(output_file)

        # if input filepath is a file, export file
        if os.path.isfile(input_file):
            metadata_key = 0
            export_file(input_file, output_file, file_type, metadata_key)

        # if input filepath is a directory, walk through nested directories until file
        # is found. Output files will go into the output filepath given within the
        # nested directories it is in the input direcotry
        elif os.path.isdir(input_file):
            metadata_key = 0
            for dirpath, dirnames, filenames in os.walk(input_file):
                for dir_name in dirnames:
                    nested_dirs = dirpath.replace(input_file, "")
                    if not os.path.exists(f"{output_file}{nested_dirs}/{dir_name}"):
                        os.makedirs(f"{output_file}{nested_dirs}/{dir_name}")

                if len(filenames):
                    for file in filenames:
                        input_filepath = f"{dirpath}/{file}"
                        metadata_key += 1
                        nested_dirs = dirpath.replace(input_file, "")
                        output_filepath = f"{output_file}{nested_dirs}"
                        export_file(
                            input_filepath, output_filepath, file_type, metadata_key
                        )
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
        "--file-type", choices=["csv", "yaml", "navigator-layer", "stix", "json"]
    )

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("input_file")

    args: argparse.Namespace = parser.parse_args()
    return args


def copy_parsed_mappings(input_filepath, output_filepath):
    shutil.copyfile(input_filepath, output_filepath + ".json")


def read_json_file(filepath):
    with open(filepath, encoding="UTF-8") as user_file:
        mappings = user_file.read()
        return json.loads(mappings)


def export_file(input_file, output_file, file_type, metadata_key):
    # read input file
    parsed_mappings = read_json_file(input_file)

    # assign output filename and filepath
    filepath_parts = input_file.split("/")
    input_filename = filepath_parts[-1]
    output_filename = input_filename[0 : input_filename.rindex(".")]
    output_filepath = f"{output_file}/{output_filename}"

    # export mappings
    if file_type is None:
        write_parsed_mappings_yaml(parsed_mappings, output_filepath)
        write_parsed_mappings_csv(parsed_mappings, output_filepath, metadata_key)
        write_parsed_mappings_navigator_layer(parsed_mappings, output_filepath)
        write_parsed_mappings_stix(parsed_mappings, output_filepath)
        copy_parsed_mappings(input_file, output_filepath)
    elif file_type == "yaml":
        write_parsed_mappings_yaml(parsed_mappings, output_filepath)
    elif file_type == "csv":
        write_parsed_mappings_csv(parsed_mappings, output_filepath, metadata_key)
    elif file_type == "navigator-layer":
        write_parsed_mappings_navigator_layer(parsed_mappings, output_filepath)
    elif file_type == "stix":
        write_parsed_mappings_stix(parsed_mappings, output_filepath)
    elif file_type == "json":
        copy_parsed_mappings(input_file, output_filepath)
    else:
        print("Please enter a correct filetype")


def validate_file(input_file):
    parsed_mappings = read_json_file(input_file)
    schema_filepath = f"{ROOT_DIR}/schema/mapex-unified-data-schema.json"
    schema = json.loads(open(schema_filepath, "r", encoding="UTF-8").read())
    validation_errors = validate(instance=parsed_mappings, schema=schema)
    if validation_errors is None:
        print("successfully validated")
