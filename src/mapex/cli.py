import argparse
import json
import os
import shutil
import sys
from pathlib import Path

from jsonschema import validate
from mapex.write_parsed_mappings import (
    create_df,
    write_parsed_mappings_csv,
    write_parsed_mappings_excel,
    write_parsed_mappings_navigator_layer,
    write_parsed_mappings_stix,
    write_parsed_mappings_yaml,
)
from termcolor import colored

ROOT_DIR = Path.cwd()
PARSED_MAPPINGS_DIR = ROOT_DIR / "mappings"
MAPEX_DIR = ROOT_DIR / "src" / "mapex"


def main():
    """Main entry point for `mapex` command line."""
    args = _parse_args()
    input_file_str = args.input_file
    input_file_path = Path(args.input_file)
    if args.command == "export":
        output_file = Path(args.output_file)
        file_type = args.file_type

        # if input filepath is a file, export file
        if os.path.isfile(input_file_path):
            export_file(input_file_path, output_file, file_type)

        # if input filepath is a directory, walk through nested directories until file
        # is found. Output files will go into the output filepath given within the
        # nested directories it is in the input direcotry
        elif os.path.isdir(input_file_path):
            for dirpath, _, filenames in os.walk(input_file_path):
                if len(filenames):
                    for file in filenames:
                        input_filepath = Path(dirpath) / file
                        nested_dirs = dirpath.replace(input_file_str + "/", "")
                        output_filepath = output_file / Path(nested_dirs)
                        output_filepath.mkdir(parents=True, exist_ok=True)
                        export_file(input_filepath, output_filepath, file_type)
        else:
            print("Input file must be a valid file or directory")
            sys.exit(1)

    elif args.command == "validate":
        if os.path.isfile(input_file_path):
            validation_errors = validate_file(input_file_path)
            if validation_errors is not None:
                sys.exit(1)

        elif os.path.isdir(input_file_path):
            for dirpath, _, filenames in os.walk(input_file_path):
                for file in filenames:
                    input_filepath = Path(dirpath) / file
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
        "--file-type",
        choices=["csv", "yaml", "navigator-layer", "stix", "excel", "json"],
    )

    validate_parser = subparsers.add_parser("validate")
    validate_parser.add_argument("input_file")

    args: argparse.Namespace = parser.parse_args()
    return args


def read_json_file(filepath):
    with open(filepath, encoding="UTF-8") as user_file:
        mappings = user_file.read()
        return json.loads(mappings)


def copy_parsed_mappings(input_filepath, output_filepath):
    shutil.copyfile(input_filepath, f"{output_filepath}.json")


def export_file(input_file, output_file, file_type):
    # read input file
    parsed_mappings = read_json_file(input_file)

    # validate contents of mapping file
    validation_errors = validate_file(input_file)
    if validation_errors is not None:
        sys.exit(1)
    # additional sanity checks
    sanity_check_mappings(parsed_mappings)

    # assign output filename and filepath
    output_filename = input_file.stem
    output_filepath = output_file / output_filename

    # export mappings
    if file_type is None:
        write_parsed_mappings_yaml(parsed_mappings, output_filepath)
        write_parsed_mappings_navigator_layer(parsed_mappings, output_filepath)
        write_parsed_mappings_stix(parsed_mappings, output_filepath)
        copy_parsed_mappings(input_file, output_filepath)
        df = create_df(parsed_mappings)
        write_parsed_mappings_csv(df, output_filepath)
        write_parsed_mappings_excel(df, output_filepath)
    elif file_type == "yaml":
        write_parsed_mappings_yaml(parsed_mappings, output_filepath)
    elif file_type == "csv":
        df = create_df(parsed_mappings)
        write_parsed_mappings_csv(df, output_filepath)
    elif file_type == "excel":
        df = create_df(parsed_mappings)
        write_parsed_mappings_excel(df, output_filepath)
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
    schema_filepath = ROOT_DIR / "schema" / "mapex-unified-data-schema.json"
    schema = json.loads(open(schema_filepath, "r", encoding="UTF-8").read())
    return validate(instance=parsed_mappings, schema=schema)


def sanity_check_mappings(parsed_mappings):
    # get all group ids defined and group ids used
    mapping_objects = parsed_mappings["mapping_objects"]
    groups_used_in_mappings = set(
        [mapping_object["group"] for mapping_object in mapping_objects]
    )

    metadata_group_ids = set(
        [group["id"] for group in parsed_mappings["metadata"]["groups"]]
    )

    # warning if there is a group in metadata that is never used
    all_groups_used = metadata_group_ids.issubset(groups_used_in_mappings)
    extra_groups = metadata_group_ids.difference(groups_used_in_mappings)
    if not all_groups_used:
        print(
            colored(
                f"""WARNING: The following groups are not used
            by the mapping objects: {extra_groups}""",
                "yellow",
            )
        )
        # unused groups are eliminated in exported file
        metadata_groups = parsed_mappings["metadata"]["groups"]
        for group in extra_groups:
            metadata_group = list(
                filter(
                    lambda group_object: group_object["id"] == group, metadata_groups
                )
            )[0]
            parsed_mappings["metadata"]["groups"].remove(metadata_group)

    # # error if any objects reference a group that is not defined in metadata
    all_used_groups_defined = groups_used_in_mappings.issubset(metadata_group_ids)
    missing_groups = groups_used_in_mappings.difference(metadata_group_ids)
    if not all_used_groups_defined:
        print(
            colored(
                f"""ERROR: The following groups are referenced by mapping
            objects but aren't defined in 'metadata': {missing_groups}""",
                "red",
            )
        )
        sys.exit(1)

    # get all mapping type ids defined and mapping type ids used
    mapping_objects = parsed_mappings["mapping_objects"]
    mapping_types_used_in_mappings = set(
        [mapping_object["mapping_type"] for mapping_object in mapping_objects]
    )

    metadata_mapping_type_ids = set(
        [
            mapping_type["id"]
            for mapping_type in parsed_mappings["metadata"]["mapping_types"]
        ]
    )

    # warning if there is a group in metadata that is never used
    all_mapping_types_used = metadata_mapping_type_ids.issubset(
        mapping_types_used_in_mappings
    )
    extra_mapping_types = metadata_mapping_type_ids.difference(
        mapping_types_used_in_mappings
    )
    if not all_mapping_types_used:
        print(
            colored(
                f"""WARNING: The following mapping types are not used
                    by the mapping objects: {extra_mapping_types} """,
                "yellow",
            )
        )

    # error if any objects reference a group that is not defined in metadata
    all_mapping_types_defined = mapping_types_used_in_mappings.issubset(
        metadata_mapping_type_ids
    )
    missing_mapping_types = mapping_types_used_in_mappings.difference(
        metadata_mapping_type_ids
    )
    if not all_mapping_types_defined:
        print(
            colored(
                f"""ERROR: The following mapping types are referenced by mapping
            objects but are not defined in 'metadata': {missing_mapping_types}""",
                "red",
            )
        )
        sys.exit(1)
