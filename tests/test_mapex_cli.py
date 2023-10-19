import json
import os

from mapex.cli import read_json_file
from mapex.write_parsed_mappings import (
    get_filename_version_string,
    write_parsed_mappings_csv,
    write_parsed_mappings_navigator_layer,
    write_parsed_mappings_yaml,
)

from tests.expected_results.expected_results_navigator_layer import (
    expected_navigator_layer_results,
)
from tests.expected_results.expected_results_yaml import expected_yaml_results


def test_write_mappings_to_yaml(tmpdir):
    # ARRANGE
    json_filepath = os.path.join(
        os.path.dirname(__file__), "files/parsed_mappings.json"
    )
    parsed_mappings = read_json_file(json_filepath)
    filepath = f"{tmpdir}"

    # ACT
    write_parsed_mappings_yaml(parsed_mappings, filepath)
    file = open(f"{filepath}_attack-13.0.yaml", "r", encoding="UTF-8")
    result = file.read()

    # ASSERT

    assert result == expected_yaml_results


def test_write_mappings_to_csv(tmpdir):
    # ARRANGE
    root_dir = os.path.dirname(__file__)
    json_filepath = os.path.join(root_dir, "files/parsed_mappings.json")
    parsed_mappings = read_json_file(json_filepath)
    filepath = f"{tmpdir}"
    expected_attack_objects_file = open(
        f"{root_dir}/expected_results/expected_csv_results_attack_objects.csv",
        "r",
        encoding="UTF-8",
    )
    expected_metadata_file = open(
        f"{root_dir}/expected_results/expected_csv_results_metadata.csv",
        "r",
        encoding="UTF-8",
    )
    metadata_key = 0

    # ACT
    write_parsed_mappings_csv(parsed_mappings, filepath, metadata_key)
    version_string = get_filename_version_string(parsed_mappings)
    attack_objects_file = open(
        f"{filepath}{version_string}_attack_objects.csv",
        "r",
        encoding="UTF-8",
    )
    metadata_file = open(
        f"{filepath}{version_string}_metadata.csv", "r", encoding="UTF-8"
    )

    # ASSERT
    assert expected_attack_objects_file.read() == attack_objects_file.read()
    assert expected_metadata_file.read() == metadata_file.read()


def test_nist_mappings_parser_navigator_layer(tmpdir):
    # ARRANGE
    root_dir = os.path.dirname(__file__)
    json_filepath = os.path.join(root_dir, "files/parsed_mappings.json")
    parsed_mappings = read_json_file(json_filepath)
    filepath = f"{tmpdir}"

    # ACT
    write_parsed_mappings_navigator_layer(parsed_mappings, filepath)
    version_string = get_filename_version_string(parsed_mappings)
    file = open(
        f"{filepath}{version_string}_navigator_layer.json", "r", encoding="UTF-8"
    )
    result = json.load(file)

    # ASSERT
    print("RESULT")
    print(result)
    print("EXPECTED")
    print(expected_navigator_layer_results)
    assert result == expected_navigator_layer_results
