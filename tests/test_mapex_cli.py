import json
import os

from mapex.cli import read_json_file
from mapex.write_parsed_mappings import (
    write_parsed_mappings_csv,
    write_parsed_mappings_navigator_layer,
    write_parsed_mappings_stix,
    write_parsed_mappings_yaml,
)

from tests.expected_results.expected_results_navigator_layer import (
    expected_navigator_layer_results,
)
from tests.expected_results.expected_results_stix import expected_stix_results
from tests.expected_results.expected_results_yaml import expected_yaml_results


def test_write_mappings_to_yaml(tmpdir):
    # ARRANGE
    json_filepath = os.path.join(
        os.path.dirname(__file__), "files/parsed_mappings.json"
    )
    parsed_mappings = read_json_file(json_filepath)
    filepath = f"{tmpdir}/parsed_mappings"

    # ACT
    write_parsed_mappings_yaml(parsed_mappings, filepath)
    file = open(f"{filepath}.yaml", "r", encoding="UTF-8")
    result = file.read()

    # ASSERT

    assert result == expected_yaml_results


def test_write_mappings_to_csv(tmpdir):
    # ARRANGE
    root_dir = os.path.dirname(__file__)
    json_filepath = os.path.join(root_dir, "files/parsed_mappings.json")
    parsed_mappings = read_json_file(json_filepath)
    filepath = f"{tmpdir}/parsed_mappings"
    expected_csv_file = open(
        f"{root_dir}/expected_results/expected_csv_results.csv",
        "r",
        encoding="UTF-8",
    )

    # ACT
    write_parsed_mappings_csv(parsed_mappings, filepath)
    csv_file = open(
        f"{filepath}.csv",
        "r",
        encoding="UTF-8",
    )

    # ASSERT
    print("EXPECTED")
    print(expected_csv_file.read())
    print("")
    print("RESULT")
    print(csv_file.read())
    assert expected_csv_file.read() == csv_file.read()


def test_write_mappings_to_navigator_layer(tmpdir):
    # ARRANGE
    root_dir = os.path.dirname(__file__)
    json_filepath = os.path.join(root_dir, "files/parsed_mappings.json")
    parsed_mappings = read_json_file(json_filepath)
    filepath = f"{tmpdir}/parsed_mappings"

    # ACT
    write_parsed_mappings_navigator_layer(parsed_mappings, filepath)
    file = open(f"{filepath}_navigator_layer.json", "r", encoding="UTF-8")
    result = json.load(file)

    # ASSERT
    assert result == expected_navigator_layer_results


def test_write_mappings_to_stix(tmpdir):
    # ARRANGE
    root_dir = os.path.dirname(__file__)
    json_filepath = os.path.join(root_dir, "files/parsed_mappings.json")
    parsed_mappings = read_json_file(json_filepath)
    filepath = f"{tmpdir}/parsed_mappings"

    # ACT
    write_parsed_mappings_stix(parsed_mappings, filepath)
    file = open(f"{filepath}_stix.json", "r", encoding="UTF-8")
    result = json.load(file)
    dict_fluid_values = ["created", "modified", "id", "source_ref"]

    # pop values, such as uuids and created dates, that change on every run
    for value in dict_fluid_values:
        if value in list(result.keys()):
            result.pop(value)
        for stix_object in result["objects"]:
            if value in list(stix_object.keys()):
                stix_object.pop(value)

    # ASSERT
    assert result == expected_stix_results
