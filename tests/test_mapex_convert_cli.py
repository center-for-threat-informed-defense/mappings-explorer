import json
import os

import yaml
from mapex_convert.cli import write_parsed_mappings_json

from tests.expected_results.expected_results_json import (
    expected_cve_mapping_json,
    expected_nist_mapping_json,
    expected_security_stack_mapping_json,
    expected_veris_mapping_json,
)
from tests.parsers import (
    cve_mappings_parser,
    nist_mappings_parser,
    security_stack_mappings_parser,
    veris_mappings_parser,
)


def test_nist_mappings_parser_json(tmpdir):
    # ARRANGE
    filename = "nist_mappings"
    filepath = f"{tmpdir}/{filename}"
    parsed_mappings = nist_mappings_parser()

    # ACT
    write_parsed_mappings_json(parsed_mappings, filepath)
    file = open(f"{filepath}.json", "r", encoding="UTF-8")
    result = json.load(file)

    # ASSERT
    print("RESULT")
    print(result)
    print("EXPECTED")
    print(expected_nist_mapping_json)
    assert result == expected_nist_mapping_json


def test_security_stack_mappings_json(tmpdir):
    # ARRANGE
    root_filepath = os.path.join(os.path.dirname(__file__), "files/security_stack")

    # ACT
    for _, directories, _ in os.walk(root_filepath):
        for directory in directories:
            # get parsed data
            filepath = f"{root_filepath}/{directory}"
            parsed_mappings = security_stack_mappings_parser(filepath)

            # write parsed data to file
            filename = f"security_stack_{directory}_mappings"
            tmpdir.mkdir(directory).join(filename)
            output_filepath = f"{tmpdir}/{directory}/{filename}"
            write_parsed_mappings_json(parsed_mappings, output_filepath)
            file = open(f"{output_filepath}.json", "r", encoding="UTF-8")
            result = json.load(file)

            # ASSERT
            assert result == expected_security_stack_mapping_json


def test_veris_mappings_json(tmpdir):
    # ARRANGE
    parsed_mappings = veris_mappings_parser()
    filename = "veris_mappings"
    filepath = f"{tmpdir}/{filename}"

    # ACT
    write_parsed_mappings_json(parsed_mappings, filepath)
    file = open(f"{filepath}.json", "r", encoding="UTF-8")
    result = json.load(file)

    # ASSERT
    assert result == expected_veris_mapping_json


def test_cve_mappings_json(tmpdir):
    # ARRANGE
    parsed_mappings = cve_mappings_parser()
    filename = "cve_mappings"
    filepath = f"{tmpdir}/{filename}"

    # ACT
    write_parsed_mappings_json(parsed_mappings, filepath)
    file = open(f"{filepath}.json", "r", encoding="UTF-8")
    result = yaml.safe_load(file)

    # ASSERT
    assert result == expected_cve_mapping_json
