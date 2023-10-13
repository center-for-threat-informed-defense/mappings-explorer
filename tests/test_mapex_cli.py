import json
import os

import yaml
from mappings_explorer.cli.mapex.write_parsed_mappings import (
    write_parsed_mappings_csv,
    write_parsed_mappings_navigator_layer,
    write_parsed_mappings_yaml,
)

from tests.expected_results.expected_results_navigator_layer import (
    expected_cve_navigator_layer,
    expected_nist_navigator_layer,
    expected_security_stack_navigator_layer,
    expected_veris_navigator_layer,
)
from tests.expected_results.expected_results_yaml import (
    expected_cve_mapping_yaml,
    expected_nist_mapping_yaml,
    expected_security_stack_mapping_yaml,
    expected_veris_mapping_yaml,
)
from tests.parsers import (
    cve_mappings_parser,
    nist_mappings_parser,
    security_stack_mappings_parser,
    veris_mappings_parser,
)


def test_write_nist_mappings_to_yaml(tmpdir):
    # ARRANGE
    parsed_mappings = yaml.dump(nist_mappings_parser())
    filename = "nist_mappings"
    filepath = f"{tmpdir}/{filename}"

    # ACT
    write_parsed_mappings_yaml(parsed_mappings, filepath)
    file = open(f"{filepath}.yaml", "r", encoding="UTF-8")
    result = yaml.safe_load(file)

    # ASSERT
    assert result == expected_nist_mapping_yaml


def test_nist_mappings_parser_csv(tmpdir):
    # ARRANGE
    filename = "nist_mappings"
    filepath = f"{tmpdir}/{filename}"
    parsed_mappings = nist_mappings_parser()
    veris_directory = "tests/expected_results/csv/nist"
    expected_attack_objects_file = open(
        f"{veris_directory}/expected_nist_results_attack_objects.csv",
        "r",
        encoding="UTF-8",
    )
    expected_metadata_file = open(
        f"{veris_directory}/expected_nist_results_metadata.csv", "r", encoding="UTF-8"
    )
    metadata_key = 0

    # ACT
    write_parsed_mappings_csv(parsed_mappings, filepath, metadata_key)
    attack_objects_file = open(f"{filepath}_attack_objects.csv", "r", encoding="UTF-8")
    metadata_file = open(f"{filepath}_metadata.csv", "r", encoding="UTF-8")

    # ASSERT
    assert expected_attack_objects_file.read() == attack_objects_file.read()
    assert expected_metadata_file.read() == metadata_file.read()


def test_nist_mappings_parser_navigator_layer(tmpdir):
    # ARRANGE
    filename = "nist_mappings"
    filepath = f"{tmpdir}/{filename}"
    parsed_mappings = nist_mappings_parser()

    # ACT
    write_parsed_mappings_navigator_layer(parsed_mappings, filepath, "nist")
    file = open(f"{filepath}_navigator_layer.json", "r", encoding="UTF-8")
    result = json.load(file)

    # ASSERT
    assert result == expected_nist_navigator_layer


def test_security_stack_mappings_yaml(tmpdir):
    # ARRANGE
    root_filepath = os.path.join(os.path.dirname(__file__), "files/security_stack")

    # ACT
    for _, directories, _ in os.walk(root_filepath):
        for directory in directories:
            # get parsed ddata
            filepath = f"{root_filepath}/{directory}"
            parsed_mappings = yaml.dump(security_stack_mappings_parser(filepath))

            # write parsed data to file
            filename = f"security_stack_{directory}_mappings"
            tmpdir.mkdir(directory).join(filename)
            output_filepath = f"{tmpdir}/{directory}/{filename}"
            write_parsed_mappings_yaml(parsed_mappings, output_filepath)
            file = open(f"{output_filepath}.yaml", "r", encoding="UTF-8")
            result = yaml.safe_load(file)

            # ASSERT
            assert result == expected_security_stack_mapping_yaml


def test_security_stack_mappings_csv(tmpdir):
    # ARRANGE
    root_filepath = os.path.join(os.path.dirname(__file__), "files/security_stack")
    security_stack_directory = "tests/expected_results/csv/security_stack"
    expected_attack_objects_file = open(
        f"{security_stack_directory}/expected_security_stack_results_attack_objects.csv",
        "r",
        encoding="UTF-8",
    )
    expected_metadata_file = open(
        f"{security_stack_directory}/expected_security_stack_results_metadata.csv",
        "r",
        encoding="UTF-8",
    )

    # ACT
    for _, directories, _ in os.walk(root_filepath):
        metadata_key = 0
        for directory in directories:
            # get parsed data
            filepath = f"{root_filepath}/{directory}"
            parsed_mappings = security_stack_mappings_parser(filepath)

            # write parsed data to csv files
            filename = f"security_stack_{directory}_mappings"
            tmpdir.mkdir(directory).join(filename)
            write_parsed_mappings_csv(parsed_mappings, filepath, metadata_key)
            metadata_key += 1
            attack_objects_file = open(
                f"{filepath}_attack_objects.csv", "r", encoding="UTF-8"
            )
            metadata_file = open(f"{filepath}_metadata.csv", "r", encoding="UTF-8")

            # ASSERT
            assert expected_attack_objects_file.read() == attack_objects_file.read()
            assert expected_metadata_file.read() == metadata_file.read()


def test_security_stack_mappings_navigator_layer(tmpdir):
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
            write_parsed_mappings_navigator_layer(
                parsed_mappings, output_filepath, "security stack"
            )
            file = open(
                f"{output_filepath}_navigator_layer.json", "r", encoding="UTF-8"
            )
            result = json.load(file)

            # ASSERT
            assert result == expected_security_stack_navigator_layer


def test_veris_mappings_yaml(tmpdir):
    # ARRANGE
    parsed_mappings = yaml.dump(veris_mappings_parser())
    filename = "veris_mappings"
    filepath = f"{tmpdir}/{filename}"

    # ACT
    write_parsed_mappings_yaml(parsed_mappings, filepath)
    file = open(f"{filepath}.yaml", "r", encoding="UTF-8")
    result = yaml.safe_load(file)

    # ASSERT
    assert result == expected_veris_mapping_yaml


def test_veris_mappings_parser_csv(tmpdir):
    # ARRANGE
    filename = "veris_mappings"
    filepath = f"{tmpdir}/{filename}"
    parsed_mappings = veris_mappings_parser()
    veris_directory = "tests/expected_results/csv/veris"
    expected_attack_objects_file = open(
        f"{veris_directory}/expected_veris_results_attack_objects.csv",
        "r",
        encoding="UTF-8",
    )
    expected_metadata_file = open(
        f"{veris_directory}/expected_veris_results_metadata.csv", "r", encoding="UTF-8"
    )

    # ACT
    metadata_key = 0
    write_parsed_mappings_csv(parsed_mappings, filepath, metadata_key)
    attack_objects_file = open(f"{filepath}_attack_objects.csv", "r", encoding="UTF-8")
    metadata_file = open(f"{filepath}_metadata.csv", "r", encoding="UTF-8")

    # ASSERT
    assert expected_attack_objects_file.read() == attack_objects_file.read()
    assert expected_metadata_file.read() == metadata_file.read()


def test_veris_mappings_navigator_layer(tmpdir):
    # ARRANGE
    parsed_mappings = veris_mappings_parser()
    filename = "veris_mappings"
    filepath = f"{tmpdir}/{filename}"

    # ACT
    write_parsed_mappings_navigator_layer(parsed_mappings, filepath, "veris")
    file = open(f"{filepath}_navigator_layer.json", "r", encoding="UTF-8")
    result = json.load(file)

    # ASSERT
    assert result == expected_veris_navigator_layer


def test_cve_mappings_yaml(tmpdir):
    # ARRANGE
    parsed_mappings = yaml.dump(cve_mappings_parser())
    filename = "cve_mappings"
    filepath = f"{tmpdir}/{filename}"

    # ACT
    write_parsed_mappings_yaml(parsed_mappings, filepath)
    file = open(f"{filepath}.yaml", "r", encoding="UTF-8")
    result = yaml.safe_load(file)

    # ASSERT
    assert result == expected_cve_mapping_yaml


def test_cve_mappings_parser_csv(tmpdir):
    # ARRANGE
    filename = "cve_mappings"
    filepath = f"{tmpdir}/{filename}"
    parsed_mappings = cve_mappings_parser()
    cve_directory = "tests/expected_results/csv/cve"
    expected_attack_objects_file = open(
        f"{cve_directory}/expected_cve_results_attack_objects.csv",
        "r",
        encoding="UTF-8",
    )
    expected_metadata_file = open(
        f"{cve_directory}/expected_cve_results_metadata.csv", "r", encoding="UTF-8"
    )

    # ACT
    metadata_key = 0
    write_parsed_mappings_csv(parsed_mappings, filepath, metadata_key)
    attack_objects_file = open(f"{filepath}_attack_objects.csv", "r", encoding="UTF-8")
    metadata_file = open(f"{filepath}_metadata.csv", "r", encoding="UTF-8")

    # ASSERT
    assert expected_attack_objects_file.read() == attack_objects_file.read()
    assert expected_metadata_file.read() == metadata_file.read()


def test_cve_mappings_navigator_layer(tmpdir):
    # ARRANGE
    parsed_mappings = cve_mappings_parser()
    filename = "cve_mappings"
    filepath = f"{tmpdir}/{filename}"

    # ACT
    write_parsed_mappings_navigator_layer(parsed_mappings, filepath, "cve")
    file = open(f"{filepath}_navigator_layer.json", "r", encoding="UTF-8")
    result = yaml.safe_load(file)

    # ASSERT
    assert result == expected_cve_navigator_layer
