import json
import os

from mapex.write_parsed_mappings import (
    get_filename_version_string,
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
    parsed_mappings = nist_mappings_parser()
    filepath = f"{tmpdir}/nist"

    # ACT
    write_parsed_mappings_yaml(parsed_mappings, filepath)
    file = open(f"{filepath}_attack-13.0.yaml", "r", encoding="UTF-8")
    result = file.read()

    # ASSERT
    assert result == expected_nist_mapping_yaml


def test_nist_mappings_parser_csv(tmpdir):
    # ARRANGE
    filepath = f"{tmpdir}/nist"
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
    filename = "nist"
    filepath = f"{tmpdir}/{filename}"
    parsed_mappings = nist_mappings_parser()

    # ACT
    write_parsed_mappings_navigator_layer(parsed_mappings, filepath, "nist")
    version_string = get_filename_version_string(parsed_mappings)
    file = open(
        f"{filepath}{version_string}_navigator_layer.json", "r", encoding="UTF-8"
    )
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
            parsed_mappings = security_stack_mappings_parser(filepath)

            # write parsed data to file
            filename = f"security_stack_{directory}"
            tmpdir.mkdir(directory).join(filename)
            output_filepath = f"{tmpdir}/{directory}/{filename}"
            write_parsed_mappings_yaml(parsed_mappings, output_filepath)
            version_string = get_filename_version_string(parsed_mappings)
            file = open(
                f"{output_filepath}{version_string}.yaml", "r", encoding="UTF-8"
            )
            result = file.read()

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
            output_filepath = f"{tmpdir}/{directory}/{filename}"
            write_parsed_mappings_csv(parsed_mappings, output_filepath, metadata_key)
            metadata_key += 1
            version_string = get_filename_version_string(parsed_mappings)
            attack_objects_file = open(
                f"{output_filepath}{version_string}_attack_objects.csv",
                "r",
                encoding="UTF-8",
            )
            metadata_file = open(
                f"{output_filepath}{version_string}_metadata.csv", "r", encoding="UTF-8"
            )

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
            version_string = get_filename_version_string(parsed_mappings)
            file = open(
                f"{output_filepath}{version_string}_navigator_layer.json",
                "r",
                encoding="UTF-8",
            )
            result = json.load(file)

            # ASSERT
            assert result == expected_security_stack_navigator_layer


def test_veris_mappings_yaml(tmpdir):
    # ARRANGE
    parsed_mappings = veris_mappings_parser()
    filename = "veris_mappings"
    filepath = f"{tmpdir}/{filename}"

    # ACT
    write_parsed_mappings_yaml(parsed_mappings, filepath)
    version_string = get_filename_version_string(parsed_mappings)
    file = open(f"{filepath}{version_string}.yaml", "r", encoding="UTF-8")
    result = file.read()

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
    version_string = get_filename_version_string(parsed_mappings)
    attack_objects_file = open(
        f"{filepath}{version_string}_attack_objects.csv", "r", encoding="UTF-8"
    )
    metadata_file = open(
        f"{filepath}{version_string}_metadata.csv", "r", encoding="UTF-8"
    )

    # ASSERT
    assert expected_attack_objects_file.read() == attack_objects_file.read()
    assert expected_metadata_file.read() == metadata_file.read()


def test_veris_mappings_navigator_layer(tmpdir):
    # ARRANGE
    parsed_mappings = veris_mappings_parser()
    filename = "veris"
    filepath = f"{tmpdir}/{filename}"

    # ACT
    write_parsed_mappings_navigator_layer(parsed_mappings, filepath, "veris")
    version_string = get_filename_version_string(parsed_mappings)
    file = open(
        f"{filepath}{version_string}_navigator_layer.json", "r", encoding="UTF-8"
    )
    result = json.load(file)

    # ASSERT
    assert result == expected_veris_navigator_layer


def test_cve_mappings_yaml(tmpdir):
    # ARRANGE
    parsed_mappings = cve_mappings_parser()
    filename = "cve"
    filepath = f"{tmpdir}/{filename}"

    # ACT
    write_parsed_mappings_yaml(parsed_mappings, filepath)
    version_string = get_filename_version_string(parsed_mappings)
    file = open(f"{filepath}{version_string}.yaml", "r", encoding="UTF-8")
    result = file.read()

    # ASSERT
    assert result == expected_cve_mapping_yaml


def test_cve_mappings_parser_csv(tmpdir):
    # ARRANGE
    filename = "cve"
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
    version_string = get_filename_version_string(parsed_mappings)
    attack_objects_file = open(
        f"{filepath}{version_string}_attack_objects.csv", "r", encoding="UTF-8"
    )
    metadata_file = open(
        f"{filepath}{version_string}_metadata.csv", "r", encoding="UTF-8"
    )

    # ASSERT
    assert expected_attack_objects_file.read() == attack_objects_file.read()
    assert expected_metadata_file.read() == metadata_file.read()


def test_cve_mappings_navigator_layer(tmpdir):
    # ARRANGE
    parsed_mappings = cve_mappings_parser()
    filename = "cve"
    filepath = f"{tmpdir}/{filename}"

    # ACT
    write_parsed_mappings_navigator_layer(parsed_mappings, filepath, "cve")
    version_string = get_filename_version_string(parsed_mappings)
    file = open(
        f"{filepath}{version_string}_navigator_layer.json", "r", encoding="UTF-8"
    )
    result = json.load(file)

    # ASSERT
    assert result == expected_cve_navigator_layer
