import json
import os

import yaml

from src.mappings_explorer.cli.cli import (
    configure_cve_mappings,
    configure_nist_mappings,
    configure_security_stack_mappings,
    configure_veris_mappings,
)
from src.mappings_explorer.cli.read_files import (
    read_csv_file,
    read_excel_file,
    read_json_file,
    read_yaml_file,
)
from src.mappings_explorer.cli.write_parsed_mappings import (
    write_parsed_mappings_csv,
    write_parsed_mappings_json,
    write_parsed_mappings_navigator_layer,
    write_parsed_mappings_yaml,
)
from tests.expected_results.expected_results_json import (
    expected_cve_mapping_json,
    expected_nist_mapping_json,
    expected_security_stack_mapping_json,
    expected_veris_mapping_json,
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


def nist_mappings_parser():
    filepath = os.path.join(os.path.dirname(__file__), "files/test_nist_mappings.xlsx")
    attack_version = "13.0"
    mappings_version = "1"
    dataframe = read_excel_file(filepath)
    parsed_mappings = configure_nist_mappings(
        dataframe, attack_version, mappings_version
    )
    return parsed_mappings


def test_nist_mappings_parser_yaml(tmpdir):
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
    assert result == expected_nist_mapping_json


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
    expected_mapping_platforms_file = open(
        f"{veris_directory}/expected_nist_results_mapping_platforms.csv",
        "r",
        encoding="UTF-8",
    )
    expected_metadata_file = open(
        f"{veris_directory}/expected_nist_results_metadata.csv", "r", encoding="UTF-8"
    )

    # ACT
    write_parsed_mappings_csv(parsed_mappings, filepath)
    attack_objects_file = open(f"{filepath}_attack-objects.csv", "r", encoding="UTF-8")
    mapping_platforms_file = open(
        f"{filepath}_mapping-platforms.csv", "r", encoding="UTF-8"
    )
    metadata_file = open(f"{filepath}_metadata.csv", "r", encoding="UTF-8")

    # ASSERT
    assert expected_attack_objects_file.read() == attack_objects_file.read()
    assert expected_mapping_platforms_file.read() == mapping_platforms_file.read()
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


def security_stack_mappings_parser(filepath):
    parsed_mappings = []
    for file in os.listdir(filepath):
        data = read_yaml_file(f"{filepath}/{file}")
        configure_security_stack_mappings(data, parsed_mappings)
    return parsed_mappings


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


def test_security_stack_mappings_csv(tmpdir):
    # ARRANGE
    root_filepath = os.path.join(os.path.dirname(__file__), "files/security_stack")
    security_stack_directory = "tests/expected_results/csv/security_stack"
    expected_attack_objects_file = open(
        f"{security_stack_directory}/expected_security_stack_results_attack_objects.csv",
        "r",
        encoding="UTF-8",
    )
    expected_mapping_platforms_file = open(
        f"{security_stack_directory}/expected_security_stack_results_mapping_platforms.csv",
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
        for directory in directories:
            print("DIRECTORY!", directory)
            # get parsed data
            filepath = f"{root_filepath}/{directory}"
            parsed_mappings = security_stack_mappings_parser(filepath)

            # write parsed data to file
            filename = f"security_stack_{directory}_mappings"
            tmpdir.mkdir(directory).join(filename)
            write_parsed_mappings_csv(parsed_mappings, filepath)
            attack_objects_file = open(
                f"{filepath}_attack-objects.csv", "r", encoding="UTF-8"
            )
            mapping_platforms_file = open(
                f"{filepath}_mapping-platforms.csv", "r", encoding="UTF-8"
            )
            metadata_file = open(f"{filepath}_metadata.csv", "r", encoding="UTF-8")

            # ASSERT
            assert expected_attack_objects_file.read() == attack_objects_file.read()
            assert (
                expected_mapping_platforms_file.read() == mapping_platforms_file.read()
            )
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


def veris_mappings_parser():
    filepath = os.path.join(os.path.dirname(__file__), "files/test_veris_mappings.json")
    veris_mappings = read_json_file(filepath)
    domain = "enterprise"
    parsed_mappings = configure_veris_mappings(veris_mappings, domain)
    return parsed_mappings


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
    expected_mapping_platforms_file = open(
        f"{veris_directory}/expected_veris_results_mapping_platforms.csv",
        "r",
        encoding="UTF-8",
    )
    expected_metadata_file = open(
        f"{veris_directory}/expected_veris_results_metadata.csv", "r", encoding="UTF-8"
    )

    # ACT
    write_parsed_mappings_csv(parsed_mappings, filepath)
    attack_objects_file = open(f"{filepath}_attack-objects.csv", "r", encoding="UTF-8")
    mapping_platforms_file = open(
        f"{filepath}_mapping-platforms.csv", "r", encoding="UTF-8"
    )
    metadata_file = open(f"{filepath}_metadata.csv", "r", encoding="UTF-8")

    # ASSERT
    assert expected_attack_objects_file.read() == attack_objects_file.read()
    assert expected_mapping_platforms_file.read() == mapping_platforms_file.read()
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


def cve_mappings_parser():
    filepath = os.path.join(os.path.dirname(__file__), "files/test_cve_mappings.csv")
    id_to_name_dict = {
        "T1059": {"name": "Name for T1059", "domain": "enterprise"},
        "T1190": {"name": "Name for T1190", "domain": "enterprise"},
        "T1078": {"name": "Name for T1078", "domain": "enterprise"},
        "T1068": {"name": "Name for T1068", "domain": "enterprise"},
    }
    cve_mappings = read_csv_file(filepath)
    parsed_mappings = configure_cve_mappings(cve_mappings, id_to_name_dict)
    return parsed_mappings


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
    expected_mapping_platforms_file = open(
        f"{cve_directory}/expected_cve_results_mapping_platforms.csv",
        "r",
        encoding="UTF-8",
    )
    expected_metadata_file = open(
        f"{cve_directory}/expected_cve_results_metadata.csv", "r", encoding="UTF-8"
    )

    # ACT
    write_parsed_mappings_csv(parsed_mappings, filepath)
    attack_objects_file = open(f"{filepath}_attack-objects.csv", "r", encoding="UTF-8")
    mapping_platforms_file = open(
        f"{filepath}_mapping-platforms.csv", "r", encoding="UTF-8"
    )
    metadata_file = open(f"{filepath}_metadata.csv", "r", encoding="UTF-8")

    # ASSERT
    assert expected_attack_objects_file.read() == attack_objects_file.read()
    assert expected_mapping_platforms_file.read() == mapping_platforms_file.read()
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
