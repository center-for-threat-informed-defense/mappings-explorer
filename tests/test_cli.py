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
from tests.expected_results import (
    expected_cve_mapping,
    expected_nist_mapping,
    expected_security_stack_mapping,
    expected_veris_mapping,
)


def test_nist_mappings_parser():
    # ARRANGE
    filepath = os.path.join(os.path.dirname(__file__), "files/test_nist_mappings.xlsx")
    attack_version = "13.0"
    mappings_version = "1"

    # ACT
    dataframe = read_excel_file(filepath)
    parsed_mappings = configure_nist_mappings(
        dataframe, attack_version, mappings_version
    )
    result = yaml.dump(parsed_mappings)

    # ASSERT
    assert result == expected_nist_mapping


def test_security_stack_mappings():
    # ARRANGE
    root_filepath = os.path.join(os.path.dirname(__file__), "files/security_stack")

    # ACT
    # read in all files in SecurityStack directory
    for _, directories, _ in os.walk(root_filepath):
        for directory in directories:
            parsed_mappings = []
            for file in os.listdir(f"{root_filepath}/{directory}"):
                filepath = f"{root_filepath}/{directory}/{file}"
                data = read_yaml_file(filepath)
                configure_security_stack_mappings(data, parsed_mappings)
        result = yaml.dump(parsed_mappings)

        # ASSERT
        assert result == expected_security_stack_mapping


def test_veris_mappings():
    # ARRANGE
    filepath = os.path.join(os.path.dirname(__file__), "files/test_veris_mappings.json")

    # ACT
    veris_mappings = read_json_file(filepath)
    domain = "enterprise"
    parsed_mappings = configure_veris_mappings(veris_mappings, domain)
    result = yaml.dump(parsed_mappings)

    # ASSERT
    assert result == expected_veris_mapping


def test_cve_mappings():
    # ARRANGE
    filepath = os.path.join(os.path.dirname(__file__), "files/test_cve_mappings.csv")
    id_to_name_dict = {
        "T1059": {"name": "Name for T1059", "domain": "enterprise"},
        "T1190": {"name": "Name for T1190", "domain": "enterprise"},
        "T1078": {"name": "Name for T1078", "domain": "enterprise"},
        "T1068": {"name": "Name for T1068", "domain": "enterprise"},
    }

    # ACT
    cve_mappings = read_csv_file(filepath)
    parsed_mappings = configure_cve_mappings(cve_mappings, id_to_name_dict)
    result = yaml.dump(parsed_mappings)

    # ASSERT
    assert result == expected_cve_mapping


# def test_parse_yaml_to_json():
#     # ARRANGE
#     yaml = expected_cve_mapping


#     # ACT

#     # ASSERT

# def test_parse_yaml_to_csv():
