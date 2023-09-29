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
    read_yaml,
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
    filepath = os.path.join(
        os.path.dirname(__file__), "files/test_security_stack_mappings.yaml"
    )

    # ACT
    data = read_yaml(filepath)
    parsed_mappings = configure_security_stack_mappings(data)
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
    print("!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    print("RESULT", result)
    print("EXPECTED", expected_veris_mapping)
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
