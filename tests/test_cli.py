import os
import yaml
from tests.expected_results import (
    expected_nist_mapping,
    expected_security_stack_mapping,
    expected_veris_mapping
)
from src.mappings_explorer.cli.cli import (
    configure_nist_mappings,
    configure_security_stack_mappings,
    configure_veris_mappings,
    read_excel_file,
    read_json_file,
    read_yaml,
)

def test_nist_mappings_parser():
    # ARRANGE
    filepath = os.path.join(os.path.dirname(__file__), 'files/test_nist_mappings.xlsx')
    attack_version = '13.0'
    mappings_version = '1'
    expected = expected_nist_mapping

    # ACT
    dataframe = read_excel_file(filepath)
    parsed_mappings = []
    parsed_mappings = configure_nist_mappings(
        dataframe,
        parsed_mappings,
        attack_version,
        mappings_version
    )
    result = yaml.dump(parsed_mappings)

    # ASSERT
    assert result == expected


def test_security_stack_mappings():
    # ARRANGE
    filepath = os.path.join(os.path.dirname(__file__), 'files/test_security_stack_mappings.yaml')
    expected = expected_security_stack_mapping

    # ACT
    data = read_yaml(filepath)
    parsed_mappings = []
    parsed_mappings = configure_security_stack_mappings(data, parsed_mappings)
    result = yaml.dump(parsed_mappings)

    # ASSERT
    assert result == expected


def test_veris_mappings():
    # ARRANGE
    filepath = os.path.join(os.path.dirname(__file__), 'files/test_veris_mappings.json')
    expected = expected_veris_mapping

    # ACT
    parsed_mappings = []
    veris_mappings = read_json_file(filepath)
    parsed_mappings = configure_veris_mappings(veris_mappings, parsed_mappings)
    result = yaml.dump(parsed_mappings)

    # ASSERT
    assert result == expected
