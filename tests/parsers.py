import os

from mappings_explorer.cli.mapex_convert.parse_cve_mappings import (
    configure_cve_mappings,
)
from mappings_explorer.cli.mapex_convert.parse_nist_mappings import (
    configure_nist_mappings,
)
from mappings_explorer.cli.mapex_convert.parse_security_stack_mappings import (
    configure_security_stack_mappings,
)
from mappings_explorer.cli.mapex_convert.parse_veris_mappings import (
    configure_veris_mappings,
)
from mappings_explorer.cli.mapex_convert.read_files import (
    read_csv_file,
    read_excel_file,
    read_json_file,
    read_yaml_file,
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


def security_stack_mappings_parser(filepath):
    parsed_mappings = {}
    for file in os.listdir(filepath):
        data = read_yaml_file(f"{filepath}/{file}")
        configure_security_stack_mappings(data, parsed_mappings)
    return parsed_mappings


def veris_mappings_parser():
    filepath = os.path.join(os.path.dirname(__file__), "files/test_veris_mappings.json")
    veris_mappings = read_json_file(filepath)
    domain = "enterprise"
    parsed_mappings = configure_veris_mappings(veris_mappings, domain)
    return parsed_mappings


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
