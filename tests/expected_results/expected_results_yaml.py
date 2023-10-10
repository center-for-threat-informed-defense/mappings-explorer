import yaml

from tests.expected_results.expected_results_json import (
    expected_cve_mapping_json,
    expected_nist_mapping_json,
    expected_security_stack_mapping_json,
    expected_veris_mapping_json,
)

expected_nist_mapping_yaml = yaml.dump(expected_nist_mapping_json)

expected_security_stack_mapping_yaml = yaml.dump(expected_security_stack_mapping_json)

expected_veris_mapping_yaml = yaml.dump(expected_veris_mapping_json)

expected_cve_mapping_yaml = yaml.dump(expected_cve_mapping_json)
