import yaml

from tests.expected_results.expected_results_json import (
    expected_nist_mapping_json,
)

expected_yaml_results = yaml.dump(expected_nist_mapping_json)
