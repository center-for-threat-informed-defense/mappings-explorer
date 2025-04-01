import json
import os

import yaml

root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
parsed_mappings_json_filepath = os.path.join(root_dir, "files/parsed_mappings.json")
with open(parsed_mappings_json_filepath, encoding="UTF-8") as user_file:
    mappings = user_file.read()
    expected_yaml_results = yaml.dump(json.loads(mappings))
