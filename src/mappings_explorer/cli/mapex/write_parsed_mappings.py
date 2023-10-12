import json

import pandas as pd
import yaml


def write_parsed_mappings_yaml(parsed_mappings, filepath):
    parsed_mappings_yaml = yaml.dump(parsed_mappings)
    result_yaml_file = open(
        f"{filepath}.yaml",
        "w",
        encoding="UTF-8",
    )
    result_yaml_file.write(parsed_mappings_yaml)


def write_parsed_mappings_json(parsed_mappings, filepath):
    result_json_file = open(
        f"{filepath}.json",
        "w",
        encoding="UTF-8",
    )
    json.dump(parsed_mappings, fp=result_json_file)


def write_parsed_mappings_csv(parsed_mappings, filepath, metadata_key):
    # create csv with metadata
    metadata_object = parsed_mappings["metadata"]
    metadata_object["key"] = metadata_key
    metadata_object_df = pd.DataFrame(metadata_object, index=[0])
    metadata_object_df.to_csv(f"{filepath}_metadata-objects.csv")

    # create csv with attack objects
    attack_objects = parsed_mappings["attack-objects"]
    for attack_object in attack_objects:
        attack_object["metadata_key"] = metadata_key

    attack_object_df = pd.DataFrame(attack_objects)
    attack_object_df.to_csv(f"{filepath}_attack-objects.csv")
