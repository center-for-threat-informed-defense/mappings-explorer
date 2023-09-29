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


def write_parsed_mappings_csv(parsed_mappings, filepath):
    metatdata_objects = []
    attack_objects = []
    mapping_platform_objects = []
    for index, mapping in enumerate(parsed_mappings):
        # metadata object
        metadata_object = mapping["metadata"]
        metadata_object["key"] = index
        metatdata_objects.append(metadata_object)

        # attack object
        attack_object = mapping["attack-object"]
        attack_object["metadata-key"] = index
        attack_object["key"] = index
        # mapping platform will be its own table and will not be
        # part of attack_object
        exclude_keys = ["mapping-platform"]
        attack_object = {
            k: attack_object[k]
            for k in set(list(attack_object.keys())) - set(exclude_keys)
        }
        attack_objects.append(attack_object)

        # mapping platform object
        mapping_platform_object = mapping["attack-object"]["mapping-platform"]
        mapping_platform_object["attack-object-key"] = index
        mapping_platform_objects.append(mapping_platform_object)

    metadata_df = pd.DataFrame(metatdata_objects)
    metadata_df.to_csv(f"{filepath}_metadata.csv")

    attack_object_df = pd.DataFrame(attack_objects)
    attack_object_df.to_csv(f"{filepath}_attack-objects.csv")

    mapping_platform_df = pd.DataFrame(mapping_platform_objects)
    mapping_platform_df.to_csv(f"{filepath}_mapping-platforms.csv")
