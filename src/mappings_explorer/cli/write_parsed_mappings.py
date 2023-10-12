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
    metadata_objects = []
    attack_objects = []
    mapping_platform_objects = []
    for index, mapping in enumerate(parsed_mappings):
        # metadata object
        metadata_object = mapping["metadata"]
        metadata_object["key"] = index
        metadata_objects.append(metadata_object)

        # attack object
        attack_object = mapping["attack-object"]
        attack_object["metadata-key"] = index
        attack_object["key"] = index
        # mapping platform will be its own table and will not be
        # part of attack_object
        exclude_keys = ["mapping-platform"]
        attack_object = {
            key: attack_object[key] for key in attack_object if key not in exclude_keys
        }
        attack_objects.append(attack_object)

        # mapping platform object
        mapping_platform_object = mapping["attack-object"]["mapping-platform"]
        mapping_platform_object["attack-object-key"] = index
        mapping_platform_objects.append(mapping_platform_object)

    metadata_df = pd.DataFrame(metadata_objects)
    metadata_df.to_csv(f"{filepath}_metadata.csv", columns=metadata_objects[0].keys())

    attack_object_df = pd.DataFrame(attack_objects)
    attack_object_df.to_csv(f"{filepath}_attack-objects.csv")

    mapping_platform_df = pd.DataFrame(mapping_platform_objects)
    mapping_platform_df.to_csv(f"{filepath}_mapping-platforms.csv")


def write_parsed_mappings_navigator_layer(parsed_mappings, filepath, mapping_type):
    techniques_dict = get_techniques_dict(parsed_mappings)
    layer = create_layer(techniques_dict, parsed_mappings, mapping_type)
    navigator_layer = open(
        f"{filepath}_navigator_layer.json",
        "w",
        encoding="UTF-8",
    )
    json.dump(layer, fp=navigator_layer)


def get_techniques_dict(parsed_mappings):
    techniques_dict = {}
    for mapping in parsed_mappings:
        tehchnique_id = mapping["attack-object"]["id"]
        mapping_target = mapping["attack-object"]["mapping-target"]
        if techniques_dict.get(tehchnique_id):
            techniques_dict[tehchnique_id].append(mapping_target)
        else:
            techniques_dict[tehchnique_id] = [mapping_target]
    return techniques_dict


def create_layer(techniques_dict, parsed_mappings, mapping_type):
    description = (
        f"{mapping_type} heatmap overview of {mapping_type} "
        "mappings, scores are the number of associated entries"
    )

    # this will change when there is only one metadata object per project
    mappings_metadata = parsed_mappings[0]["metadata"]

    gradient = ["#ffe766", "#ffaf66"]
    layer = {
        "name": f"{mapping_type} overview",
        "versions": {
            "navigator": "4.8.0",
            "layer": "4.4",
            "attack": mappings_metadata["attack-version"],
        },
        "sorting": 3,
        "description": description,
        "domain": f"{mappings_metadata['technology-domain']}-attack",
        "techniques": [],
        "gradient": {
            "colors": gradient,
        },
    }
    for technique in techniques_dict:
        related_controls_string = ",".join(techniques_dict[technique])
        layer["techniques"].append(
            {
                "techniqueID": technique,
                "score": len(techniques_dict[technique]),
                "comment": f"Related to {related_controls_string}",
            }
        )

    layer["gradient"]["minValue"] = (
        min(map(lambda t: t["score"], layer["techniques"]))
        if len(layer["techniques"]) > 0
        else 0
    )

    layer["gradient"]["maxValue"] = (
        max(map(lambda t: t["score"], layer["techniques"]))
        if len(layer["techniques"]) > 0
        else 100
    )

    return layer
