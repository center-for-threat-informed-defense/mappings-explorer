import json

import pandas as pd
import yaml


def get_filename_version_string(parsed_mappings):
    mapping_framework_version = parsed_mappings["metadata"]["mapping_framework_version"]
    mapping_framework_version_string = (
        f"-{mapping_framework_version}" if mapping_framework_version else ""
    )
    attack_version = parsed_mappings["metadata"]["attack_version"]
    return f"{mapping_framework_version_string}_attack-{attack_version}"


def write_parsed_mappings_yaml(parsed_mappings, filepath):
    parsed_mappings_yaml = yaml.dump(parsed_mappings)
    filename_version_string = get_filename_version_string(parsed_mappings)
    result_yaml_file = open(
        f"{filepath}{filename_version_string}.yaml",
        "w",
        encoding="UTF-8",
    )
    result_yaml_file.write(parsed_mappings_yaml)


def write_parsed_mappings_csv(parsed_mappings, filepath, metadata_key):
    # create filename
    filename_version_string = get_filename_version_string(parsed_mappings)
    attack_object_filename = f"{filename_version_string}_attack_objects"
    metadata_filename = f"{filename_version_string}_metadata"

    # create csv with metadata
    metadata_object = parsed_mappings["metadata"]
    metadata_object["key"] = metadata_key
    metadata_object["mappings_types"] = ",".join(metadata_object["mappings_types"])
    metadata_df = pd.DataFrame(metadata_object, index=[0])
    metadata_df.to_csv(f"{filepath}{metadata_filename}.csv")

    # create csv with attack objects
    attack_objects = parsed_mappings["attack_objects"]
    for attack_object in attack_objects:
        attack_object["metadata_key"] = metadata_key

    attack_object_df = pd.DataFrame(attack_objects)
    attack_object_df.to_csv(f"{filepath}{attack_object_filename}.csv")


def write_parsed_mappings_navigator_layer(parsed_mappings, filepath):
    filename_version_string = get_filename_version_string(parsed_mappings)
    techniques_dict = get_techniques_dict(parsed_mappings)
    mapping_type = parsed_mappings["metadata"]["mapping_framework"]
    layer = create_layer(techniques_dict, parsed_mappings, mapping_type)
    navigator_layer = open(
        f"{filepath}{filename_version_string}_navigator_layer.json",
        "w",
        encoding="UTF-8",
    )
    json.dump(layer, fp=navigator_layer)


def get_techniques_dict(parsed_mappings):
    techniques_dict = {}
    for mapping in parsed_mappings["attack_objects"]:
        tehchnique_id = mapping["attack_object_id"]
        capability_id = mapping["capability_id"]

        # add score metadata if it is a scoring mapping
        score_metadata = (
            "technique-scores" in parsed_mappings["metadata"]["mappings_types"]
        )

        if score_metadata:
            # define metadata objects
            metadata_control = {"name": "control", "value": mapping["capability_id"]}
            metadata_score_category = {
                "name": "category",
                "value": mapping["score_category"],
            }
            metadata_score_value = {"name": "value", "value": mapping["score_value"]}
            metadata_comment = {"name": "comment", "value": mapping["comments"]}
            divider = {"divider": True}

        if techniques_dict.get(tehchnique_id):
            # add capability information to technique it is mapped to
            techniques_dict[tehchnique_id]["capability_ids"].append(capability_id)
            if score_metadata:
                techniques_dict[tehchnique_id]["metadata"].extend(
                    [
                        metadata_control,
                        metadata_score_category,
                        metadata_score_value,
                        metadata_comment,
                        divider,
                    ]
                )
        else:
            # add capability information to technique it is mapped to
            techniques_dict[tehchnique_id] = {"capability_ids": [capability_id]}
            if score_metadata:
                techniques_dict[tehchnique_id]["metadata"] = [
                    metadata_control,
                    metadata_score_category,
                    metadata_score_value,
                    metadata_comment,
                    divider,
                ]
    return techniques_dict


def create_layer(techniques_dict, parsed_mappings, mapping_type):
    description = (
        f"{mapping_type} heatmap overview of {mapping_type} "
        "mappings, scores are the number of associated entries"
    )

    # this will change when there is only one metadata object per project
    mappings_metadata = parsed_mappings["metadata"]

    gradient = ["#ffe766", "#ffaf66"]
    layer = {
        "name": f"{mapping_type} overview",
        "versions": {
            "navigator": "4.8.0",
            "layer": "4.4",
            "attack": mappings_metadata["attack_version"],
        },
        "sorting": 3,
        "description": description,
        "domain": f"{mappings_metadata['technology_domain']}-attack",
        "techniques": [],
        "gradient": {
            "colors": gradient,
        },
    }
    for technique in techniques_dict:
        related_controls_string = ", ".join(
            techniques_dict[technique]["capability_ids"]
        )
        layer["techniques"].append(
            {
                "techniqueID": technique,
                "score": len(techniques_dict[technique]["capability_ids"]),
                "comment": f"Related to {related_controls_string}",
                "metadata": techniques_dict[technique]["metadata"],
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
