import json
import uuid
from datetime import datetime

import pandas as pd
import requests
import yaml


def write_parsed_mappings_yaml(parsed_mappings, filepath):
    parsed_mappings_yaml = yaml.dump(parsed_mappings)
    result_yaml_file = open(
        f"{filepath}.yaml",
        "w",
        encoding="UTF-8",
    )
    result_yaml_file.write(parsed_mappings_yaml)


def write_parsed_mappings_csv(parsed_mappings, filepath, metadata_key):
    # create filename
    attack_object_filepath = f"{filepath}_attack_objects"
    metadata_filepath = f"{filepath}_metadata"

    # create csv with metadata
    metadata_object = parsed_mappings["metadata"]
    metadata_object["key"] = metadata_key
    metadata_object["mappings_types"] = ",".join(metadata_object["mappings_types"])
    metadata_df = pd.DataFrame(metadata_object, index=[0])
    metadata_df.to_csv(f"{metadata_filepath}.csv")

    # create csv with attack objects
    attack_objects = parsed_mappings["attack_objects"]
    for attack_object in attack_objects:
        attack_object["metadata_key"] = metadata_key

    attack_object_df = pd.DataFrame(attack_objects)
    attack_object_df.to_csv(f"{attack_object_filepath}.csv")


def write_parsed_mappings_navigator_layer(parsed_mappings, filepath):
    techniques_dict = get_techniques_dict(parsed_mappings)
    mapping_type = parsed_mappings["metadata"]["mapping_framework"]
    layer = create_layer(techniques_dict, parsed_mappings, mapping_type)
    navigator_layer = open(
        f"{filepath}_navigator_layer.json",
        "w",
        encoding="UTF-8",
    )
    json.dump(layer, fp=navigator_layer)


def write_parsed_mappings_stix(parsed_mappings, filepath):
    # create bundle
    bundle_uuid = str(uuid.uuid4())
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{bundle_uuid}",
        "spec_version": "2.1",
        "created": datetime.now().isoformat(),
        "modified": datetime.now().isoformat(),
        "objects": [],
    }
    technique_target_dict = load_attack_json(parsed_mappings)

    for mapping in parsed_mappings["attack_objects"]:
        # create SDO for each capability
        if not any(
            stix_object.get("name") == mapping["capability_id"]
            for stix_object in stix_bundle["objects"]
        ):
            stix_object = get_stix_object(parsed_mappings, mapping)
            stix_bundle["objects"].append(stix_object)

        # add attack pattern SDO for each technique/subtechnique
        relationship_uuid = str(uuid.uuid4())
        related_source_ref = [
            stix_object["id"]
            for stix_object in stix_bundle["objects"]
            if stix_object.get("name") == mapping["capability_id"]
        ][0]
        stix_bundle["objects"].append(
            {
                "type": "relationship",
                "id": f"relationship--{relationship_uuid}",
                "spec_version": "2.1",
                "created": datetime.now().isoformat(),
                "modified": datetime.now().isoformat(),
                "relationship_type": mapping["mapping_type"].replace("_", "-"),
                "source_ref": related_source_ref,
                "target_ref": technique_target_dict.get(
                    mapping["attack_object_id"], ""
                ),
            },
        )

    stix_file = open(
        f"{filepath}_stix.json",
        "w",
        encoding="UTF-8",
    )
    json.dump(stix_bundle, fp=stix_file)


def get_stix_object(parsed_mappings, mapping):
    mapping_framwork = parsed_mappings["metadata"]["mapping_framework"]
    infrastructure_frameworks = ["nist_800_53", "aws", "gcp", "azure"]
    if mapping_framwork == "cve":
        return create_vulnerability_object(mapping)
    elif mapping_framwork in infrastructure_frameworks:
        return create_infrastructure_object(mapping)
    elif mapping_framwork == "veris":
        return create_attack_pattern_object(mapping)


def create_vulnerability_object(mapping):
    vulnerability_uuid = str(uuid.uuid4())
    return {
        "type": "vulnerability",
        "id": f"vulnerability--{vulnerability_uuid}",
        "spec_version": "2.1",
        "created": datetime.now().isoformat(),
        "modified": datetime.now().isoformat(),
        "name": mapping["capability_id"],
        "description": mapping["capability_description"],
        "external_references": [
            {
                "url": f"https://nvd.nist.gov/vuln/detail/{mapping['capability_id']}",
                "source_name": "cve",
                "external_id": mapping["capability_id"],
            }
        ],
    }


def create_infrastructure_object(mapping):
    infrastructure_uuid = str(uuid.uuid4())
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": f"infrastructure--{infrastructure_uuid}",
        "name": mapping["capability_id"],
        "created": datetime.now().isoformat(),
        "modified": datetime.now().isoformat(),
    }


def create_attack_pattern_object(mapping):
    attack_pattern_uuid = str(uuid.uuid4())
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": f"attack-pattern--{attack_pattern_uuid}",
        "name": mapping["capability_id"],
        "created": datetime.now().isoformat(),
        "modified": datetime.now().isoformat(),
    }


def load_attack_json(parsed_mappings):
    BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"

    # load enterprise attack stix json to map technique ids to names
    attack_version = parsed_mappings["metadata"]["attack_version"]

    if "." not in attack_version:
        attack_version = attack_version + ".0"

    enterpise_attack_url = (
        f"{BASE_URL}/enterprise-attack/enterprise-attack-{attack_version}.json"
    )

    response = requests.get(enterpise_attack_url)
    enterprise_attack_data = json.loads(response.text)

    # load mobile attack stix json to map technique ids to names
    enterpise_attack_url = (
        f"{BASE_URL}/mobile-attack/mobile-attack-{attack_version}.json"
    )
    response = requests.get(enterpise_attack_url)
    mobile_attack_data = json.loads(response.text)

    # load ics attack stix json to map technique ids to names
    enterpise_attack_url = f"{BASE_URL}/ics-attack/ics-attack-{attack_version}.json"
    response = requests.get(enterpise_attack_url)
    ics_attack_data = json.loads(response.text)

    domain_data = [enterprise_attack_data, mobile_attack_data, ics_attack_data]

    attack_object_id_to_name = {}
    for domain in domain_data:
        for attack_object in domain["objects"]:
            if not domain["type"] == "relationship":
                # skip objects without IDs
                if not attack_object.get("external_references"):
                    continue
                # skip deprecated and revoked objects
                # Note: False is the default value if the property is not present
                if attack_object.get("revoked", False):
                    continue
                # Note: False is the default value if the property is not present
                if attack_object.get("x_mitre_deprecated", False):
                    continue
                # map attackID to stixID
                if attack_object["external_references"][0].get(
                    "external_id"
                ) and attack_object.get("name"):
                    attack_object_id_to_name[
                        attack_object["external_references"][0]["external_id"]
                    ] = attack_object["id"]

    return attack_object_id_to_name


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
                "metadata": techniques_dict[technique].get("metadata", []),
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
