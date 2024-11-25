import json
import os
import sys
import uuid
from datetime import datetime, timezone

import pandas as pd
import requests
import yaml
from loguru import logger
from stix2validator import print_results, validate_instance


def write_parsed_mappings_json(parsed_mappings, filepath):
    filepath = f"{filepath}_json"
    filepath_with_count = filepath
    counter = 0
    while os.path.exists(f"{filepath_with_count}.json"):
        counter += 1
        filepath_with_count = f"{filepath}_{counter}"

    json_file = open(
        f"{filepath_with_count}.json",
        "w",
        encoding="UTF-8",
    )
    json.dump(parsed_mappings, fp=json_file)
    logger.info(
        "Successfully wrote mappings json file to {filepath_with_count}_json.json",
        filepath_with_count=filepath_with_count,
    )


def write_parsed_mappings_yaml(parsed_mappings, filepath):
    parsed_mappings_yaml = yaml.dump(parsed_mappings)
    filepath_with_count = filepath
    counter = 0
    while os.path.exists(f"{filepath_with_count}.yaml"):
        counter += 1
        filepath_with_count = f"{filepath}_{counter}"
    result_yaml_file = open(
        f"{filepath_with_count}.yaml",
        "w",
        encoding="UTF-8",
    )
    result_yaml_file.write(parsed_mappings_yaml)
    logger.info(
        "Successfully wrote mappings yaml file to {filepath_with_count}.yaml",
        filepath_with_count=filepath_with_count,
    )


def create_df(parsed_mappings):
    # create csv with attack objects
    mapping_objects = parsed_mappings["mapping_objects"]
    for mapping_object in mapping_objects:
        # add metadata fields to attack object
        columns_from_metadata = [
            "organization",
            "creation_date",
            "last_update",
            "attack_version",
            "technology_domain",
            "mapping_framework",
            "mapping_framework_version",
        ]
        for column in columns_from_metadata:
            mapping_object[column] = parsed_mappings["metadata"][column]

        # get mapping type name based on id
        # account for None value of mapping_type in not_mappable items
        mapping_types_objects = parsed_mappings["metadata"]["mapping_types"]
        mapping_type_name = (
            [
                mapping_types_objects[mapping_type]["name"]
                for mapping_type in mapping_types_objects
                if mapping_type == mapping_object["mapping_type"]
            ][0]
            if mapping_object["mapping_type"]
            and mapping_object["mapping_type"] != "non_mappable"
            else (
                "non_mappable"
                if mapping_object["mapping_type"] == "non_mappable"
                else None
            )
        )

        # get group name based on id
        capability_group_objects = parsed_mappings["metadata"]["capability_groups"]
        capability_group_name = [
            capability_group_objects[capability_group]
            for capability_group in capability_group_objects
            if capability_group == mapping_object["capability_group"]
        ]

        if len(capability_group_name):
            capability_group_name = capability_group_name[0]

        else:
            capability_group_name = None

        # swap mapping_type id and group id with mapping_type name and group name
        mapping_object["mapping_type"] = mapping_type_name
        mapping_object["capability_group"] = capability_group_name

    columns_order = [
        "mapping_framework",
        "mapping_framework_version",
        "capability_group",
        "capability_id",
        "capability_description",
        "mapping_type",
        "attack_object_id",
        "attack_object_name",
        "attack_version",
        "technology_domain",
        "score_category",
        "score_value",
        "related_score",
        "references",
        "comments",
        "organization",
        "creation_date",
        "last_update",
    ]

    return pd.DataFrame(data=mapping_objects, columns=columns_order)


def write_parsed_mappings_csv(df, filepath):
    filepath_with_count = filepath
    counter = 0
    while os.path.exists(f"{filepath_with_count}.csv"):
        counter += 1
        filepath_with_count = f"{filepath}_{counter}"
    df.to_csv(f"{filepath_with_count}.csv")
    logger.info(
        "Successfully wrote mappings csv file to {filepath_with_count}.csv",
        filepath_with_count=filepath_with_count,
    )


def write_parsed_mappings_excel(df, filepath):
    filepath_with_count = filepath
    counter = 0
    while os.path.exists(f"{filepath_with_count}.xlsx"):
        counter += 1
        filepath_with_count = f"{filepath}_{counter}"
    df.to_excel(f"{filepath_with_count}.xlsx", index=False)
    logger.info(
        "Successfully wrote mappings excel file to {filepath_with_count}.xlsx",
        filepath_with_count=filepath_with_count,
    )


def write_parsed_mappings_navigator_layer(parsed_mappings, filepath):
    techniques_dict = get_techniques_dict(parsed_mappings["mapping_objects"])
    mapping_type = parsed_mappings["metadata"]["mapping_framework"]
    domain = parsed_mappings["metadata"]["technology_domain"]
    attack_version = parsed_mappings["metadata"]["attack_version"]
    layer = create_layer(techniques_dict, mapping_type, domain, attack_version)
    filepath = f"{filepath}_navigator_layer"
    filepath_with_count = filepath
    counter = 0
    while os.path.exists(f"{filepath_with_count}.json"):
        counter += 1
        filepath_with_count = f"{filepath}_{counter}"
    navigator_layer = open(
        f"{filepath_with_count}.json",
        "w",
        encoding="UTF-8",
    )
    json.dump(layer, fp=navigator_layer)
    logger.info(
        "Successfully wrote navigator layer file to {filepath_with_count}.json",
        filepath_with_count=filepath_with_count,
    )


def write_parsed_mappings_stix(parsed_mappings, filepath):
    created_date = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    # create bundle
    bundle_uuid = str(uuid.uuid4())
    stix_bundle = {
        "type": "bundle",
        "id": f"bundle--{bundle_uuid}",
        "spec_version": "2.1",
        "created": created_date,
        "modified": created_date,
        "objects": [],
    }
    technique_target_dict = load_attack_json(parsed_mappings)
    for mapping in parsed_mappings["mapping_objects"]:
        # create SDO for each capability
        if (
            not any(
                stix_object.get("name") == mapping["capability_id"]
                for stix_object in stix_bundle["objects"]
            )
            and mapping["capability_id"]
        ):
            stix_object = get_stix_object(parsed_mappings, mapping, created_date)
            stix_bundle["objects"].append(stix_object)

        # add attack pattern SDO for each technique/subtechnique
        relationship_uuid = str(uuid.uuid4())
        related_source_ref = [
            stix_object["id"]
            for stix_object in stix_bundle["objects"]
            if stix_object.get("name") == mapping["capability_id"]
            and mapping["capability_id"]
        ]
        related_target_ref = technique_target_dict.get(mapping["attack_object_id"], "")

        # account for None mapping_type on not_mappable items
        mapping_type = (
            mapping["mapping_type"].replace("_", "-")
            if mapping["mapping_type"]
            else None
        )
        # do not add a relationship node for a non-mappable technique
        if related_source_ref and related_target_ref:
            stix_bundle["objects"].append(
                {
                    "type": "relationship",
                    "id": f"relationship--{relationship_uuid}",
                    "spec_version": "2.1",
                    "created": created_date,
                    "modified": created_date,
                    "relationship_type": mapping_type,
                    "source_ref": related_source_ref[0],
                    "target_ref": related_target_ref,
                },
            )
    # only write to file if stix is valid
    validation_results = validate_instance(stix_bundle)
    if validation_results.is_valid:
        filepath = f"{filepath}_stix"
        filepath_with_count = filepath
        counter = 0
        while os.path.exists(f"{filepath_with_count}.json"):
            counter += 1
            filepath_with_count = f"{filepath}_{counter}"
        stix_file = open(
            f"{filepath_with_count}.json",
            "w",
            encoding="UTF-8",
        )
        json.dump(stix_bundle, fp=stix_file)
        logger.info(
            "Successfully wrote mappings stix file to {filepath_with_count}.json",
            filepath_with_count=filepath_with_count,
        )
    else:
        logger.error(
            "Invalid STIX generated for {filepath}_json.json",
            filepath=filepath,
        )
        print_results(validation_results)
        sys.exit(1)


def get_stix_object(parsed_mappings, mapping, created_date):
    mapping_framwork = parsed_mappings["metadata"]["mapping_framework"]
    infrastructure_frameworks = [
        "nist_800_53",
        "aws",
        "gcp",
        "azure",
        "m365",
        "intel-vpro",
    ]
    if mapping_framwork == "cve" or mapping_framwork == "kev":
        return create_vulnerability_object(mapping, created_date)
    elif mapping_framwork in infrastructure_frameworks:
        return create_infrastructure_object(mapping, created_date)
    elif mapping_framwork == "veris":
        return create_attack_pattern_object(mapping, created_date)
    else:
        logger.warning(
            "Cannot create STIX export for mappings with unrecognized mapping framework"
        )


def create_vulnerability_object(mapping, created_date):
    vulnerability_uuid = str(uuid.uuid4())
    return {
        "type": "vulnerability",
        "id": f"vulnerability--{vulnerability_uuid}",
        "spec_version": "2.1",
        "created": created_date,
        "modified": created_date,
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


def create_infrastructure_object(mapping, created_date):
    infrastructure_uuid = str(uuid.uuid4())
    return {
        "type": "infrastructure",
        "spec_version": "2.1",
        "id": f"infrastructure--{infrastructure_uuid}",
        "name": mapping["capability_id"],
        "created": created_date,
        "modified": created_date,
    }


def create_attack_pattern_object(mapping, created_date):
    attack_pattern_uuid = str(uuid.uuid4())
    return {
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": f"attack-pattern--{attack_pattern_uuid}",
        "name": mapping["capability_id"],
        "created": created_date,
        "modified": created_date,
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


def get_techniques_dict(mapping_objects):
    techniques_dict = {}
    for mapping in mapping_objects:
        technique_id = mapping["attack_object_id"]
        capability_id = mapping["capability_id"]

        # define metadata
        metadata = []
        if mapping.get("score_category"):
            metadata.append(
                {
                    "name": "category",
                    "value": mapping["score_category"],
                }
            )

        if mapping.get("score_value"):
            metadata.append({"name": "value", "value": mapping["score_value"]})

        if mapping.get("comments"):
            metadata.append({"name": "comment", "value": mapping["comments"]})

        if techniques_dict.get(technique_id) is None:
            techniques_dict[technique_id] = {
                "capability_ids": {capability_id},
                "metadata": [],
            }

        technique = techniques_dict[technique_id]

        # Add Capability ID
        technique["capability_ids"].add(capability_id)

        # Add Metadata
        metadata_info = []
        if len(metadata) > 0:
            metadata_info.extend(
                [
                    {"divider": True},
                    {"name": "control", "value": mapping["capability_id"]},
                ]
            )
            metadata_info.extend(metadata)

        # No need to check if metadata_info is empty
        technique["metadata"].extend(metadata_info)

    return techniques_dict


def create_layer(techniques_dict, layer_title, domain, attack_version):
    description = (
        f"{layer_title} heatmap overview of {layer_title} "
        "mappings, scores are the number of associated entries"
    )

    gradient = ["#ffe766", "#ffaf66"]
    layer = {
        "name": f"{layer_title} overview",
        "versions": {
            "navigator": "4.8.0",
            "layer": "4.4",
            "attack": attack_version,
        },
        "sorting": 3,
        "description": description,
        "domain": f"{domain}-attack",
        "techniques": [],
        "gradient": {
            "colors": gradient,
        },
    }
    for technique in techniques_dict:
        capability_ids = [
            capability_id
            for capability_id in techniques_dict[technique]["capability_ids"]
            if capability_id
        ]

        related_controls_string = ""
        if len(capability_ids):
            # formats ids in a bulleted list
            related_controls_string = "\u2022" + "\n\u2022".join(capability_ids)

        layer["techniques"].append(
            {
                "techniqueID": technique,
                "score": len(techniques_dict[technique]["capability_ids"]),
                "comment": f" Related to: \n {related_controls_string}",
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
