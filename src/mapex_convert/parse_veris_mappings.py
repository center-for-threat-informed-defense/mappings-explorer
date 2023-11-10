import os
import uuid

import pandas as pd


def configure_veris_mappings(veris_mappings, domain):
    mappings_framework_version = veris_mappings["metadata"]["veris_version"]
    description_dict = create_description_dict(mappings_framework_version)

    mapping_types = [{"id": str(uuid.uuid4()), "name": "related-to", "description": ""}]
    parsed_mappings = {
        "metadata": {
            "mapping_version": veris_mappings["metadata"]["mappings_version"],
            "attack_version": veris_mappings["metadata"]["attack_version"],
            # this is an assumption that all cve mappings are enterprise
            # this assumption is not currently true
            # need to clarify how we will handle non-enterprise cve mappings
            "technology_domain": domain,
            "author": "",
            "contact": "",
            # confirm creation-data value is correct
            "creation_date": "02/03/2021",
            # confirm last-update value is correct
            "last_update": "10/27/2021",
            "organization": "",
            "mapping_framework": "veris",
            "mapping_framework_version": mappings_framework_version,
            "mapping_types": mapping_types,
            "groups": [],
        },
        "mapping_objects": [],
    }

    groups = []
    for attack_object in veris_mappings["attack_to_veris"]:
        mapped_attack_object = veris_mappings["attack_to_veris"][attack_object]
        for veris_object in mapped_attack_object["veris"]:
            # if veris object is missing one of the sections, replace extra '.""'
            veris_object = veris_object.replace('.""', "")

            mapping_type_uuid = list(
                filter(
                    lambda mapping_type_object: mapping_type_object["name"]
                    == "related-to",
                    mapping_types,
                )
            )[0]["id"]

            # get group id and anme
            veris_group = veris_object[
                : veris_object.index(".", veris_object.index(".") + 1)
            ]
            if not any(group["id"] == veris_group for group in groups):
                groups.append({"id": veris_group, "name": veris_group})

            parsed_mappings["mapping_objects"].append(
                {
                    "comments": "",
                    "attack_object_id": attack_object,
                    "attack_object_name": mapped_attack_object["name"],
                    "references": [],
                    "capability_description": description_dict[veris_object],
                    "capability_id": veris_object,
                    "mapping_type": mapping_type_uuid,
                    "group": veris_group,
                }
            )

    parsed_mappings["metadata"]["groups"] = groups
    return parsed_mappings


def create_description_dict(mappings_version):
    ROOT_DIR = os.path.abspath(os.curdir)
    enumerations_filepath = ROOT_DIR + "/src/mapex_convert/mappings/Veris/enumerations"
    if mappings_version == "1.3.5":
        filepath = f"{enumerations_filepath}/veris135-enumerations.csv"
    elif mappings_version == "1.3.7":
        filepath = f"{enumerations_filepath}/veris1_3_7-enumerations-groups.csv"

    df = pd.read_csv(filepath)

    description_dict = {}
    # if any of df cells have no value, fill with an empty string
    df = df.fillna("")
    for _, row in df.iterrows():
        path = f"{row['AXES']}.{row['CATEGORY']}.{row['SUB CATEGORY']}.{row['VALUE']}"
        # if any of the veris paths do not have all sections, remove the extra '.'
        path = path.replace("..", ".")
        description_dict[path] = row["DESCRIPTION"]

    return description_dict
