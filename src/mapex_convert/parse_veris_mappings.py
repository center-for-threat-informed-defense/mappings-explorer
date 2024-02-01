import os

import pandas as pd
from pathlib import Path
from loguru import logger
from mapex_convert.read_files import read_csv_file

ROOT_DIR = Path(os.path.abspath(os.curdir))


def configure_veris_mappings(veris_mappings, domain):
    mappings_framework_version = veris_mappings["metadata"]["veris_version"]
    description_dict = create_description_dict(mappings_framework_version)
    creation_date = (
        "08/26/2021" if mappings_framework_version == "1.3.5" else "04/06/2023"
    )
    mapping_types = {"related_to": {"name": "related-to", "description": ""}}
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
            "creation_date": creation_date,
            # confirm last-update value is correct
            "last_update": creation_date,
            "organization": "",
            "mapping_framework": "veris",
            "mapping_framework_version": mappings_framework_version,
            "mapping_types": mapping_types,
            "capability_groups": {},
        },
        "mapping_objects": [],
    }

    capability_groups = {}
    for attack_object in veris_mappings["attack_to_veris"]:
        mapped_attack_object = veris_mappings["attack_to_veris"][attack_object]
        for veris_object in mapped_attack_object["veris"]:
            # if veris object is missing one of the sections, replace extra '.""'
            veris_object = veris_object.replace('.""', "")
            mapping_type_id = [
                mapping_type
                for mapping_type in mapping_types
                if mapping_types[mapping_type]["name"] == "related-to"
            ][0]

            # get capability group id and anme
            veris_group = veris_object[
                : veris_object.index(".", veris_object.index(".") + 1)
            ].replace(" ", "_")
            if veris_group not in capability_groups:
                capability_groups[veris_group] = veris_group

            parsed_mappings["mapping_objects"].append(
                {
                    "comments": "",
                    "attack_object_id": attack_object,
                    "attack_object_name": mapped_attack_object["name"],
                    "references": [],
                    "capability_description": description_dict[veris_object.lower()],
                    "capability_id": veris_object,
                    "mapping_type": mapping_type_id,
                    "capability_group": veris_group,
                    "status": "complete",
                }
            )
    non_mappables = get_non_mappables(domain, mappings_framework_version)
    for veris_object in non_mappables:
        veris_group = (
            veris_object[: veris_object.index(".", veris_object.index(".") + 1)]
            .replace(" ", "_")
            .lower()
        )
        if veris_group not in capability_groups:
            capability_groups[veris_group] = veris_group
        parsed_mappings["mapping_objects"].append(
            {
                "comments": "",
                "attack_object_id": None,
                "attack_object_name": None,
                "references": None,
                "capability_description": description_dict[veris_object.lower()]
                if description_dict.get(veris_object)
                else "",
                "capability_id": veris_object,
                "mapping_type": None,
                "capability_group": veris_group,
                "status": "complete",
            }
        )

    parsed_mappings["metadata"]["capability_groups"] = capability_groups
    return parsed_mappings


def create_description_dict(mappings_version):
    enumerations_filepath = ROOT_DIR / "src/mapex_convert/mappings/Veris/enumeration"
    if mappings_version == "1.3.5":
        filepath = enumerations_filepath / "veris135-enumerations.csv"
    elif mappings_version == "1.3.7":
        filepath = enumerations_filepath / "veris1_3_7-enumerations-groups.csv"
    df = pd.read_csv(filepath)

    description_dict = {}
    # if any of df cells have no value, fill with an empty string
    df = df.fillna("")
    for _, row in df.iterrows():
        path = f"{row['AXES']}.{row['CATEGORY']}.{row['SUB CATEGORY']}.{row['VALUE']}"
        # if any of the veris paths do not have all sections, remove the extra '.'
        path = path.replace("..", ".")
        description_dict[path.lower()] = row["DESCRIPTION"]
    return description_dict


def get_non_mappables(domain, mapping_framework_version):
    non_mappables_filepath = ROOT_DIR / "src/mapex_convert/mappings/Veris/non-mappables"
    non_mappables_df = pd.DataFrame()
    valid_domain_and_version = True
    if domain == "ics":
        non_mappables_df = read_csv_file(
            non_mappables_filepath / "veris_ics_aggregate_non_mappables.csv"
        )
    elif domain == "mobile":
        non_mappables_df = read_csv_file(
            non_mappables_filepath / "veris_mobile_aggregate_non_mappables.csv"
        )
    elif domain == "enterprise" and mapping_framework_version == "1.3.7":
        non_mappables_df = read_csv_file(
            non_mappables_filepath / "veris_enterprise_aggregate_non_mappables.csv"
        )
    elif mapping_framework_version == "1.3.5":
        non_mappables_df = read_csv_file(
            non_mappables_filepath / "veris_135_non_mappables.csv"
        )
    else:
        valid_domain_and_version = False
        logger.warning(
            "No non-mappables for {domain} and {mapping_framewwork_version}",
            domain=domain,
            mapping_framework_version=mapping_framework_version,
        )
    if valid_domain_and_version:
        non_mappables = []
        for index, row in non_mappables_df.iterrows():
            non_mappables.append(row["Non-Mappable"])
        return non_mappables
