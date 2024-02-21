import requests
from loguru import logger


def configure_cve_mappings(df, attack_id_to_name_dict):
    cve_mapping_types = [
        "Primary Impact",
        "Secondary Impact",
        "Exploitation Technique",
        "Uncategorized",
    ]

    formatted_cve_mapping_types = [
        mapping_type.lower().replace(" ", "_") for mapping_type in cve_mapping_types
    ]

    cve_mapping_types_objects = {}

    for mapping_type in formatted_cve_mapping_types:
        mapping_type_id = mapping_type.lower().replace(" ", "_")
        cve_mapping_types_objects[mapping_type_id] = {
            "description": "",
            "name": mapping_type,
        }

    # put data in correct format with correct fields
    parsed_mappings = {
        "metadata": {
            "mapping_version": "",
            "attack_version": "9.0",
            # this is an assumption that all cve mappings are enterprise
            # this assumption is not currently true
            # need to clarify how we will handle non-enterprise cve mappings
            "technology_domain": "enterprise",
            "author": "",
            "contact": "",
            # confirm creation-data value is correct
            "creation_date": "10/21/2021",
            # confirm last-update value is correct
            "last_update": "10/21/2021",
            "organization": "",
            "mapping_framework": "cve",
            "mapping_framework_version": "10/21/2021",
            "mapping_types": cve_mapping_types_objects,
            "capability_groups": {},
        },
        "mapping_objects": [],
    }

    capability_groups = {}
    for _, row in df.iterrows():
        for mapping_type in cve_mapping_types:
            if isinstance(row[mapping_type], str):
                # split techniques and subtechniques into individual attack objects
                mapped_mapping_objects = row[mapping_type].split("; ")
                mapping_type = mapping_type.lower().replace(" ", "_")
                for attack_object in mapped_mapping_objects:
                    # technique id is not in the dictionary, set it to an empty string
                    # this can happen if the technique has been deprecated or revoked
                    # will likely change when we get concrete guidance on how to deal
                    # with deprecated and/or revoked technique
                    attack_details = attack_id_to_name_dict.get(
                        attack_object.strip(), {}
                    )
                    name = attack_details.get("name", "")

                    mapping_type_id = [
                        cve_mapping_type
                        for cve_mapping_type in cve_mapping_types_objects
                        if cve_mapping_types_objects[cve_mapping_type]["name"]
                        == mapping_type
                    ][0]

                    # capability_groups
                    capability_id = row["CVE ID"]
                    capability_year = capability_id[
                        capability_id.index("-") + 1 : row["CVE ID"].rindex("-")
                    ]
                    capability_description = ""
                    try:
                        response = requests.get(
                            f"https://cveawg.mitre.org/api/cve/{capability_id}/",
                            verify=False,
                        ).json()
                        descriptions = response["containers"]["cna"]["affected"]
                        capability_description = descriptions[0]["product"]
                    except:
                        logger.error("Failed to fetch capability description")

                    # if group doesn't exist yet, create it
                    if capability_year not in capability_groups:
                        capability_groups[capability_year] = f"{capability_year} CVEs"

                    parsed_mappings["mapping_objects"].append(
                        {
                            "comments": "",
                            "attack_object_id": attack_object,
                            "attack_object_name": name,
                            "references": [],
                            "capability_description": capability_description,
                            "capability_id": row["CVE ID"],
                            "mapping_type": mapping_type_id,
                            "capability_group": capability_year,
                            "status": "complete",
                        }
                    )

    parsed_mappings["metadata"]["capability_groups"] = capability_groups
    return parsed_mappings
