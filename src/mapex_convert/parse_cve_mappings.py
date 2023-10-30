import uuid


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
            "creation_date": "02/03/2021",
            # confirm last-update value is correct
            "last_update": "10/27/2021",
            "organization": "",
            "mapping_framework": "cve",
            "mapping_framework_version": "",
            "mappings_types": formatted_cve_mapping_types,
            "groups": [],
        },
        "attack_objects": [],
    }

    groups = []
    for _, row in df.iterrows():
        for mapping_type in cve_mapping_types:
            if isinstance(row[mapping_type], str):
                # split techniques and subtechniques into individual attack objects
                mapped_attack_objects = row[mapping_type].split("; ")
                mapping_type = mapping_type.lower().replace(" ", "_")
                for attack_object in mapped_attack_objects:
                    # figure out capability group
                    capability_id = row["CVE ID"]
                    capability_year = capability_id[
                        capability_id.index("-") + 1 : row["CVE ID"].rindex("-")
                    ]
                    if not any(group["name"] == capability_year for group in groups):
                        group_id = str(uuid.uuid4())
                        groups.append({"id": group_id, "name": capability_year})

                    # technique id is not in the dictionary, set it to an empty string
                    # this can happen if the technique has been deprecated or revoked
                    # will likely change when we get concrete guidance on how to deal
                    # with deprecated and/or revoked technique
                    attack_details = attack_id_to_name_dict.get(
                        attack_object.strip(), {}
                    )
                    name = attack_details.get("name", "")
                    group = list(
                        filter(lambda group: group["name"] == capability_year, groups)
                    )[0]["id"]

                    parsed_mappings["attack_objects"].append(
                        {
                            "comments": "",
                            "attack_object_id": attack_object,
                            "attack_object_name": name,
                            "references": [],
                            "tags": [],
                            "capability_description": "",
                            "capability_id": capability_id,
                            "mapping_type": mapping_type,
                            "group": group,
                        }
                    )
    parsed_mappings["metadata"]["groups"] = groups
    return parsed_mappings
