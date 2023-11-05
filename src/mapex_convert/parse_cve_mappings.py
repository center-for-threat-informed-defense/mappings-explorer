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

    cve_mapping_types_objects = [
        {"id": str(uuid.uuid4()), "description": "", "name": mapping_type}
        for mapping_type in formatted_cve_mapping_types
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
            "mapping_types": cve_mapping_types_objects,
        },
        "attack_objects": [],
    }

    for _, row in df.iterrows():
        for mapping_type in cve_mapping_types:
            if isinstance(row[mapping_type], str):
                # split techniques and subtechniques into individual attack objects
                mapped_attack_objects = row[mapping_type].split("; ")
                mapping_type = mapping_type.lower().replace(" ", "_")
                for attack_object in mapped_attack_objects:
                    # technique id is not in the dictionary, set it to an empty string
                    # this can happen if the technique has been deprecated or revoked
                    # will likely change when we get concrete guidance on how to deal
                    # with deprecated and/or revoked technique
                    attack_details = attack_id_to_name_dict.get(
                        attack_object.strip(), {}
                    )
                    name = attack_details.get("name", "")
                    mapping_type_uuid = list(
                        filter(
                            lambda mapping_type_object: mapping_type_object["name"]
                            == mapping_type,
                            cve_mapping_types_objects,
                        )
                    )[0]["id"]
                    parsed_mappings["attack_objects"].append(
                        {
                            "comments": "",
                            "attack_object_id": attack_object,
                            "attack_object_name": name,
                            "references": [],
                            "tags": [],
                            "capability_description": "",
                            "capability_id": row["CVE ID"],
                            "mapping_type": mapping_type_uuid,
                        }
                    )
    return parsed_mappings
