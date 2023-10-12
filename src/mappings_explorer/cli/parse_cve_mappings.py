def configure_cve_mappings(df, attack_id_to_name_dict):
    # put data in correct format with correct fields
    result = {
        "metadata": {
            "mapping-version": "",
            "attack-version": "9.0",
            # this is an assumption that all cve mappings are enterprise
            # this assumption is not currently true
            # need to clarify how we will handle non-enterprise cve mappings
            "technology-domain": "enterprise",
            "author": "",
            "contact": "",
            # confirm creation-data value is correct
            "creation-date": "02/03/21",
            # confirm last-update value is correct
            "last-update": "10/27/21",
            "organization": "",
            "mapping-framework": "CVE Vulnerability List",
            "mapping-framework-version": "",
        },
        "attack-objects": [],
    }

    cve_mapping_types = [
        "Primary Impact",
        "Secondary Impact",
        "Exploitation Technique",
        "Uncategorized",
    ]

    for _, row in df.iterrows():
        for mapping_type in cve_mapping_types:
            if isinstance(row[mapping_type], str):
                # split techniques and subtechniques into individual attack objects
                mapped_attack_objects = row[mapping_type].split("; ")
                for attack_object in mapped_attack_objects:
                    # technique id is not in the dictionary, set it to an empty string
                    # this can happen if the technique has been deprecated or revoked
                    # will likely change when we get concrete guidance on how to deal
                    # with deprecated and/or revoked technique
                    attack_details = attack_id_to_name_dict.get(
                        attack_object.strip(), {}
                    )
                    name = attack_details.get("name", "")

                    result["attack-objects"].append(
                        {
                            "comments": "",
                            "attack-object-id": attack_object,
                            "attack-object-name": name,
                            "references": [],
                            "tags": [],
                            "mapping-description": "",
                            "capability-id": row["CVE ID"],
                            "mapping-type": mapping_type,
                        }
                    )

    return result
