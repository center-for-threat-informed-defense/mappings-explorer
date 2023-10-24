def configure_nist_mappings(dataframe, attack_version, mapping_version):
    # put data in correct format with correct fields
    parsed_mappings = {
        "metadata": {
            "mapping_version": mapping_version,
            "attack_version": attack_version,
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
            "mapping_framework": "nist_800_53",
            "mapping_framework_version": "",
            "mappings_types": ["mitigates"],
        },
        "attack_objects": [],
    }

    for _, row in dataframe.iterrows():
        parsed_mappings["attack_objects"].append(
            {
                "comments": "",
                "attack_object_id": row["Technique ID"],
                "attack_object_name": row["Technique Name"],
                "references": [],
                "tags": [],
                "capability_description": "",
                "capability_id": row["Control ID"],
                "mapping_type": row["Mapping Type"],
            }
        )

    return parsed_mappings
