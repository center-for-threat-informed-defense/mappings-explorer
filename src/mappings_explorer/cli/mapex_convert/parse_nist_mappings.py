def configure_nist_mappings(dataframe, attack_version, mappings_version):
    # put data in correct format with correct fields
    parsed_mappings = {
        "metadata": {
            "mapping-version": mappings_version,
            "attack-version": attack_version,
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
            "mapping-framework": "NIST Security controls",
            "mapping-framework-version": "",
        },
        "attack-objects": [],
    }

    for _, row in dataframe.iterrows():
        parsed_mappings["attack-objects"].append(
            {
                "comments": "",
                "attack-object-id": row["Technique ID"],
                "attack-object-name": row["Technique Name"],
                "references": [],
                "tags": [],
                "mapping-description": "",
                "capability-id": row["Control Name"],
                "mapping-type": row["Mapping Type"],
            }
        )

    return parsed_mappings
