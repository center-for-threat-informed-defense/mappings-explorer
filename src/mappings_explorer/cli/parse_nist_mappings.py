def configure_nist_mappings(dataframe, attack_version, mappings_version):
    parsed_mappings = []
    for _, row in dataframe.iterrows():
        parsed_mappings.append(
            {
                "metadata": {
                    "mapping-version": mappings_version,
                    "attack-version": attack_version,
                    "technology-domain": "enterprise",
                    "author": "",
                    "contact": "",
                    # get correct value
                    "creation-date": "",
                    "last-update": "",
                    "organization": "",
                    "mapping-platform": "NIST Security controls",
                    "mapping-platform-version": "",
                },
                "attack-object": {
                    "comments": "",
                    "id": row["Technique ID"],
                    "name": row["Technique Name"],
                    "references": [],
                    "tags": [],
                    "mapping-description": "",
                    "mapping-target": row["Control ID"],
                    "mapping-platform": {
                        "name": "NIST Security controls",
                        "control-name": row["Control Name"],
                        "mapping-type": row["Mapping Type"],
                    },
                },
            }
        )

    return parsed_mappings
