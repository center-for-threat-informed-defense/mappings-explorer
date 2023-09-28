def configure_veris_mappings(veris_mappings, domain):
    parsed_mappings = []
    for attack_object in veris_mappings["attack_to_veris"]:
        mapped_attack_object = veris_mappings["attack_to_veris"][attack_object]
        for veris_object in mapped_attack_object["veris"]:
            parsed_mappings.append(
                {
                    "metadata": {
                        "mapping-version": veris_mappings["metadata"][
                            "mappings_version"
                        ],
                        "attack-version": veris_mappings["metadata"]["attack_version"],
                        "technology-domain": domain,
                        "author": "",
                        "contact": "",
                        # get correct value
                        "creation-date": "",
                        "last-update": "",
                        "organization": "",
                        "mapping-platform": "VERIS Framework",
                        "mapping-platform-version": veris_mappings["metadata"][
                            "veris_version"
                        ],
                    },
                    "attack-object": {
                        "comments": "",
                        "id": attack_object,
                        "name": mapped_attack_object["name"],
                        "references": [],
                        "tags": [],
                        "mapping-description": "",
                        "mapping-target": veris_object,
                        "mapping-platform": {
                            "relationship-type": "",
                            "date-delivered": "",
                        },
                    },
                }
            )

    return parsed_mappings
