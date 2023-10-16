def configure_veris_mappings(veris_mappings, domain):
    parsed_mappings = {
        "metadata": {
            "mapping-version": veris_mappings["metadata"]["mappings_version"],
            "attack-version": veris_mappings["metadata"]["attack_version"],
            # this is an assumption that all cve mappings are enterprise
            # this assumption is not currently true
            # need to clarify how we will handle non-enterprise cve mappings
            "technology-domain": domain,
            "author": "",
            "contact": "",
            # confirm creation-data value is correct
            "creation-date": "02/03/21",
            # confirm last-update value is correct
            "last-update": "10/27/21",
            "organization": "",
            "mapping-framework": "VERIS Framework",
            "mapping-framework-version": veris_mappings["metadata"]["veris_version"],
        },
        "attack-objects": [],
    }

    for attack_object in veris_mappings["attack_to_veris"]:
        mapped_attack_object = veris_mappings["attack_to_veris"][attack_object]
        for veris_object in mapped_attack_object["veris"]:
            parsed_mappings["attack-objects"].append(
                {
                    "comments": "",
                    "attack-object-id": attack_object,
                    "attack-object-name": mapped_attack_object["name"],
                    "references": [],
                    "tags": [],
                    "mapping-description": "",
                    "capability-id": veris_object,
                    "mapping-type": "related-to",
                }
            )

    return parsed_mappings
