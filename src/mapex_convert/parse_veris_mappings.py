import uuid


def configure_veris_mappings(veris_mappings, domain):
    mapping_types = [{"id": str(uuid.uuid4()), "name": "related-to", "description": ""}]
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
            "creation_date": "02/03/2021",
            # confirm last-update value is correct
            "last_update": "10/27/2021",
            "organization": "",
            "mapping_framework": "veris",
            "mapping_framework_version": veris_mappings["metadata"]["veris_version"],
            "mapping_types": mapping_types,
        },
        "attack_objects": [],
    }

    for attack_object in veris_mappings["attack_to_veris"]:
        mapped_attack_object = veris_mappings["attack_to_veris"][attack_object]
        for veris_object in mapped_attack_object["veris"]:
            mapping_type_uuid = list(
                filter(
                    lambda mapping_type_object: mapping_type_object["name"]
                    == "related-to",
                    mapping_types,
                )
            )[0]["id"]
            parsed_mappings["attack_objects"].append(
                {
                    "comments": "",
                    "attack_object_id": attack_object,
                    "attack_object_name": mapped_attack_object["name"],
                    "references": [],
                    "tags": [],
                    "capability_description": "",
                    "capability_id": veris_object,
                    "mapping_type": mapping_type_uuid,
                }
            )

    return parsed_mappings
