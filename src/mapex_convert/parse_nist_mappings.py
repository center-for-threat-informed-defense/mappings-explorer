import uuid


def configure_nist_mappings(dataframe, attack_version, mapping_framework_version):
    # put data in correct format with correct fields
    mapping_types = [{"id": str(uuid.uuid4()), "name": "mitigates", "description": ""}]
    parsed_mappings = {
        "metadata": {
            "mapping_version": "",
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
            "mapping_framework_version": mapping_framework_version,
            "mapping_types": mapping_types,
        },
        "attack_objects": [],
    }

    for _, row in dataframe.iterrows():
        mapping_type_uuid = list(
            filter(
                lambda mapping_type_object: mapping_type_object["name"] == "mitigates",
                mapping_types,
            )
        )[0]["id"]
        parsed_mappings["attack_objects"].append(
            {
                "comments": "",
                "attack_object_id": row["Technique ID"],
                "attack_object_name": row["Technique Name"],
                "references": [],
                "tags": [],
                "capability_description": row["Control Name"],
                "capability_id": row["Control ID"],
                "mapping_type": mapping_type_uuid,
            }
        )

    return parsed_mappings
