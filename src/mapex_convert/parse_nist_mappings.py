import uuid


def configure_nist_mappings(dataframe, attack_version, mapping_framework_version):
    # put data in correct format with correct fields
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
            "mappings_types": ["mitigates"],
            "groups": [],
        },
        "attack_objects": [],
    }

    groups = []
    for _, row in dataframe.iterrows():
        control_id = row["Control ID"]

        if not any(group["name"] == control_id for group in groups):
            group_id = str(uuid.uuid4())
            groups.append({"id": group_id, "name": control_id})

        group = list(filter(lambda group: group["name"] == control_id, groups))[0]["id"]

        parsed_mappings["attack_objects"].append(
            {
                "comments": "",
                "attack_object_id": row["Technique ID"],
                "attack_object_name": row["Technique Name"],
                "references": [],
                "tags": [],
                "capability_description": "",
                "capability_id": control_id,
                "mapping_type": row["Mapping Type"],
                "group": group,
            }
        )

    parsed_mappings["metadata"]["groups"] = groups
    return parsed_mappings
