import uuid


def configure_security_stack_mappings(data, parsed_mappings):
    # ensure creation date meets correct date format
    platform = data["platform"].lower()
    if platform == "aws":
        year = "2021"
        month = "09"
        day = "21"
    elif platform == "azure":
        year = "2021"
        month = "06"
        day = "29"
    elif platform == "gcp":
        year = "2022"
        month = "06"
        day = "28"

    if len(list(parsed_mappings.keys())) == 0:
        mapping_types = [
            {"id": str(uuid.uuid4()), "name": "technique_scores", "description": ""}
        ]
        parsed_mappings["metadata"] = {
            "mapping_version": str(data["version"]),
            "attack_version": str(data["ATT&CK version"]),
            # this is an assumption that all cve mappings are enterprise
            # this assumption is not currently true
            # need to clarify how we will handle non-enterprise cve mappings
            "technology_domain": "enterprise",
            "author": "",
            "contact": data["contact"],
            # confirm creation-data value is correct
            "creation_date": f"{month}/{day}/{year}",
            # confirm last-update value is correct
            "last_update": f"{month}/{day}/{year}",
            "organization": "",
            "mapping_framework": platform,
            "mapping_framework_version": f"{year[-2:]}.{month}.{day}",
            "mapping_framework_version_schema": "ACCESS_DATE",
            "mapping_types": mapping_types,
            "groups": [],
        }
        parsed_mappings["mapping_objects"] = []

    # get mapping type id
    mapping_type_uuid = list(
        filter(
            lambda mapping_type_object: mapping_type_object["name"]
            == "technique_scores",
            parsed_mappings["metadata"]["mapping_types"],
        )
    )[0]["id"]

    for technique in data["techniques"]:
        references = data.get("references") or []

        for technique_score in technique["technique-scores"]:
            comments = technique_score.get("comments") or ""

            # get group uuid
            capability_name = data["name"]
            capability_id = capability_name.lower().replace(" ", "_")
            if not any(
                group["name"] == capability_name
                for group in parsed_mappings["metadata"]["groups"]
            ):
                parsed_mappings["metadata"]["groups"].append(
                    {"id": capability_id, "name": capability_name}
                )

            parsed_mappings["mapping_objects"].append(
                {
                    "comments": comments,
                    "attack_object_id": technique["id"],
                    "attack_object_name": technique["name"],
                    "references": list(references),
                    "capability_description": capability_name,
                    "capability_id": capability_name,
                    "mapping_type": mapping_type_uuid,
                    "score_category": technique_score["category"].lower(),
                    "score_value": technique_score["value"].lower(),
                    "related_score": "",
                    "group": capability_id,
                }
            )
        if technique.get("sub-techniques-scores"):
            for subtechnique_score in technique.get("sub-techniques-scores"):
                for subtechnique in subtechnique_score["sub-techniques"]:
                    for score in subtechnique_score["scores"]:
                        subtechnique_comments = score.get("comments") or ""
                        subtechniqe_references = score.get("references") or []

                        parsed_mappings["mapping_objects"].append(
                            {
                                "comments": subtechnique_comments,
                                "attack_object_id": subtechnique["id"],
                                "attack_object_name": subtechnique["name"],
                                "references": subtechniqe_references,
                                "capability_description": capability_name,
                                "capability_id": capability_name,
                                "mapping_type": mapping_type_uuid,
                                "score_category": score["category"].lower(),
                                "score_value": score["value"].lower(),
                                "related_score": technique["id"],
                                "group": capability_id,
                            }
                        )
