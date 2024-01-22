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

    attack_version = str(data["ATT&CK version"])
    if attack_version.find(".") == -1:
        attack_version = attack_version + ".0"

    if len(list(parsed_mappings.keys())) == 0:
        mapping_types = {
            "technique_scores": {"name": "technique_scores", "description": ""}
        }
        parsed_mappings["metadata"] = {
            "mapping_version": str(data["version"]),
            "attack_version": attack_version,
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
            "mapping_framework_version": f"{month}/{day}/{year}",
            "mapping_types": mapping_types,
            "capability_groups": {},
        }
        parsed_mappings["mapping_objects"] = []

    mapping_type_id = [
        mapping_type
        for mapping_type in parsed_mappings["metadata"]["mapping_types"]
        if parsed_mappings["metadata"]["mapping_types"][mapping_type]["name"]
        == "technique_scores"
    ][0]

    if len(data["techniques"]) == 0:
        if data["name"] not in parsed_mappings["metadata"]["capability_groups"]:
            parsed_mappings["metadata"]["capability_groups"][data["name"]] = data[
                "name"
            ]
        parsed_mappings["mapping_objects"].append(
            {
                "comments": None,
                "attack_object_id": None,
                "attack_object_name": None,
                "references": None,
                "capability_description": data["name"],
                "capability_id": data["name"],
                "mapping_type": None,
                "score_category": None,
                "score_value": None,
                "related_score": None,
                "capability_group": data["name"],
                "status": "non_mappable",
            }
        )

    for technique in data["techniques"]:
        references = data.get("references") or []

        for technique_score in technique["technique-scores"]:
            comments = technique_score.get("comments") or ""

            # get capability_group id
            capability_name = data["name"]
            capability_id = capability_name.lower().replace(" ", "_")
            if capability_id not in parsed_mappings["metadata"]["capability_groups"]:
                parsed_mappings["metadata"]["capability_groups"][
                    capability_id
                ] = capability_name

            parsed_mappings["mapping_objects"].append(
                {
                    "comments": comments,
                    "attack_object_id": technique["id"],
                    "attack_object_name": technique["name"],
                    "references": list(references),
                    "capability_description": capability_name,
                    "capability_id": capability_name,
                    "mapping_type": mapping_type_id,
                    "score_category": technique_score["category"].lower(),
                    "score_value": technique_score["value"].lower(),
                    "related_score": "",
                    "capability_group": capability_id,
                    "status": "complete",
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
                                "mapping_type": mapping_type_id,
                                "score_category": score["category"].lower(),
                                "score_value": score["value"].lower(),
                                "related_score": technique["id"],
                                "capability_group": capability_id,
                                "status": "complete",
                            }
                        )
