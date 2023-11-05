import uuid


def configure_security_stack_mappings(data, parsed_mappings):
    # ensure creation date meets correct date format
    creation_date = data["creation date"]

    month = creation_date[0 : creation_date.index("/")].rjust(2, "0")
    day = creation_date[creation_date.index("/") + 1 : creation_date.rindex("/")].rjust(
        2, "0"
    )

    year = creation_date[creation_date.rindex("/") + 1 :]
    if len(year) < 4:
        year += 1

    if len(list(parsed_mappings.keys())) == 0:
        mapping_types = [
            {"id": str(uuid.uuid4()), "name": "technique-scores", "description": ""}
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
            "mapping_framework": data["platform"].lower(),
            "mapping_framework_version": "",
            "mapping_types": mapping_types,
        }
        parsed_mappings["attack_objects"] = []

    # get mapping type id
    mapping_type_uuid = list(
        filter(
            lambda mapping_type_object: mapping_type_object["name"]
            == "technique-scores",
            parsed_mappings["metadata"]["mapping_types"],
        )
    )[0]["id"]

    for technique in data["techniques"]:
        tags = data.get("tags") or []
        references = data.get("references") or []

        for technique_score in technique["technique-scores"]:
            comments = technique_score.get("comments") or ""

            parsed_mappings["attack_objects"].append(
                {
                    "comments": comments,
                    "attack_object_id": technique["id"],
                    "attack_object_name": technique["name"],
                    "references": list(references),
                    "tags": list(tags),
                    "capability_description": "",
                    "capability_id": data["name"],
                    "mapping_type": mapping_type_uuid,
                    "score_category": technique_score["category"],
                    "score_value": technique_score["value"],
                    "related_score": "",
                }
            )
        if technique.get("sub-techniques-scores"):
            for subtechnique_score in technique.get("sub-techniques-scores"):
                for subtechnique in subtechnique_score["sub-techniques"]:
                    for score in subtechnique_score["scores"]:
                        subtechnique_comments = score.get("comments") or ""
                        subtechnique_tags = score.get("tags") or []
                        subtechniqe_references = score.get("references") or []
                        parsed_mappings["attack_objects"].append(
                            {
                                "comments": subtechnique_comments,
                                "attack_object_id": subtechnique["id"],
                                "attack_object_name": subtechnique["name"],
                                "references": subtechniqe_references,
                                "tags": subtechnique_tags,
                                "capability_description": "",
                                "capability_id": data["name"],
                                "mapping_type": mapping_type_uuid,
                                "score_category": score["category"],
                                "score_value": score["value"],
                                "related_score": technique["id"],
                            }
                        )
