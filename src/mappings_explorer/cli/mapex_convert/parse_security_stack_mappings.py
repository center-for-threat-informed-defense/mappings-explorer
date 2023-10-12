def configure_security_stack_mappings(data, parsed_mappings):
    if len(list(parsed_mappings.keys())) == 0:
        parsed_mappings["metadata"] = {
            "mapping-version": data["version"],
            "attack-version": data["ATT&CK version"],
            # this is an assumption that all cve mappings are enterprise
            # this assumption is not currently true
            # need to clarify how we will handle non-enterprise cve mappings
            "technology-domain": "enterprise",
            "author": "",
            "contact": data["contact"],
            # confirm creation-data value is correct
            "creation-date": data["creation date"],
            # confirm last-update value is correct
            "last-update": "",
            "organization": "",
            "mapping-framework": data["platform"],
            "mapping-framework-version": "",
        }
        parsed_mappings["attack-objects"] = []

    for technique in data["techniques"]:
        # related score is true if there are subtechnique scores
        # associated with the technique
        related_score = True if technique.get("sub-techniques-scores") else False

        comments = data.get("comments") or ""
        tags = data.get("tags") or []
        references = data.get("references") or []

        for technique_score in technique["technique-scores"]:
            parsed_mappings["attack-objects"].append(
                {
                    "comments": comments,
                    "attack-object-id": technique["id"],
                    "attack-object-name": technique["name"],
                    "references": list(references),
                    "tags": list(tags),
                    "mapping-description": "",
                    "capability-id": data["name"],
                    "mapping-type": "technique-scores",
                    "score-category": technique_score["category"],
                    "score-value": technique_score["value"],
                    "related-score": related_score,
                }
            )
