def configure_security_stack_mappings(data):
    parsed_mappings = []
    for technique in data["techniques"]:
        # related score is true if there are subtechnique scores
        # associated with the technique
        related_score = True if technique.get("sub-techniques-scores") else False

        comments = data.get("comments") or ""
        tags = data.get("tags") or []
        references = data.get("references") or []

        for technique_score in technique["technique-scores"]:
            parsed_mappings.append(
                {
                    "metadata": {
                        "mapping-version": data["version"],
                        "attack-version": data["ATT&CK version"],
                        "technology-domain": "enterprise",
                        "author": "",
                        "contact": data["contact"],
                        # confirm this value is correct
                        "creation-date": data["creation date"],
                        "last-update": "",
                        "organization": "",
                        "mapping-platform": data["platform"],
                        "mapping-platform-version": "",
                    },
                    "attack-object": {
                        "comments": comments,
                        "id": technique["id"],
                        "name": technique["name"],
                        "references": list(references),
                        "tags": list(tags),
                        "mapping-description": "",
                        "mapping-target": data["name"],
                        "mapping-platform": {
                            "score-category": technique_score["category"],
                            "score-value": technique_score["value"],
                            "related-score": related_score,
                            "tags": list(tags),
                        },
                    },
                }
            )
    return parsed_mappings
