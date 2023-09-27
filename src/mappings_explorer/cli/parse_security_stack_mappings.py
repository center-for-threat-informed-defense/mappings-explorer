def configure_security_stack_mappings(data, parsed_mappings):
    for technique in data["techniques"]:
        # related score is true if there are subtechnique scores
        # associated with the technique
        related_score = True if technique.get("sub-techniques-scores") else False

        comment = data.get("comments") or ""
        tags = data.get("tags") or []
        references = data.get("references") or []

        for technique_score in technique["technique-scores"]:
            parsed_mappings.append(
                {
                    "metadata": {
                        "mapping-verision": data["version"],
                        "attack-version": data["ATT&CK version"],
                        "creation-date": data[
                            "creation date"
                        ],  # confirm that this value is correct
                        "last-update": data[
                            "creation date"
                        ],  # confirm this value is correct
                        "author": "",
                        "contact": data["contact"],
                        "organization": "",
                        "platform": data["platform"],
                        "platform-version": "",  # get correct value
                        "mapping-type": "scoring",
                    },
                    "attack-object": {
                        "id": technique["id"],
                        "name": technique["name"],
                        "value": data["name"],
                        "mapping-pattern": "",
                        "secondary-property": "",
                        "comments": comment,
                        "references": list(references),
                        "score-category": technique_score["category"],
                        "score-value": technique_score["value"],
                        "score-comment": technique_score.get("comments"),
                        "related-score": related_score,
                        "tags": list(tags),
                    },
                }
            )
