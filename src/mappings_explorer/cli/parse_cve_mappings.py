def configure_cve_mappings(datareader, attack_id_to_name_dict):
    # store the headers and then skip them
    headers = next(datareader, None)

    # put data in correct format with correct fields
    result = []
    for row in datareader:
        for i in range(1, 4):
            if row[i]:
                # split techniques and subtechniques into individual attack objects
                mapped_attack_objects = row[i].split("; ")
                for attack_object in mapped_attack_objects:
                    # technique id is not in the dictionary, set it to an empty string
                    # this can happen if the technique has been deprecated or revoked
                    # will likely change when we get concrete guidance on how to deal
                    # with deprecated and/or revoked technique
                    attack_details = attack_id_to_name_dict.get(
                        attack_object.strip(), {}
                    )
                    name = attack_details.get("name", "")
                    domain = attack_details.get("domain", "")

                    result.append(
                        {
                            "metadata": {
                                "mapping-version": "",
                                "attack-version": "9.0",
                                "technology-domain": domain,
                                "author": "",
                                "contact": "",
                                # confirm creation-data value is correct
                                "creation-date": "02/03/21",
                                # confirm last-update value is correct
                                "last-update": "10/27/21",
                                "organization": "",
                                "mapping-platform": "CVE Vulnerability List",
                                "mapping-platform-version": "",
                            },
                            "attack-object": {
                                "comments": "",
                                "id": attack_object,
                                "name": name,
                                "references": [],
                                "tags": [],
                                "mapping-description": "",
                                "mapping-target": row[0],
                                "mapping-platform": {
                                    "name": "CVE Vulnerability List",
                                    "impact": headers[i],
                                    "phase": row[5],
                                },
                            },
                        }
                    )

    return result
