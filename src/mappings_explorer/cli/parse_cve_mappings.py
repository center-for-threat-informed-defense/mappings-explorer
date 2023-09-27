def configure_cve_mappings(datareader, attack_id_to_name_dict):
    # skip the headers
    next(datareader, None)

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
                    name = attack_id_to_name_dict.get(attack_object.strip(), "")

                    result.append(
                        {
                            "metadata": {
                                "mapping-verision": row[
                                    5
                                ],  # confirm that this value is correct
                                "attack-version": "9.0",
                                # confirm this value is correct
                                "creation-date": "02/03/21",
                                # confirm this value is correct
                                "last-update": "10/27/21",
                                "author": "",
                                "contact": "",
                                "organization": "",
                                "platform": "CVE Vulnerability List",
                                "platform-version": 13,  # confirm this value is correct
                                "mapping-type": "association",
                            },
                            "attack-object": {
                                "id": attack_object,
                                "name": name,
                                "value": row[0],
                                "mapping-pattern": "",
                                "secondary-property": "",
                                "tags": [],
                                "comments": "",
                                "references": [],
                            },
                        }
                    )

    return result
