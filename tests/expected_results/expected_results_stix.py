expected_stix_results = {
    "type": "bundle",
    "spec_version": "2.1",
    "objects": [
        {
            "type": "infrastructure",
            "spec_version": "2.1",
            "name": "AC-10",
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "relationship_type": "1234",
            "target_ref": "attack-pattern--2c4d4e92-0ccf-4a97-b54c-86d662988a53",
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "relationship_type": "1234",
            "target_ref": "attack-pattern--ed7efd4d-ce28-4a19-a8e6-c58011eb2c7a",
        },
    ],
}
