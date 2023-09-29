import yaml

expected_nist_mapping = yaml.dump(
    [
        {
            "metadata": {
                "mapping-version": "1",
                "attack-version": "13.0",
                "creation-date": "",
                "last-update": "",
                "author": "",
                "contact": "",
                "organization": "",
                "mapping-platform": "NIST Security controls",
                "mapping-platform-version": "",  # get correct value
                "technology-domain": "enterprise",
            },
            "attack-object": {
                "id": "T1137",
                "name": "Office Application Startup",
                "mapping-target": "AC-10",
                "tags": [],
                "comments": "",
                "references": [],
                "mapping-description": "",
                "mapping-platform": {
                    "control-name": "Concurrent Session Control",
                    "mapping-type": "mitigates",
                    "name": "NIST Security controls",
                },
            },
        },
        {
            "metadata": {
                "mapping-version": "1",
                "attack-version": "13.0",
                "creation-date": "",
                "last-update": "",
                "author": "",
                "contact": "",
                "organization": "",
                "mapping-platform": "NIST Security controls",
                "mapping-platform-version": "",  # get correct value
                "technology-domain": "enterprise",
            },
            "attack-object": {
                "id": "T1137.002",
                "name": "Office Test",
                "mapping-target": "AC-10",
                "tags": [],
                "comments": "",
                "references": [],
                "mapping-description": "",
                "mapping-platform": {
                    "control-name": "Concurrent Session Control",
                    "mapping-type": "mitigates",
                    "name": "NIST Security controls",
                },
            },
        },
    ]
)

expected_security_stack_mapping = yaml.dump(
    [
        {
            "metadata": {
                "mapping-version": 1,
                "attack-version": 9,
                "creation-date": "05/27/2021",  # confirm that this value is correct
                "last-update": "",  # confirm this value is correct
                "author": "",
                "contact": "ctid@mitre-engenuity.org",
                "organization": "",
                "mapping-platform": "AWS",
                "mapping-platform-version": "",  # get correct value
                "technology-domain": "enterprise",
            },
            "attack-object": {
                "id": "T1078",
                "name": "Valid Accounts",
                "mapping-target": "Amazon Cognito",
                "comments": "comment",
                "references": [
                    "https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html",
                    "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-compromised-credentials.html",
                    "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html",
                ],
                "mapping-platform": {
                    "score-category": "Protect",
                    "score-value": "Minimal",
                    "related-score": True,
                    "tags": ["Identity"],
                },
                "mapping-description": "",
                "tags": ["Identity"],
            },
        },
        {
            "metadata": {
                "mapping-version": 1,
                "attack-version": 9,
                "creation-date": "05/27/2021",  # confirm that this value is correct
                "last-update": "",  # confirm this value is correct
                "author": "",
                "contact": "ctid@mitre-engenuity.org",
                "organization": "",
                "mapping-platform": "AWS",
                "mapping-platform-version": "",  # get correct value
                "technology-domain": "enterprise",
            },
            "attack-object": {
                "id": "T1110",
                "name": "Brute Force",
                "mapping-target": "Amazon Cognito",
                "comments": "comment",
                "references": [
                    "https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html",
                    "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-compromised-credentials.html",
                    "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html",
                ],
                "mapping-description": "",
                "mapping-platform": {
                    "score-category": "Protect",
                    "score-value": "Significant",
                    "related-score": True,
                    "tags": ["Identity"],
                },
                "tags": ["Identity"],
            },
        },
    ]
)

expected_veris_mapping = yaml.dump(
    [
        {
            "metadata": {
                "mapping-version": "1.9",
                "attack-version": "9.0",
                "creation-date": "",  # get correct value
                "last-update": "",  # get correct value
                "author": "",
                "contact": "",
                "organization": "",
                "mapping-platform": "VERIS Framework",
                "mapping-platform-version": "1.3.5",
                "technology-domain": "enterprise",
            },
            "attack-object": {
                "id": "T1047",
                "name": "Windows Management Instrumentation",
                "mapping-target": "action.hacking.variety.Abuse of functionality",
                "tags": [],
                "comments": "",
                "references": [],
                "mapping-description": "",
                "mapping-platform": {
                    "relationship-type": "related-to",
                    "veris-path": "action.hacking.variety.Abuse of functionality",
                },
            },
        },
        {
            "metadata": {
                "mapping-version": "1.9",
                "attack-version": "9.0",
                "creation-date": "",  # get correct value
                "last-update": "",  # get correct value
                "author": "",
                "contact": "",
                "organization": "",
                "mapping-platform": "VERIS Framework",
                "mapping-platform-version": "1.3.5",
                "technology-domain": "enterprise",
            },
            "attack-object": {
                "id": "T1047",
                "name": "Windows Management Instrumentation",
                "mapping-target": "action.hacking.vector.Command shell",
                "tags": [],
                "comments": "",
                "references": [],
                "mapping-description": "",
                "mapping-platform": {
                    "relationship-type": "related-to",
                    "veris-path": "action.hacking.vector.Command shell",
                },
            },
        },
        {
            "metadata": {
                "mapping-version": "1.9",
                "attack-version": "9.0",
                "creation-date": "",  # get correct value
                "last-update": "",  # get correct value
                "author": "",
                "contact": "",
                "organization": "",
                "mapping-platform": "VERIS Framework",
                "mapping-platform-version": "1.3.5",
                "technology-domain": "enterprise",
            },
            "attack-object": {
                "id": "T1053",
                "name": "Scheduled Task/Job",
                "mapping-target": "action.hacking.variety.Abuse of functionality",
                "tags": [],
                "comments": "",
                "references": [],
                "mapping-description": "",
                "mapping-platform": {
                    "relationship-type": "related-to",
                    "veris-path": "action.hacking.variety.Abuse of functionality",
                },
            },
        },
    ]
)

expected_cve_mapping = yaml.dump(
    [
        {
            "metadata": {
                "mapping-version": "",  # confirm that this value is correct
                "attack-version": "9.0",
                "creation-date": "02/03/21",  # confirm this value is correct
                "last-update": "10/27/21",  # confirm this value is correct
                "author": "",
                "contact": "",
                "organization": "",
                "mapping-platform": "CVE Vulnerability List",
                "mapping-platform-version": "",  # confirm this value is correct
                "technology-domain": "enterprise",
            },
            "attack-object": {
                "id": "T1059",
                "name": "Name for T1059",
                "mapping-target": "CVE-2019-15243",
                "tags": [],
                "comments": "",
                "references": [],
                "mapping-description": "",
                "mapping-platform": {
                    "impact": "Primary Impact",
                    "name": "CVE Vulnerability List",
                    "phase": "Phase 2",
                },
            },
        },
        {
            "metadata": {
                "mapping-version": "",  # confirm that this value is correct
                "attack-version": "9.0",
                "creation-date": "02/03/21",  # confirm this value is correct
                "last-update": "10/27/21",  # confirm this value is correct
                "author": "",
                "contact": "",
                "organization": "",
                "mapping-platform": "CVE Vulnerability List",
                "mapping-platform-version": "",  # confirm this value is correct
                "technology-domain": "enterprise",
            },
            "attack-object": {
                "id": "T1190",
                "name": "Name for T1190",
                "mapping-target": "CVE-2019-15243",
                "tags": [],
                "comments": "",
                "references": [],
                "mapping-description": "",
                "mapping-platform": {
                    "impact": "Exploitation Technique",
                    "name": "CVE Vulnerability List",
                    "phase": "Phase 2",
                },
            },
        },
        {
            "metadata": {
                "mapping-version": "",  # confirm that this value is correct
                "attack-version": "9.0",
                "creation-date": "02/03/21",  # confirm this value is correct
                "last-update": "10/27/21",  # confirm this value is correct
                "author": "",
                "contact": "",
                "organization": "",
                "mapping-platform": "CVE Vulnerability List",
                "mapping-platform-version": "",  # confirm this value is correct
                "technology-domain": "enterprise",
            },
            "attack-object": {
                "id": "T1078",
                "name": "Name for T1078",
                "mapping-target": "CVE-2019-15243",
                "tags": [],
                "comments": "",
                "references": [],
                "mapping-description": "",
                "mapping-platform": {
                    "impact": "Exploitation Technique",
                    "name": "CVE Vulnerability List",
                    "phase": "Phase 2",
                },
            },
        },
        {
            "metadata": {
                "mapping-version": "",  # confirm that this value is correct
                "attack-version": "9.0",
                "creation-date": "02/03/21",  # confirm this value is correct
                "last-update": "10/27/21",  # confirm this value is correct
                "author": "",
                "contact": "",
                "organization": "",
                "mapping-platform": "CVE Vulnerability List",
                "mapping-platform-version": "",  # confirm this value is correct
                "technology-domain": "enterprise",
            },
            "attack-object": {
                "id": "T1068",
                "name": "Name for T1068",
                "mapping-target": "CVE-2019-15976",
                "tags": [],
                "comments": "",
                "references": [],
                "mapping-description": "",
                "mapping-platform": {
                    "impact": "Primary Impact",
                    "name": "CVE Vulnerability List",
                    "phase": "Phase 2",
                },
            },
        },
    ]
)
