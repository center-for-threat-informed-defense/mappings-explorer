expected_nist_mapping_json = {
    "metadata": {
        "mapping_version": "1",
        "attack_version": "13.0",
        "technology_domain": "enterprise",
        "author": "",
        "contact": "",
        "creation_date": "02/03/2021",
        "last_update": "10/27/2021",
        "organization": "",
        "mapping_framework": "nist_800_53",
        "mapping_framework_version": "",
        "mappings_types": ["mitigates"],
    },
    "attack_objects": [
        {
            "comments": "",
            "attack_object_id": "T1137",
            "attack_object_name": "Office Application Startup",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "AC-10",
            "mapping_type": "mitigates",
        },
        {
            "comments": "",
            "attack_object_id": "T1137.002",
            "attack_object_name": "Office Test",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "AC-10",
            "mapping_type": "mitigates",
        },
    ],
}

expected_security_stack_mapping_json = {
    "metadata": {
        "mapping_version": "1",
        "attack_version": "9",
        "technology_domain": "enterprise",
        "author": "",
        "contact": "ctid@mitre-engenuity.org",
        "creation_date": "05/27/2021",
        "last_update": "05/27/2021",
        "organization": "",
        "mapping_framework": "aws",
        "mapping_framework_version": "",
        "mappings_types": ["technique-scores"],
    },
    "attack_objects": [
        {
            "comments": "comment",
            "attack_object_id": "T1078",
            "attack_object_name": "Valid Accounts",
            "references": [
                "https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html",
                "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-compromised-credentials.html",
                "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html",
            ],
            "tags": ["Identity"],
            "mapping_description": "",
            "capability_id": "Amazon Cognito",
            "mapping_type": "technique-scores",
            "score_category": "Protect",
            "score_value": "Minimal",
            "related_score": "",
        },
        {
            "comments": "score comment",
            "attack_object_id": "T1078.004",
            "attack_object_name": "Cloud Accounts",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "Amazon Cognito",
            "mapping_type": "technique-scores",
            "score_category": "Protect",
            "score_value": "Partial",
            "related_score": "T1078",
        },
        {
            "comments": "comment",
            "attack_object_id": "T1110",
            "attack_object_name": "Brute Force",
            "references": [
                "https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html",
                "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-compromised-credentials.html",
                "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html",
            ],
            "tags": ["Identity"],
            "mapping_description": "",
            "capability_id": "Amazon Cognito",
            "mapping_type": "technique-scores",
            "score_category": "Protect",
            "score_value": "Significant",
            "related_score": "",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.001",
            "attack_object_name": "Password Guessing",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "Amazon Cognito",
            "mapping_type": "technique-scores",
            "score_category": "Protect",
            "score_value": "Significant",
            "related_score": "T1110",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.002",
            "attack_object_name": "Password Cracking",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "Amazon Cognito",
            "mapping_type": "technique-scores",
            "score_category": "Protect",
            "score_value": "Significant",
            "related_score": "T1110",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.003",
            "attack_object_name": "Password Spraying",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "Amazon Cognito",
            "mapping_type": "technique-scores",
            "score_category": "Protect",
            "score_value": "Significant",
            "related_score": "T1110",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.004",
            "attack_object_name": "Credential Stuffing",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "Amazon Cognito",
            "mapping_type": "technique-scores",
            "score_category": "Protect",
            "score_value": "Significant",
            "related_score": "T1110",
        },
        {
            "comments": "comment",
            "attack_object_id": "T1078",
            "attack_object_name": "Valid Accounts",
            "references": [
                "https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html",
                "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-compromised-credentials.html",
                "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html",
            ],
            "tags": ["Identity"],
            "mapping_description": "",
            "capability_id": "Amazon Cognito",
            "mapping_type": "technique-scores",
            "score_category": "Protect",
            "score_value": "Minimal",
            "related_score": "",
        },
        {
            "comments": "score comment",
            "attack_object_id": "T1078.004",
            "attack_object_name": "Cloud Accounts",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "Amazon Cognito",
            "mapping_type": "technique-scores",
            "score_category": "Protect",
            "score_value": "Partial",
            "related_score": "T1078",
        },
        {
            "comments": "comment",
            "attack_object_id": "T1110",
            "attack_object_name": "Brute Force",
            "references": [
                "https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html",
                "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-compromised-credentials.html",
                "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html",
            ],
            "tags": ["Identity"],
            "mapping_description": "",
            "capability_id": "Amazon Cognito",
            "mapping_type": "technique-scores",
            "score_category": "Protect",
            "score_value": "Significant",
            "related_score": "",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.001",
            "attack_object_name": "Password Guessing",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "Amazon Cognito",
            "mapping_type": "technique-scores",
            "score_category": "Protect",
            "score_value": "Significant",
            "related_score": "T1110",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.002",
            "attack_object_name": "Password Cracking",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "Amazon Cognito",
            "mapping_type": "technique-scores",
            "score_category": "Protect",
            "score_value": "Significant",
            "related_score": "T1110",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.003",
            "attack_object_name": "Password Spraying",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "Amazon Cognito",
            "mapping_type": "technique-scores",
            "score_category": "Protect",
            "score_value": "Significant",
            "related_score": "T1110",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.004",
            "attack_object_name": "Credential Stuffing",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "Amazon Cognito",
            "mapping_type": "technique-scores",
            "score_category": "Protect",
            "score_value": "Significant",
            "related_score": "T1110",
        },
    ],
}

expected_veris_mapping_json = {
    "metadata": {
        "mapping_version": "1.9",
        "attack_version": "9.0",
        "technology_domain": "enterprise",
        "author": "",
        "contact": "",
        "creation_date": "02/03/2021",
        "last_update": "10/27/2021",
        "organization": "",
        "mapping_framework": "veris",
        "mapping_framework_version": "1.3.5",
        "mappings_types": ["related-to"],
    },
    "attack_objects": [
        {
            "comments": "",
            "attack_object_id": "T1047",
            "attack_object_name": "Windows Management Instrumentation",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "action.hacking.variety.Abuse of functionality",
            "mapping_type": "related-to",
        },
        {
            "comments": "",
            "attack_object_id": "T1047",
            "attack_object_name": "Windows Management Instrumentation",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "action.hacking.vector.Command shell",
            "mapping_type": "related-to",
        },
        {
            "comments": "",
            "attack_object_id": "T1053",
            "attack_object_name": "Scheduled Task/Job",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "action.hacking.variety.Abuse of functionality",
            "mapping_type": "related-to",
        },
    ],
}

expected_cve_mapping_json = {
    "metadata": {
        "mapping_version": "",
        "attack_version": "9.0",
        "technology_domain": "enterprise",
        "author": "",
        "contact": "",
        "creation_date": "02/03/2021",
        "last_update": "10/27/2021",
        "organization": "",
        "mapping_framework": "cve",
        "mapping_framework_version": "",
        "mappings_types": [
            "Primary Impact",
            "Secondary Impact",
            "Exploitation Technique",
            "Uncategorized",
        ],
    },
    "attack_objects": [
        {
            "comments": "",
            "attack_object_id": "T1059",
            "attack_object_name": "Name for T1059",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "CVE-2019-15243",
            "mapping_type": "Primary Impact",
        },
        {
            "comments": "",
            "attack_object_id": "T1190",
            "attack_object_name": "Name for T1190",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "CVE-2019-15243",
            "mapping_type": "Exploitation Technique",
        },
        {
            "comments": "",
            "attack_object_id": "T1078",
            "attack_object_name": "Name for T1078",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "CVE-2019-15243",
            "mapping_type": "Exploitation Technique",
        },
        {
            "comments": "",
            "attack_object_id": "T1068",
            "attack_object_name": "Name for T1068",
            "references": [],
            "tags": [],
            "mapping_description": "",
            "capability_id": "CVE-2019-15976",
            "mapping_type": "Primary Impact",
        },
    ],
}
