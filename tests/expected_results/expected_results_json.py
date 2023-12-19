expected_nist_mapping_json = {
    "metadata": {
        "mapping_version": "",
        "attack_version": "13.0",
        "technology_domain": "enterprise",
        "author": "",
        "contact": "",
        "creation_date": "01/13/2022",
        "last_update": "01/13/2022",
        "organization": "",
        "mapping_framework": "nist_800_53",
        "mapping_framework_version": "rev1",
        "groups": {"AC": "Access Control"},
    },
    "mapping_objects": [
        {
            "comments": "",
            "attack_object_id": "T1137",
            "attack_object_name": "Office Application Startup",
            "references": [],
            "capability_description": "Concurrent Session Control",
            "capability_id": "AC-10",
            "group": "AC",
            "status": "complete",
        },
        {
            "comments": "",
            "attack_object_id": "T1137.002",
            "attack_object_name": "Office Test",
            "references": [],
            "capability_description": "Concurrent Session Control",
            "capability_id": "AC-10",
            "group": "AC",
            "status": "complete",
        },
    ],
}

expected_security_stack_mapping_json = {
    "metadata": {
        "mapping_version": "1",
        "attack_version": "9.0",
        "technology_domain": "enterprise",
        "author": "",
        "contact": "ctid@mitre-engenuity.org",
        "creation_date": "09/21/2021",
        "last_update": "09/21/2021",
        "organization": "",
        "mapping_framework": "aws",
        "mapping_framework_version": "09/21/2021",
        "groups": {"amazon_cognito": "Amazon Cognito"},
    },
    "mapping_objects": [
        {
            "comments": "comment",
            "attack_object_id": "T1078",
            "attack_object_name": "Valid Accounts",
            "references": [
                "https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html",
                "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-compromised-credentials.html",
                "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html",
            ],
            "capability_description": "Amazon Cognito",
            "capability_id": "Amazon Cognito",
            "score_category": "protect",
            "score_value": "minimal",
            "related_score": "",
            "group": "amazon_cognito",
            "status": "complete",
        },
        {
            "comments": "score comment",
            "attack_object_id": "T1078.004",
            "attack_object_name": "Cloud Accounts",
            "references": [],
            "capability_description": "Amazon Cognito",
            "capability_id": "Amazon Cognito",
            "score_category": "protect",
            "score_value": "partial",
            "related_score": "T1078",
            "group": "amazon_cognito",
            "status": "complete",
        },
        {
            "comments": "technique score comment",
            "attack_object_id": "T1110",
            "attack_object_name": "Brute Force",
            "references": [
                "https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html",
                "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-compromised-credentials.html",
                "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html",
            ],
            "capability_description": "Amazon Cognito",
            "capability_id": "Amazon Cognito",
            "score_category": "protect",
            "score_value": "significant",
            "related_score": "",
            "group": "amazon_cognito",
            "status": "complete",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.001",
            "attack_object_name": "Password Guessing",
            "references": [],
            "capability_description": "Amazon Cognito",
            "capability_id": "Amazon Cognito",
            "score_category": "protect",
            "score_value": "significant",
            "related_score": "T1110",
            "group": "amazon_cognito",
            "status": "complete",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.002",
            "attack_object_name": "Password Cracking",
            "references": [],
            "capability_description": "Amazon Cognito",
            "capability_id": "Amazon Cognito",
            "score_category": "protect",
            "score_value": "significant",
            "related_score": "T1110",
            "group": "amazon_cognito",
            "status": "complete",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.003",
            "attack_object_name": "Password Spraying",
            "references": [],
            "capability_description": "Amazon Cognito",
            "capability_id": "Amazon Cognito",
            "score_category": "protect",
            "score_value": "significant",
            "related_score": "T1110",
            "group": "amazon_cognito",
            "status": "complete",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.004",
            "attack_object_name": "Credential Stuffing",
            "references": [],
            "capability_description": "Amazon Cognito",
            "capability_id": "Amazon Cognito",
            "score_category": "protect",
            "score_value": "significant",
            "related_score": "T1110",
            "group": "amazon_cognito",
            "status": "complete",
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
            "capability_description": "Amazon Cognito",
            "capability_id": "Amazon Cognito",
            "score_category": "protect",
            "score_value": "minimal",
            "related_score": "",
            "group": "amazon_cognito",
            "status": "complete",
        },
        {
            "comments": "score comment",
            "attack_object_id": "T1078.004",
            "attack_object_name": "Cloud Accounts",
            "references": [],
            "capability_description": "Amazon Cognito",
            "capability_id": "Amazon Cognito",
            "score_category": "protect",
            "score_value": "partial",
            "related_score": "T1078",
            "group": "amazon_cognito",
            "status": "complete",
        },
        {
            "comments": "technique score comment",
            "attack_object_id": "T1110",
            "attack_object_name": "Brute Force",
            "references": [
                "https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html",
                "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-compromised-credentials.html",
                "https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html",
            ],
            "capability_description": "Amazon Cognito",
            "capability_id": "Amazon Cognito",
            "score_category": "protect",
            "score_value": "significant",
            "related_score": "",
            "group": "amazon_cognito",
            "status": "complete",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.001",
            "attack_object_name": "Password Guessing",
            "references": [],
            "capability_description": "Amazon Cognito",
            "capability_id": "Amazon Cognito",
            "score_category": "protect",
            "score_value": "significant",
            "related_score": "T1110",
            "group": "amazon_cognito",
            "status": "complete",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.002",
            "attack_object_name": "Password Cracking",
            "references": [],
            "capability_description": "Amazon Cognito",
            "capability_id": "Amazon Cognito",
            "score_category": "protect",
            "score_value": "significant",
            "related_score": "T1110",
            "group": "amazon_cognito",
            "status": "complete",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.003",
            "attack_object_name": "Password Spraying",
            "references": [],
            "capability_description": "Amazon Cognito",
            "capability_id": "Amazon Cognito",
            "score_category": "protect",
            "score_value": "significant",
            "related_score": "T1110",
            "group": "amazon_cognito",
            "status": "complete",
        },
        {
            "comments": "score-comment",
            "attack_object_id": "T1110.004",
            "attack_object_name": "Credential Stuffing",
            "references": [],
            "capability_description": "Amazon Cognito",
            "capability_id": "Amazon Cognito",
            "score_category": "protect",
            "score_value": "significant",
            "related_score": "T1110",
            "group": "amazon_cognito",
            "status": "complete",
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
        "creation_date": "08/26/2021",
        "last_update": "08/26/2021",
        "organization": "",
        "mapping_framework": "veris",
        "mapping_framework_version": "1.3.5",
        "groups": {"action.hacking": "action.hacking"},
    },
    "mapping_objects": [
        {
            "comments": "",
            "attack_object_id": "T1047",
            "attack_object_name": "Windows Management Instrumentation",
            "references": [],
            "capability_description": "Abuse of functionality",
            "capability_id": "action.hacking.variety.Abuse of functionality",
            "group": "action.hacking",
            "status": "complete",
        },
        {
            "comments": "",
            "attack_object_id": "T1047",
            "attack_object_name": "Windows Management Instrumentation",
            "references": [],
            "capability_description": "Remote shell",
            "capability_id": "action.hacking.vector.Command shell",
            "group": "action.hacking",
            "status": "complete",
        },
        {
            "comments": "",
            "attack_object_id": "T1053",
            "attack_object_name": "Scheduled Task/Job",
            "references": [],
            "capability_description": "Abuse of functionality",
            "capability_id": "action.hacking.variety.Abuse of functionality",
            "group": "action.hacking",
            "status": "complete",
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
        "creation_date": "10/21/2021",
        "last_update": "10/21/2021",
        "organization": "",
        "mapping_framework": "cve",
        "mapping_framework_version": "10/21/2021",
        "groups": {"2019": "2019 CVEs"},
    },
    "mapping_objects": [
        {
            "comments": "",
            "attack_object_id": "T1059",
            "attack_object_name": "Name for T1059",
            "references": [],
            "capability_description": "",
            "capability_id": "CVE-2019-15243",
            "group": "2019",
            "status": "complete",
        },
        {
            "comments": "",
            "attack_object_id": "T1190",
            "attack_object_name": "Name for T1190",
            "references": [],
            "capability_description": "",
            "capability_id": "CVE-2019-15243",
            "group": "2019",
            "status": "complete",
        },
        {
            "comments": "",
            "attack_object_id": "T1078",
            "attack_object_name": "Name for T1078",
            "references": [],
            "capability_description": "",
            "capability_id": "CVE-2019-15243",
            "group": "2019",
            "status": "complete",
        },
        {
            "comments": "",
            "attack_object_id": "T1068",
            "attack_object_name": "Name for T1068",
            "references": [],
            "capability_description": "",
            "capability_id": "CVE-2019-15976",
            "group": "2019",
            "status": "complete",
        },
    ],
}
