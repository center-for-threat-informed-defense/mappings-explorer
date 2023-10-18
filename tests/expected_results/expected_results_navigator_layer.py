expected_nist_navigator_layer = {
    "name": "nist overview",
    "versions": {"navigator": "4.8.0", "layer": "4.4", "attack": "13.0"},
    "sorting": 3,
    "description": "nist heatmap overview of nist mappings, scores are the number of associated entries",
    "domain": "enterprise-attack",
    "techniques": [
        {"techniqueID": "T1137", "score": 1, "comment": "Related to AC-10"},
        {"techniqueID": "T1137.002", "score": 1, "comment": "Related to AC-10"},
    ],
    "gradient": {"colors": ["#ffe766", "#ffaf66"], "minValue": 1, "maxValue": 1},
}

expected_security_stack_navigator_layer = {
    "name": "security stack overview",
    "versions": {"navigator": "4.8.0", "layer": "4.4", "attack": 9},
    "sorting": 3,
    "description": "security stack heatmap overview of security stack mappings, scores are the number of associated entries",
    "domain": "enterprise-attack",
    "techniques": [
        {
            "techniqueID": "T1078",
            "score": 2,
            "comment": "Related to Amazon Cognito, Amazon Cognito",
        },
        {
            "techniqueID": "T1078.004",
            "score": 2,
            "comment": "Related to Amazon Cognito, Amazon Cognito",
        },
        {
            "techniqueID": "T1110",
            "score": 2,
            "comment": "Related to Amazon Cognito, Amazon Cognito",
        },
        {
            "techniqueID": "T1110.001",
            "score": 2,
            "comment": "Related to Amazon Cognito, Amazon Cognito",
        },
        {
            "techniqueID": "T1110.002",
            "score": 2,
            "comment": "Related to Amazon Cognito, Amazon Cognito",
        },
        {
            "techniqueID": "T1110.003",
            "score": 2,
            "comment": "Related to Amazon Cognito, Amazon Cognito",
        },
        {
            "techniqueID": "T1110.004",
            "score": 2,
            "comment": "Related to Amazon Cognito, Amazon Cognito",
        },
    ],
    "gradient": {"colors": ["#ffe766", "#ffaf66"], "minValue": 2, "maxValue": 2},
}

expected_veris_navigator_layer = {
    "name": "veris overview",
    "versions": {"navigator": "4.8.0", "layer": "4.4", "attack": "9.0"},
    "sorting": 3,
    "description": "veris heatmap overview of veris mappings, scores are the number of associated entries",
    "domain": "enterprise-attack",
    "techniques": [
        {
            "techniqueID": "T1047",
            "score": 2,
            "comment": "Related to action.hacking.variety.Abuse of functionality, action.hacking.vector.Command shell",
        },
        {
            "techniqueID": "T1053",
            "score": 1,
            "comment": "Related to action.hacking.variety.Abuse of functionality",
        },
    ],
    "gradient": {"colors": ["#ffe766", "#ffaf66"], "minValue": 1, "maxValue": 2},
}

expected_cve_navigator_layer = {
    "name": "cve overview",
    "versions": {"navigator": "4.8.0", "layer": "4.4", "attack": "9.0"},
    "sorting": 3,
    "description": "cve heatmap overview of cve mappings, scores are the number of associated entries",
    "domain": "enterprise-attack",
    "techniques": [
        {
            "techniqueID": "T1059",
            "score": 1,
            "comment": "Related to CVE-2019-15243",
        },
        {
            "techniqueID": "T1190",
            "score": 1,
            "comment": "Related to CVE-2019-15243",
        },
        {
            "techniqueID": "T1078",
            "score": 1,
            "comment": "Related to CVE-2019-15243",
        },
        {
            "techniqueID": "T1068",
            "score": 1,
            "comment": "Related to CVE-2019-15976",
        },
    ],
    "gradient": {"colors": ["#ffe766", "#ffaf66"], "minValue": 1, "maxValue": 1},
}
