class Technique:
    id = ""
    label = ""
    description = ""
    mappings = []
    num_mappings = ""
    subtechniques = []
    num_subtechniques = 0


class Tactic:
    id = ""
    label = ""
    description = ""
    techniques = []
    num_techniques = ""
    mappings = []
    num_mappings = 0


all_attack_versions = [
    "8.2",
    "9.0",
    "10.0",
    "10.1",
    "11.0",
    "11.1",
    "11.2",
    "11.3",
    "12.0",
    "12.1",
    # "13.0",
    # "13.1",
    # "14.0",
    "14.1",
    # "15.0",
    "15.1",
    # "16.0",
    "16.1",
    # "17.0",
    "17.1",
]

attack_domains = {
    "Enterprise": [
        "8.2",
        "9.0",
        "10.0",
        "10.1",
        "11.0",
        "11.1",
        "11.2",
        "11.3",
        "12.0",
        "12.1",
        # "13.0",
        # "13.1",
        # "14.0",
        "14.1",
        # "15.0",
        "15.1",
        # "16.0",
        "16.1",
        # "17.0",
        "17.1",
    ],
    "ICS": [
        "8.2",
        "9.0",
        "10.0",
        "10.1",
        "11.0",
        "11.1",
        "11.2",
        "11.3",
        "12.0",
        "12.1",
        # "13.0",
        # "13.1",
        # "14.0",
        # "14.1",
        # "15.0",
        "15.1",
        # "16.0",
        "16.1",
    ],
    "Mobile": [
        "8.2",
        "9.0",
        "10.0",
        "10.1",
        # "11.0",
        # "11.1",
        # "11.2",
        # "11.3",
        "12.0",
        "12.1",
        # "13.0",
        # "13.1",
        # "14.0",
        # "14.1",
        # "15.0",
        # "16.0",
        "16.1",
    ],
}


matrix_order = {
    "enterprise": [
        "TA0043",
        "TA0042",
        "TA0001",
        "TA0002",
        "TA0003",
        "TA0004",
        "TA0005",
        "TA0006",
        "TA0007",
        "TA0008",
        "TA0009",
        "TA0011",
        "TA0010",
        "TA0040",
    ],
    "ics": [
        "TA0108",
        "TA0104",
        "TA0110",
        "TA0111",
        "TA0103",
        "TA0102",
        "TA0109",
        "TA0100",
        "TA0101",
        "TA0107",
        "TA0106",
        "TA0105",
    ],
    "mobile": [
        "TA0027",
        "TA0041",
        "TA0028",
        "TA0029",
        "TA0030",
        "TA0031",
        "TA0032",
        "TA0033",
        "TA0035",
        "TA0037",
        "TA0036",
        "TA0034",
        "TA0038",
        "TA0039",
    ],
}

platform_options = {
    "enterprise": [
        "PRE",
        "Windows",
        "macOS",
        "Linux",
        "Cloud Office Suite",
        "Cloud Identity Provider",
        "Cloud SaaS",
        "Cloud IaaS",
        "Network Devices",
        "Containers",
        "ESXi",
    ],
    "ics": [],
    "mobile": [
        "Android",
        "iOS",
    ],
}
