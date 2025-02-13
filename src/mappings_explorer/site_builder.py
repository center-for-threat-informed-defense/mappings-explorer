import argparse
import json
import os
import shutil
import zipfile

import requests
from loguru import logger
from lunr import lunr
from mapex_convert.read_files import (
    read_yaml_file,
)

from .attack_query import create_attack_jsons, get_attack_data, load_tactic_structure
from .template import (
    DATA_DIR,
    PUBLIC_DIR,
    ROOT_DIR,
    TEMPLATE_DIR,
    load_template,
)


class Capability:
    id = ""
    label = ""
    description = ""
    mappings = []
    capability_group = ""
    num_mappings = 0
    non_mappable_comment = ""


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


class CapabilityGroup:
    id = ""
    label = ""
    num_mappings = ""
    mappings = []
    capabilities = []
    num_capabilities = 0


class ExternalControl:
    id = ""
    label = ""
    description = ""
    resources = []
    version = ""
    versions = []
    attackVersion = ""
    attackVersions = []
    attackDomain = ""
    attackDomains = []
    validVersions = []
    capability_groups = []
    mappings = []
    capabilities = []
    non_mappables = []
    has_non_mappables = True
    has_non_mappable_comments = False
    additional_artifacts = {}


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


def load_projects():
    nist = ExternalControl()
    nist.id = "nist"
    nist.label = "NIST 800-53"
    nist.description = """National Institute of Standards in Technology (NIST) Special
     Publication 800-53 provides a catalog of security and privacy controls for the
     protection of information systems and organizations from a diverse set of threats
     and risks. These mappings provide resources for security control coverage
     against real-world threats as described in the MITRE ATT&CK® knowledge base and
     provide a foundation for integrating ATT&CK-based threat information into the
     risk management process."""
    nist.versions = ["rev5", "rev4"]
    nist.attackVersions = [
        "14.1",
        "12.1",
        "10.1",
        "9.0",
        "8.2",
    ]
    nist.validVersions = [
        ("rev4", "8.2", "Enterprise"),
        ("rev5", "8.2", "Enterprise"),
        ("rev4", "9.0", "Enterprise"),
        ("rev5", "9.0", "Enterprise"),
        ("rev4", "10.1", "Enterprise"),
        ("rev5", "10.1", "Enterprise"),
        ("rev4", "12.1", "Enterprise"),
        ("rev5", "12.1", "Enterprise"),
        ("rev4", "14.1", "Enterprise"),
        ("rev5", "14.1", "Enterprise"),
    ]
    nist.attackDomains = ["Enterprise"]
    nist.has_non_mappables = False
    nist.attackDomain = nist.attackDomains[0]
    nist.resources = [
        {
            "link": "about/methodology/nist-methodology/",
            "label": "NIST 800-53 Mapping Methodology",
        },
        {"link": "about/methodology/nist-scope/", "label": "Mapping Scope"},
    ]

    veris = ExternalControl()
    veris.id = "veris"
    veris.label = "VERIS"
    veris.description = """The Vocabulary for Event Recording and Incident Sharing
    (VERIS) provides a common language for describing security incidents in a structured
    and repeatable manner that allows for the analysis of data across a variety of
    incidents. These mappings provide the context to better connect the who, what, and
    why captured in VERIS incident representation with the when and how described in
    MITRE ATT&CK® adversary behavioral tactics and techniques."""
    veris.versions = ["1.4.0", "1.3.7", "1.3.5"]
    veris.attackDomains = ["Enterprise", "ICS", "Mobile"]
    veris.attackDomain = veris.attackDomains[0]
    veris.attackVersions = [
        "16.1",
        "12.1",
        "9.0",
    ]
    veris.validVersions = [
        ("1.3.5", "9.0", "Enterprise"),
        ("1.3.7", "12.1", "ICS"),
        ("1.3.7", "12.1", "Mobile"),
        ("1.3.7", "12.1", "Enterprise"),
        ("1.4.0", "16.1", "Mobile"),
        ("1.4.0", "16.1", "ICS"),
        ("1.4.0", "16.1", "Enterprise"),
    ]
    veris.mappings = []
    veris.resources = [
        {
            "link": "about/methodology/veris-methodology/",
            "label": "VERIS Mapping Methodology",
        },
    ]
    veris.additional_artifacts = {
        "1.3.7": {
            "12.1": [
                {
                    "link": "legacy/veris-1.3.7_attack-12.1-groups.json",
                    "label": "Group Mappings – JSON",
                },
                {
                    "link": "legacy/veris-1.3.7_attack-12.1-groups.xlsx",
                    "label": "Group Mappings – Excel",
                },
            ]
        }
    }

    kev = ExternalControl()
    kev.id = "kev"
    kev.label = "Known Exploited Vulnerabilities"
    kev.description = """The Known Exploited Vulnerabilities (KEV) Catalog is an
        authoritative source of vulnerabilities exploited in the wild maintained by the
        Department of Homeland Security (DHS) Cybersecurity and Infrastructure Security
        Agency (CISA). Vulnerabilities in the KEV Catalog are contained in the Common
        Vulnerabilities and Exposures (CVE®) List, which identifies and defines publicly
        known cybersecurity vulnerabilities. These mappings use the behaviors described
        in MITRE ATT&CK® to connect known exploited CVEs to publicly reported methods
        and impacts of adversary exploitation. Mapped ATT&CK techniques enable defenders
        to take a threat-informed approach to vulnerability management. With knowledge
        of mapped adversary behaviors, defenders will better understand how a
        vulnerability can impact them, helping defenders integrate vulnerability
        information into their risk models and identify appropriate compensating
        security controls."""

    kev.attackDomains = ["Enterprise", "Mobile"]
    kev.attackDomain = kev.attackDomains[0]
    kev.versions = ["02.13.2025"]
    kev.attackVersions = ["15.1"]
    kev.validVersions = [
        ("02.13.2025", "15.1", "Mobile"),
        ("02.13.2025", "15.1", "Enterprise"),
    ]
    kev.has_non_mappables = False
    kev.mappings = []
    kev.resources = [
        {
            "link": "about/methodology/cve-methodology/",
            "label": "CVE Mapping Methodology",
        },
        {
            "link": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "label": "CISA Known Exploited Vulnerabilities Catalog",
            "external": True,
        },
    ]

    aws = ExternalControl()
    aws.id = "aws"
    aws.label = "AWS"
    aws.description = """Amazon Web Services (AWS) is a widely used cloud computing
      platform. These mappings connect the security controls native to the (AWS)
      platformto MITRE ATT&CK®, providing resources to assess how to protect, detect,
      and respond to real-world threats as described in the ATT&CK knowledge base.
        """
    aws.attackDomains = ["Enterprise"]
    aws.attackDomain = aws.attackDomains[0]
    aws.attackVersions = ["16.1", "9.0"]
    aws.versions = ["12.12.2024", "09.21.2021"]
    aws.validVersions = [
        ("09.21.2021", "9.0", "Enterprise"),
        ("12.12.2024", "16.1", "Enterprise"),
    ]
    aws.mappings = []
    aws.resources = [
        {
            "link": "about/methodology/ssm-methodology/",
            "label": "Security Stack Mapping Methodology",
        },
    ]
    aws.has_non_mappable_comments = True

    azure = ExternalControl()
    azure.id = "azure"
    azure.label = "Azure"
    azure.description = """Azure is a widely used cloud computing platform. These
    mappings connect the security controls native to the Azure platform to MITRE
    ATT&CK®, providing resources to assess how to protect, detect, and respond to
    real-world threats as described in the ATT&CK knowledge base."""
    azure.attackDomains = ["Enterprise"]
    azure.attackDomain = azure.attackDomains[0]
    azure.attackVersions = ["8.2"]
    azure.versions = ["06.29.2021"]
    azure.validVersions = [
        ("06.29.2021", "8.2", "Enterprise"),
    ]
    azure.mappings = []
    azure.resources = [
        {
            "link": "about/methodology/ssm-methodology/",
            "label": "Security Stack Mapping Methodology",
        },
    ]
    azure.has_non_mappable_comments = True

    gcp = ExternalControl()
    gcp.id = "gcp"
    gcp.label = "GCP"
    gcp.description = """Google Cloud Platform (GCP) is a widely used cloud computing
      platform. These mappings connect the security controls native to the GCP platform
      to MITRE ATT&CK® providing resources to assess how to protect, detect, and respond
      to real-world threats as described in the ATT&CK knowledge base."""

    gcp.attackDomains = ["Enterprise"]
    gcp.attackDomain = gcp.attackDomains[0]
    gcp.attackVersions = ["10.0"]
    gcp.attackVersion = gcp.attackVersions[0]
    gcp.versions = ["06.28.2022"]
    gcp.validVersions = [
        ("06.28.2022", "10.0", "Enterprise"),
    ]
    gcp.mappings = []
    gcp.resources = [
        {
            "link": "about/methodology/ssm-methodology/",
            "label": "Security Stack Mapping Methodology",
        },
    ]
    gcp.has_non_mappable_comments = True

    m365 = ExternalControl()
    m365.id = "m365"
    m365.label = "M365"
    m365.description = """Microsoft 365 (M365) is a widely used Software as a Service
        (SaaS) product family of productivity software, collaboration, and cloud-based
        services. These mappings connect the security controls native to M365 product
        areas to MITRE ATT&CK® providing resources to assess how to protect, detect, and
        respond to real-world threats as described in the ATT&CK knowledge base."""

    m365.attackDomains = ["Enterprise"]
    m365.attackDomain = m365.attackDomains[0]
    m365.attackVersions = ["14.1"]
    m365.attackVersion = m365.attackVersions[0]
    m365.versions = ["12.11.2023"]
    m365.validVersions = [
        ("12.11.2023", "14.1", "Enterprise"),
    ]
    m365.mappings = []
    m365.resources = [
        {
            "link": "about/methodology/ssm-methodology/",
            "label": "Security Stack Mapping Methodology",
        },
        {
            "link": "https://www.cisecurity.org/benchmark/microsoft_365",
            "label": "CIS Microsoft 365 Benchmark (External link)",
            "external": True,
        },
    ]
    artifact_prefix = "legacy/m365-12.11.2023_attack-14.1-enterprise_"
    m365.additional_artifacts = {
        "12.11.2023": {
            "14.1": [
                {
                    "link": artifact_prefix + "E3_navigator_layers.json",
                    "label": "Navigator Layer (E3 License)",
                },
                {
                    "link": artifact_prefix + "E5_navigator_layers.json",
                    "label": "Navigator Layer (E5 License)",
                },
            ]
        }
    }
    m365.has_non_mappable_comments = False

    intel_vpro = ExternalControl()
    intel_vpro.id = "intel-vpro"
    intel_vpro.label = "Intel vPro"
    intel_vpro.description = """Advanced security features in Intel vPro hardware can be
        leveraged by operating system (OS) and security software features across system
        attack surfaces to optimize mitigations against cyber threats. These mappings
        demonstrate the practical application of hardware features by capabilities in
        Microsoft Windows 11 with Defender and CrowdStrike Falcon to assist defenders in
        understanding how these integrated capabilities can help mitigate real-world
        adversary behaviors as described in MITRE ATT&CK®."""

    intel_vpro.attackDomains = ["Enterprise"]
    intel_vpro.attackDomain = intel_vpro.attackDomains[0]
    intel_vpro.attackVersions = ["15.1"]
    intel_vpro.attackVersion = intel_vpro.attackVersions[0]
    intel_vpro.versions = ["08.20.2024"]
    intel_vpro.validVersions = [
        ("08.20.2024", "15.1", "Enterprise"),
    ]
    intel_vpro.mappings = []
    intel_vpro.resources = [
        {
            "link": "about/methodology/ssm-methodology/",
            "label": "Security Stack Mapping Methodology",
        }
    ]
    intel_vpro.has_non_mappable_comments = False

    projects = [intel_vpro, nist, kev, veris, azure, gcp, aws, m365]
    return projects


def replace_mapping_type(mapping: dict, type_list: list):
    """Replace the mapping_type value with the more descriptive name found in mappings
    file metadata

    Args:
        mapping: individual mapping object to replace mapping_type value on
        typeList: table of mapping_type values to lookup and replace
    """
    for mapping_type in type_list:
        if mapping["mapping_type"] == mapping_type:
            return type_list[mapping_type]["name"]
        elif (
            mapping["mapping_type"] == "non_mappable"
            or mapping["status"] == "non_mappable"
        ):
            return "non_mappable"


def parse_capability_groups(
    project: ExternalControl,
    attack_version: str,
    project_version: str,
    attack_domain: str,
):
    """Load mappings data from files, then find and create capability group objects
    and capability objects for the objects in the mapping files

    Args:
        project: the mapping framework to parse mappings for
        attack_version: version of ATT&CK to parse mappings for
        project_version: version of project to parse mappings for
        attack_domain: domain of ATT&CK to parse mappings for
         (ex. Enterprise, mobile, or ics)
    """
    project_id = project.id
    if project_id == "nist":
        project_id = "nist_800_53"
    filepath = PUBLIC_DIR / "data" / project_id
    full_path = (
        filepath
        / ("attack-" + attack_version)
        / (project_id + "-" + project_version.replace("/", "."))
        / attack_domain.lower()
        / (
            project_id
            + "-"
            + project_version.replace("/", ".")
            + "_attack-"
            + attack_version
            + "-"
            + attack_domain.lower()
            + ".json"
        )
    )
    f = open(full_path, "r")
    data = json.load(f)
    metadata = data["metadata"]
    project.capability_groups = []

    mappings = data["mapping_objects"]
    for mapping in mappings:
        mapping["mapping_type"] = replace_mapping_type(
            mapping, metadata["mapping_types"]
        )
        mapping["framework"] = project.id
    if metadata.get("capability_groups"):
        for i in metadata["capability_groups"]:
            g = CapabilityGroup()
            g.id = i
            g.label = metadata["capability_groups"][i]
            g.capabilities = []
            project.capability_groups.append(g)
            filtered_mappings = [
                m
                for m in mappings
                if (m.get("capability_group") == g.id and m["status"] != "non_mappable")
            ]
            g.num_mappings = len(filtered_mappings)
            g.mappings = filtered_mappings
            logger.trace(
                "     found {count} mappings in group {g_label}",
                count=len(filtered_mappings),
                g_label=g.label,
            )
    parse_capabilities(
        mappings, project, project_version, attack_version, attack_domain
    )
    project.mappings.append(
        {
            "attack_version": attack_version,
            "project_version": project_version,
            "attack_domain": attack_domain,
            "mappings": [m for m in mappings if m["status"] != "non_mappable"],
        }
    )
    if project.id == "nist" or project.id == "kev" or project.id == "intel-vpro":
        # if the project has non mappable comments and we are therefore building the
        # capability page even though it is non_mappable, get non_mappable capabilities'
        # descriptions as well
        capabilities_to_get_description = (
            project.capabilities
            if not project.has_non_mappable_comments
            else project.capabilities.extend(project.non_mappables)
        )
        for capability in capabilities_to_get_description:
            get_description_for_capability(capability, project, project_version)
    if (
        project.id == "aws"
        or project.id == "gcp"
        or project.id == "azure"
        or project.id == "m365"
    ):
        get_security_stack_descriptions(project=project)


def get_security_stack_descriptions(project: ExternalControl):
    """Pull capability descriptions from data files for security stack projects

    Args:
        project: project to provide descriptions for
    """
    root = DATA_DIR / "SecurityStack"
    data_dir = os.listdir(root)
    for dir in data_dir:
        if dir.lower() == project.id:
            rootdir = root / dir

    capabilities = project.capabilities
    # if the project has non mappable comments and we are therefore building the
    # capability page even though it is non_mappable, get non_mappable capabilities'
    # descriptions as well
    if project.has_non_mappable_comments:
        capabilities.extend(project.non_mappables)

    # iterate through mappings files
    for file in os.listdir(rootdir):
        data = read_yaml_file(rootdir / file)
        id = data.get("id", None)
        name = data["name"]
        description = data["description"]
        for c in capabilities:
            matchId = c.id == id
            matchName = c.id.lower().replace(" ", "_") == name.lower().replace(" ", "_")
            if matchId or matchName:
                c.description = description
                c.label = data["name"]
                break


def get_cve_description(project: ExternalControl, version: str, capability: Capability):
    """Query CVE endpoint to get a description for the given capability and save it to
    the description file

    Args:
        project: project where capability is from
        version: version of the project to query for (always constant for CVE)
        capability: object that needs a description
    """
    root = DATA_DIR
    file_name = f"{project.id}-{version}_descriptions.json"
    try:
        response = requests.get(
            "https://cveawg.mitre.org/api/cve/" + capability.id
        ).json()
        descriptions = response["containers"]["cna"]["descriptions"]
        capability.description = descriptions[0]["value"]
    except Exception:
        logger.exception(
            "Error loading description for CVE capability {c_id}", c_id=capability.id
        )
    entry = {"id": capability.id, "description": capability.description}
    entries = []
    with open(root / file_name, "r") as openfile:
        entries = json.load(openfile)
    entries.append(entry)
    json_object = json.dumps(entries, indent=4)
    with open(root / file_name, "w") as outfile:
        outfile.write(json_object)


def get_description_for_capability(
    capability: Capability, project: ExternalControl, version: str
):
    """Pull description for each capability either from saved capability file
    or direct another method to query for a description

    Args:
        capability: object that needs a description
        project: project where capability is from
        version: version of the project to query for (always constant for CVE)
    """
    if project.id == "nist":
        folder_name = DATA_DIR / "NIST_800-53"
    elif project.id == "kev":
        folder_name = DATA_DIR
    elif project.id == "intel-vpro":
        folder_name = DATA_DIR / "SecurityStack" / "INTEL_VPRO"
    file_name = folder_name / f"{project.id}-{version}_descriptions.json"
    if os.path.isfile(file_name):
        try:
            with open(file_name, "r") as openfile:
                json_object = json.load(openfile)
                obj = [
                    obj["description"]
                    for obj in json_object
                    if obj["id"] == capability.id
                ]
                if len(obj) > 0:
                    capability.description = obj[0]
                else:
                    logger.trace(
                        "Getting description for capability {c_id}", c_id=capability.id
                    )
                    if project.id == "nist":
                        get_nist_description(
                            project=project, version=version, capability=capability
                        )
                    if project.id == "kev":
                        get_cve_description(
                            project=project, version=version, capability=capability
                        )
        except Exception:
            logger.exception(
                "Error loading description for capability {c_id}",
                c_id=capability.id,
            )
    else:
        # if description file doesn't already exist, create it
        with open(file_name, "w") as outfile:
            json.dump([], outfile)
        # then query for capability description
        if project.id == "nist":
            get_nist_description(
                project=project, version=version, capability=capability
            )
        if project.id == "kev":
            get_cve_description(project=project, version=version, capability=capability)


def get_nist_description(
    project: ExternalControl, version: str, capability: Capability
):
    """Query NIST endpoint to get a description for the given capability and save it to
    the description file

    Args:
        project: project where capability is from
        version: version of the project to query for
        capability: object that needs a description
    """
    root = DATA_DIR / "NIST_800-53"
    file_name = f"{project.id}-{version}_descriptions.json"

    rev5_link = "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/sp_800_53_5_1_1/element/"
    rev4_link = "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/sp_800_53_4_0_0/element/"
    link = ""
    if version == "rev4":
        link = rev4_link
    else:
        link = rev5_link

    try:
        id = capability.id
        if len(id) < 5 and version != "rev4":
            id = capability.id[0:3] + "0" + capability.id[3:4]
        response = requests.get(link + id + "/graph").json()
        elements = response["response"]["elements"]
        element_array = elements[0]["elements"][0]["elements"]
        for item in element_array:
            if item["elementTypeIdentifier"] == "discussion":
                capability.description = item["text"]
    except Exception:
        logger.exception(
            "Error loading description for NIST capability {c_id}", c_id=capability.id
        )
    entry = {"id": capability.id, "description": capability.description}
    entries = []
    with open(root / file_name, "r") as openfile:
        entries = json.load(openfile)
    entries.append(entry)
    json_object = json.dumps(entries, indent=4)
    with open(root / file_name, "w") as outfile:
        outfile.write(json_object)


def delete_all_descriptions(projects: list):
    """Delete the description files to have them be refreshed if --reset-descriptions
    flag is turned on

    Args:
        projects: list of projects to delete description files for
    """
    for project in projects:
        for version in project.versions:
            file_name = f"{project.id}-{version}_descriptions.json"
            if project.id == "kev":
                dir = DATA_DIR
            if project.id == "nist":
                dir = DATA_DIR / "NIST_800-53"

            if os.path.exists(dir / file_name):
                logger.trace("deleting descriptions file {file}", file=dir / file_name)
                os.remove(dir / file_name)


def parse_capabilities(
    mappings: list,
    project: ExternalControl,
    project_version: str,
    attack_version: str,
    attack_domain: str,
):
    """Create capability objects for each unique capability id found in list of mappings

    Args:
        mappings: list of mappings to build capability list from
        project: project associated with list of mappings
        project_version: version of project associated with list of mappings
        attack_version: version of ATT&CK associated with list of mappings
        attack_domain: domain of ATT&CK associated with list of mappings
         (ex. Enterprise, mobile, or ics)

    Returns:
        List of capability objects
    """
    allIds = [m["capability_id"] for m in mappings]
    capabilityIds = list(set(allIds))
    capabilities = []
    non_mappables = []
    for id in capabilityIds:
        c = Capability()
        c.id = id

        capability_mappable_mappings = [
            m
            for m in mappings
            if (m["capability_id"] == id) and m["status"] != "non_mappable"
        ]
        capability_non_mappables = [
            m
            for m in mappings
            if (m["capability_id"] == id) and m["status"] == "non_mappable"
        ]
        capability_not_mappable = (
            len(capability_mappable_mappings) == 0 and len(capability_non_mappables) > 0
        )

        c.num_mappings = len(capability_mappable_mappings)
        c.mappings = capability_mappable_mappings

        if not capability_not_mappable:
            c.label = capability_mappable_mappings[0]["capability_description"]
            for mapping in capability_mappable_mappings:
                mapping["project"] = project.id
                mapping["project_version"] = project_version
                mapping["attack_version"] = attack_version
                mapping["attack_domain"] = attack_domain
            if capability_mappable_mappings[0].get("capability_group"):
                capability_group = [
                    g
                    for g in project.capability_groups
                    if (g.id == mapping["capability_group"])
                ]
                capability_group[0].capabilities.append(c)
                capability_group[0].num_capabilities += 1
                c.capability_group = capability_group[0]
            else:
                print(capability_mappable_mappings[0])
            logger.trace(
                "for capability {id} the number of mappings is {count}",
                id=c.id,
                count=str(len(c.mappings)),
            )
            capabilities.append(c)
        else:
            c.label = capability_non_mappables[0]["capability_description"]
            if capability_non_mappables[0].get("capability_group"):
                capability_group = [
                    g
                    for g in project.capability_groups
                    if (g.id == capability_non_mappables[0]["capability_group"])
                ]
                c.capability_group = capability_group[0]
            c.non_mappable_comment = capability_non_mappables[0].get("comments", None)
            non_mappables.append(c)

    project.non_mappables = non_mappables
    project.capabilities = capabilities


def build_external_landing(
    project: ExternalControl,
    url_prefix,
    project_version,
    attack_version,
    domain_dir,
    mappings,
    attack_domain,
    breadcrumbs,
):
    """Create landing page for each project and build pages for each capability group
        and capability for the specified project and version combination
    Args:
        project: the project object (containing mappings and description information)
        url_prefix: the root url for the built site
        project_version: version of project to build page for
        attack_version: version of ATT&CK to build page for
        domain_dir: folder for page to be built in
        mappings: list of mappings to be displayed on the page
        attack_domain: ATT&CK domain to build page for

    """
    output_path = domain_dir / "index.html"
    template = load_template("framework_landing.html.j2")
    attack_prefix = f"""
        {url_prefix}attack/attack-{attack_version}/domain-{attack_domain.lower()}/techniques/"""
    external_prefix = f"""
        {url_prefix}external/{project.id}/attack-{attack_version}/domain-{attack_domain.lower()}/{project.id}-{project_version}/"""
    capability_group_prefix = f"{external_prefix}capability-groups/"
    standard_headers = [
        (
            ":pfx_link:",
            "capability_id",
            "Capability ID",
            "capability_id",
            external_prefix,
        ),
        (
            ":pfx_link:",
            "capability_description",
            "Capability Description",
            "capability_id",
            external_prefix,
        ),
        (":text:", "mapping_type", "Mapping Type"),
        (
            ":pfx_link:",
            "attack_object_id",
            "ATT&CK ID",
            "attack_object_id",
            attack_prefix,
        ),
        (
            ":pfx_link:",
            "attack_object_name",
            "ATT&CK Name",
            "attack_object_id",
            attack_prefix,
        ),
    ]
    info_box_headers = []
    if (
        project.id == "azure"
        or project.id == "aws"
        or project.id == "gcp"
        or project.id == "m365"
    ):
        standard_headers = [
            (
                ":pfx_link:",
                "capability_id",
                "Capability ID",
                "capability_id",
                external_prefix,
            ),
            (
                ":pfx_link:",
                "capability_description",
                "Capability Description",
                "capability_id",
                external_prefix,
            ),
            (":text:", "score_category", "Category"),
            (":text:", "score_value", "Value"),
            (
                ":pfx_link:",
                "attack_object_id",
                "ATT&CK ID",
                "attack_object_id",
                attack_prefix,
            ),
            (
                ":pfx_link:",
                "attack_object_name",
                "ATT&CK Name",
                "attack_object_id",
                attack_prefix,
            ),
        ]
        info_box_headers = [
            ("comments", "Comments"),
            ("references", "References"),
        ]
    if project.id == "intel-vpro":
        standard_headers = [
            (
                ":pfx_link:",
                "capability_id",
                "Capability ID",
                "capability_id",
                external_prefix,
            ),
            (
                ":pfx_link:",
                "capability_description",
                "Capability Description",
                "capability_id",
                external_prefix,
            ),
            (":text:", "mapping_type", "Enables"),
            (":text:", "score_category", "Category"),
            (":text:", "score_value", "Value"),
            (
                ":pfx_link:",
                "attack_object_id",
                "ATT&CK ID",
                "attack_object_id",
                attack_prefix,
            ),
            (
                ":pfx_link:",
                "attack_object_name",
                "ATT&CK Name",
                "attack_object_id",
                attack_prefix,
            ),
        ]
        info_box_headers = [
            ("comments", "Comments"),
            ("references", "References"),
        ]

    # Resolve additional download artifacts
    additional_artifacts = []
    if project_version in project.additional_artifacts:
        project_artifacts = project.additional_artifacts[project_version]
        if attack_version in project_artifacts:
            additional_artifacts = project_artifacts[attack_version]

    capability_group_headers = [
        (":pfx_link:", "id", "ID", "id", capability_group_prefix),
        (":pfx_link:", "label", "Capability Group Name", "id", capability_group_prefix),
        (":text:", "num_mappings", "Number of Mappings"),
        (":text:", "num_capabilities", "Number of Capabilities"),
    ]
    non_mappable_headers = [
        (":text:", "id", "Capability ID"),
        (":text:", "label", "Capability Description"),
    ]

    if project.has_non_mappable_comments:
        non_mappable_headers = [
            (":pfx_link:", "id", "Capability ID", "id", external_prefix),
            (
                ":pfx_link:",
                "label",
                "Capability Description",
                "id",
                external_prefix,
            ),
        ]

    project_id = project.id
    if project_id == "nist":
        project_id = "nist_800_53"
    table_max_count = 500
    stream = template.stream(
        title=project.label + " Landing",
        url_prefix=url_prefix,
        control=project.label,
        description=project.description,
        project_version=project_version.replace("/", "."),
        project_id=project_id,
        versions=project.versions,
        attack_version=attack_version,
        attackVersions=project.attackVersions,
        attack_domain=attack_domain,
        domains=project.attackDomains,
        mappings=mappings,
        standard_headers=standard_headers,
        info_box_headers=info_box_headers,
        group_headers=capability_group_headers,
        capability_groups=[g for g in project.capability_groups if g.num_mappings > 0],
        valid_versions=project.validVersions,
        breadcrumbs=breadcrumbs,
        non_mappable_headers=non_mappable_headers,
        non_mappables=project.non_mappables,
        project=project,
        additional_artifacts=additional_artifacts,
        table_max_count=999_999,
        full_link="",
        full_size=0,
    )
    stream.dump(str(output_path))

    if len(mappings) > table_max_count:
        full_size = output_path.stat().st_size
        full_path = output_path.parent / "all-data.html"
        output_path.rename(full_path)

        stream = template.stream(
            title=project.label + " Landing",
            url_prefix=url_prefix,
            control=project.label,
            description=project.description,
            project_version=project_version.replace("/", "."),
            project_id=project_id,
            versions=project.versions,
            attack_version=attack_version,
            attackVersions=project.attackVersions,
            attack_domain=attack_domain,
            domains=project.attackDomains,
            mappings=mappings,
            standard_headers=standard_headers,
            info_box_headers=info_box_headers,
            group_headers=capability_group_headers,
            capability_groups=[
                g for g in project.capability_groups if g.num_mappings > 0
            ],
            valid_versions=project.validVersions,
            breadcrumbs=breadcrumbs,
            non_mappable_headers=non_mappable_headers,
            non_mappables=project.non_mappables,
            project=project,
            additional_artifacts=additional_artifacts,
            table_max_count=table_max_count,
            full_link="all-data.html",
            full_size=full_size,
        )
        stream.dump(str(output_path))

    logger.trace(
        "Created {project_id} landing: ATT&CK version {attack_version}, ",
        "control version {project_version}, ATT&CK domain {attack_domain}",
        project_id=project.id,
        attack_version=attack_version,
        project_version=project_version,
        attack_domain=attack_domain,
    )
    capability_group_headers = [
        (":pfx_link:", "id", "Capability ID", "id", external_prefix),
        (":pfx_link:", "label", "Capability Name", "id", external_prefix),
        (":text:", "num_mappings", "Number of Mappings"),
    ]
    capability_group_dir = domain_dir / "capability-groups"
    previous_link = external_prefix
    for capability_group in project.capability_groups:
        if capability_group.num_mappings > 0:
            nav = breadcrumbs + [
                (
                    f"{external_prefix}capability-groups/{capability_group.id}/",
                    f"{capability_group.label} Capability Group",
                )
            ]
            build_capability_group(
                project=project,
                capability_group=capability_group,
                url_prefix=url_prefix,
                parent_dir=capability_group_dir,
                project_version=project_version,
                attack_version=attack_version,
                standard_headers=standard_headers,
                info_box_headers=info_box_headers,
                attack_domain=attack_domain,
                breadcrumbs=nav,
                capability_group_headers=capability_group_headers,
                previous_link=previous_link,
            )
    for capability in project.capabilities:
        if capability.capability_group:
            capability_nav = breadcrumbs + [
                (
                    f"{external_prefix}{capability.id}/",
                    f"{capability.label if capability.label else capability.id}",
                ),
            ]
            build_external_capability(
                project=project,
                url_prefix=url_prefix,
                parent_dir=domain_dir,
                project_version=project_version,
                attack_version=attack_version,
                standard_headers=standard_headers,
                info_box_headers=info_box_headers,
                capability=capability,
                attack_domain=attack_domain,
                breadcrumbs=capability_nav,
                previous_link=previous_link,
            )
    if project.has_non_mappable_comments:
        for non_mappable in project.non_mappables:
            capability_nav = breadcrumbs + [
                (
                    f"{external_prefix}{non_mappable.id}/",
                    f"{non_mappable.label if non_mappable.label else non_mappable.id}",
                ),
            ]
            build_external_capability(
                project=project,
                url_prefix=url_prefix,
                parent_dir=domain_dir,
                project_version=project_version,
                attack_version=attack_version,
                standard_headers=standard_headers,
                info_box_headers=info_box_headers,
                capability=non_mappable,
                attack_domain=attack_domain,
                breadcrumbs=capability_nav,
                previous_link=previous_link,
            )


def build_external_pages(projects: list, url_prefix: str, breadcrumbs: list):
    """Parse ATT&CK data and build all pages for ATT&CK objects

    Args:
        projects: the list of projects and their mappings to parse into ATT&CK objects
        url_prefix: the root url for the built site
        breadcrumbs: the navigation tree above the pages being built in this function
        used to render the breadcrumbs on each page
    """
    logger.info("Parsing and building external pages...")
    for project in projects:
        external_dir = PUBLIC_DIR / "external"
        external_dir.mkdir(parents=True, exist_ok=True)
        dir = external_dir / project.id
        dir.mkdir(parents=True, exist_ok=True)
        logger.info("Parsing project " + project.id)
        for index, validCombo in enumerate(project.validVersions):
            logger.debug(f"Creating pages for version combo: {validCombo}")
            attack_version = validCombo[1]
            project_version = validCombo[0]
            attack_domain = validCombo[2]
            a = f"attack-{attack_version}"
            d = f"domain-{attack_domain.lower()}"
            p = f"{project.id}-{project_version}"
            domain_dir = dir / a / d / p
            domain_dir.mkdir(parents=True, exist_ok=True)
            parse_capability_groups(
                project=project,
                attack_version=attack_version,
                project_version=project_version,
                attack_domain=attack_domain,
            )
            m = [
                m
                for m in project.mappings
                if m["attack_version"] == attack_version
                and m["project_version"] == project_version
                and m["attack_domain"] == attack_domain
            ][0]
            mappings = m["mappings"]
            logger.trace("project parsed successfully")
            nav = breadcrumbs + [
                (f"{url_prefix}external/{project.id}/", f"{project.label} Home")
            ]

            build_external_landing(
                project=project,
                url_prefix=url_prefix,
                attack_version=attack_version,
                project_version=project_version,
                domain_dir=domain_dir,
                mappings=mappings,
                attack_domain=attack_domain,
                breadcrumbs=nav,
            )
            logger.debug(f"Built all pages for version combo: {validCombo}")
            # for the most up to date combo, copy the pages higher up the directory
            if index == len(project.validVersions) - 1:
                logger.debug(
                    "Copying the most recent version pair into main directory ",
                    str(validCombo),
                )
                shutil.copytree(domain_dir, dir, dirs_exist_ok=True)


def build_capability_group(
    project: ExternalControl,
    capability_group,
    url_prefix,
    parent_dir,
    project_version,
    attack_version,
    standard_headers,
    info_box_headers,
    attack_domain,
    breadcrumbs,
    capability_group_headers,
    previous_link,
):
    capability_group_id = capability_group.id
    dir = parent_dir / capability_group_id
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    template = load_template("capability_group.html.j2")
    prev_page = parent_dir
    stream = template.stream(
        title=f"{project.label} {capability_group.label}",
        url_prefix=url_prefix,
        control=project.label,
        capability_group_id=capability_group.id,
        capability_group_name=capability_group.label,
        capability_group=capability_group,
        project=project,
        description=project.description,
        control_version=project_version,
        versions=project.versions,
        attack_version=attack_version,
        attackVersions=project.attackVersions,
        attack_domain=attack_domain,
        domains=project.attackDomains,
        prev_page=prev_page,
        mappings=capability_group.mappings,
        standard_headers=standard_headers,
        info_box_headers=info_box_headers,
        breadcrumbs=breadcrumbs,
        capability_group_headers=capability_group_headers,
        previous_link=previous_link,
        table_max_count=999_999,
        full_link="",
        full_size=0,
    )
    stream.dump(str(output_path))
    logger.trace(
        "          Created capability group page {group}", group=capability_group.label
    )


def build_external_capability(
    project: ExternalControl,
    url_prefix: str,
    parent_dir: os.path,
    project_version: str,
    attack_version: str,
    standard_headers: list,
    info_box_headers: list,
    capability: Capability,
    attack_domain: str,
    breadcrumbs: list,
    previous_link: str,
):
    """Builds a capability page for a given capability

    Args:
       project: object that contains the capability (used for metadata and linking)
       url_prefix: the root url for the built site
       parent_dir: folder 1 level above where the technique page will be built
       project_version: project version for the page
       attack_version: version of ATT&CK for the page
       headers: headers for mapping table
       capability: capability object that the page is being built for
       attack_domain: ATT&CK domain for the page
       breadcrumbs: the navigation tree above the page being built in this function
        previous_link: link to go to in order to "change versions" on banner or badges
    """
    dir = parent_dir / capability.id.replace(" ", "_")
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    template = load_template("capability.html.j2")
    prev_page = parent_dir
    stream = template.stream(
        title=f"{project.label} {capability.id}",
        url_prefix=url_prefix,
        control=project.label,
        project=project,
        project_id=project.id,
        description=capability.description,
        control_version=project_version,
        versions=project.versions,
        attack_version=attack_version,
        attackVersions=project.attackVersions,
        attack_domain=attack_domain,
        domains=project.attackDomains,
        prev_page=prev_page,
        mappings=capability.mappings,
        standard_headers=standard_headers,
        info_box_headers=info_box_headers,
        capability=capability,
        breadcrumbs=breadcrumbs,
        previous_link=previous_link,
        table_max_count=999_999,
        full_link="",
        full_size=0,
    )
    stream.dump(str(output_path))
    logger.trace("          Created capability page {id}", id=capability.id)


def parse_techniques(
    attack_version: str, attack_domain: str, attack_data: dict, projects: list
):
    """Create a list of technique objects for all ATT&CK techniques that have mappings
      in a given version of ATT&CK

    Args:
        attack_version: version of ATT&CK to find technique objects for
        attack_domain: domain of ATT&CK associated with list of mappings (ex. Enterprise
        , mobile, or ics)
        attack_data: ATT&CK data containing technique metadata to add to technique objs
        projects: list of projects that contain mappings to sort through

    Returns:
        List of technique objects
    """
    techniques = []
    for project in projects:
        mappings = []
        logger.trace("adding mappings in project {id}", id=project.id)
        m = [
            m
            for m in project.mappings
            if float(m["attack_version"]) == float(attack_version)
            and m["attack_domain"] == attack_domain
        ]
        if len(m) > 0:
            m = m[len(m) - 1]
            mappings = m["mappings"]
            allIds = [m["attack_object_id"] for m in mappings]
            attack_ids = list(set(allIds))
            for id in attack_ids:
                if id in [t.id for t in techniques]:
                    technique = [t for t in techniques if t.id == id][0]
                    additional_mappings = [
                        m for m in mappings if (m["attack_object_id"] == id)
                    ]
                    technique.mappings = technique.mappings + additional_mappings
                    technique.num_mappings = len(technique.mappings)

                else:
                    t = Technique()
                    t.id = id
                    dict_item = [t for t in attack_data if t.get("id") == id]
                    if len(dict_item) > 0:
                        t.label = dict_item[0].get("name")
                        t.description = dict_item[0].get("description")
                    t.subtechniques = []
                    t.mappings = [m for m in mappings if (m["attack_object_id"] == id)]
                    t.num_mappings = len(t.mappings)
                    techniques.append(t)
    return techniques


def parse_unmapped_techniques(attack_data: dict, techniques: list):
    """Create a list of non-mappable objects for all ATT&CK techniques in each version
        Adds all technique objects that do not have mappings associated with them
    Args:
        attack_data: ATT&CK data containing technique metadata
        techniques: list of technique objects that are mappable

    Returns:
        List of technique objects
    """
    unmapped = []
    for technique in attack_data:
        if technique["id"] not in [t.id for t in techniques]:
            if technique.get("id")[:2] != "TA":
                t = Technique()
                t.id = technique["id"]
                t.label = technique["name"]
                t.description = technique["description"]
                unmapped.append(t)
    return unmapped


def parse_tactics(
    attack_version: str,
    attack_domain: str,
    attack_data: dict,
    projects: list,
    techniques: list,
):
    """Create a list of tactic objects for all ATT&CK tactics in one version of ATT&CK

    Args:
        attack_version: version of ATT&CK to find tactic objects for
        attack_domain: domain of ATT&CK to find tactic objects for (ex. Enterprise,
        mobile, or ics)
        attack_data: ATT&CK data containing tactic metadata to add to tactic objects
        projects: list of projects that contain mappings to sort through
        techniques: list of technique objects to be assigned to a given tactic

    Returns:
        List of tactic objects
    """

    tactic_dict = load_tactic_structure(
        attack_version=attack_version,
        attack_domain=attack_domain,
    )
    tactic_list = []
    tactics = [t for t in attack_data if t.get("id")[:2] == "TA"]
    for tactic in tactics:
        ta = Tactic()
        ta.id = tactic.get("id")
        ta.description = tactic.get("description")
        ta.label = tactic.get("name")
        ta.techniques = []
        tactic_list.append(ta)
    for item in tactic_dict:
        # if the item has tactic listed, add it to that tactic's list of techniques
        if tactic_dict[item].get("tactics"):
            ta = [
                ta
                for ta in tactic_list
                if ta.label.lower().replace(" ", "-")
                in tactic_dict[item].get("tactics")
            ]
            for tactic in ta:
                technique = [t for t in techniques if t.id == item]
                if technique:
                    tactic.techniques.append(technique[0])
                    tactic.num_techniques = len(tactic.techniques)
        # if item is subtechnique, find the supertechnique add to subtechnique list
        if tactic_dict[item].get("type") == "subtechnique":
            technique_id = tactic_dict[item].get("technique")
            supertechnique = [t for t in techniques if t.id == technique_id]
            technique = [t for t in techniques if t.id == item]
            if supertechnique and technique:
                supertechnique[0].subtechniques.append(technique[0])
                supertechnique[0].num_subtechniques += 1

    return tactic_list


def build_attack_pages(projects: list, url_prefix: str, breadcrumbs: list):
    """Parse ATT&CK data and build all pages for ATT&CK objects

    Args:
        projects: the list of projects and their mappings to parse into ATT&CK objects
        url_prefix: the root url for the built site
        breadcrumbs: the navigation tree above the pages being built in this function
        used to render the breadcrumbs on each page
    """
    # loop through all domain/version combinations
    for attack_domain in list(attack_domains.keys()):
        all_techniques = []
        all_tactics = []
        unmapped = []
        for attack_version in attack_domains[attack_domain]:
            logger.info(
                f"Creating pages for ATT&CK {attack_version} {attack_domain}..."
            )
            attack_data = get_attack_data(attack_version, attack_domain)
            all_techniques = parse_techniques(
                attack_version=attack_version,
                attack_domain=attack_domain,
                attack_data=attack_data,
                projects=projects,
            )
            all_tactics = parse_tactics(
                attack_version=attack_version,
                attack_domain=attack_domain,
                attack_data=attack_data,
                projects=projects,
                techniques=all_techniques,
            )
            # non_mappable attack technique tables not currently shown
            # in the website. Waiting for better solution to be worked out
            unmapped = parse_unmapped_techniques(
                attack_data=attack_data,
                techniques=all_techniques,
            )
            external_dir = (
                PUBLIC_DIR
                / "attack"
                / ("attack-" + attack_version)
                / ("domain-" + attack_domain.lower())
            )
            external_dir.mkdir(parents=True, exist_ok=True)
            build_technique_landing_page(
                url_prefix=url_prefix,
                parent_dir=external_dir,
                attack_version=attack_version,
                attack_domain=attack_domain,
                techniques=all_techniques,
                tactics=all_tactics,
                breadcrumbs=breadcrumbs,
                non_mappables=unmapped,
            )
            # Build technique pages that don't have mappings to fix any linking errors
            for technique in unmapped:
                external_dir = (
                    PUBLIC_DIR
                    / "attack"
                    / ("attack-" + attack_version)
                    / ("domain-" + attack_domain.lower())
                    / "techniques"
                )

                if technique.id:
                    build_technique_page(
                        url_prefix=url_prefix,
                        parent_dir=external_dir,
                        attack_version=attack_version,
                        attack_domain=attack_domain,
                        technique=technique,
                        breadcrumbs=breadcrumbs,
                        projects=projects,
                    )

            for technique in all_techniques:
                external_dir = (
                    PUBLIC_DIR
                    / "attack"
                    / ("attack-" + attack_version)
                    / ("domain-" + attack_domain.lower())
                    / "techniques"
                )
                if technique.id:
                    build_technique_page(
                        url_prefix=url_prefix,
                        parent_dir=external_dir,
                        attack_version=attack_version,
                        attack_domain=attack_domain,
                        technique=technique,
                        breadcrumbs=breadcrumbs,
                        projects=projects,
                    )
            logger.trace("built all technique pages")
            for tactic in all_tactics:
                external_dir = (
                    PUBLIC_DIR
                    / "attack"
                    / ("attack-" + attack_version)
                    / ("domain-" + attack_domain.lower())
                    / "tactics"
                )
                if tactic.id:
                    build_tactic_page(
                        url_prefix=url_prefix,
                        parent_dir=external_dir,
                        attack_version=attack_version,
                        attack_domain=attack_domain,
                        tactic=tactic,
                        breadcrumbs=breadcrumbs,
                    )
            logger.trace("built all tactic pages")
            logger.info(f"Built pages for ATT&CK {attack_version} {attack_domain}")

    logger.info("Done building all ATT&CK pages ")


def build_technique_page(
    url_prefix: str,
    parent_dir: os.path,
    attack_version: str,
    attack_domain: str,
    technique: Technique,
    breadcrumbs: list,
    projects: list,
):
    """Builds a technique page for a given technique

    Args:
        url_prefix: the root url for the built site
        parent_dir: folder 1 level above where the technique page will be built
        attack_version: version of ATT&CK for the page
        attack_domain: ATT&CK domain for the page
        technique: technique object that the page is being built for
        breadcrumbs: the navigation tree above the page being built in this function

    """
    attack_prefix = (
        f"{url_prefix}attack/attack-{attack_version}/"
        f"domain-{attack_domain.lower()}/techniques/"
    )
    technique_headers = [
        (":pfx_link:", "id", "Technique ID", "id", attack_prefix),
        (":pfx_link:", "label", "Technique Name", "id", attack_prefix),
        (":text:", "num_mappings", "Number of Mappings"),
    ]
    nav = breadcrumbs + [
        (f"{attack_prefix}", "ATT&CK Techniques"),
        (
            f"{attack_prefix}{technique.id}/",
            f"{technique.id} {technique.label}",
        ),
    ]
    standard_headers = [
        (":link:", "capability_id", "Capability ID", "capability_id"),
        (
            ":link:",
            "capability_description",
            "Capability Description",
            "capability_id",
        ),
        (":text:", "mapping_type", "Mapping Type"),
        (
            ":pfx_link:",
            "attack_object_id",
            "ATT&CK ID",
            "attack_object_id",
            attack_prefix,
        ),
        (
            ":pfx_link:",
            "attack_object_name",
            "ATT&CK Name",
            "attack_object_id",
            attack_prefix,
        ),
    ]
    info_box_headers = [
        ("comments", "Comments"),
        ("references", "References"),
    ]
    dir = parent_dir / technique.id
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    prev_page = parent_dir
    template = load_template("technique.html.j2")
    split_mappings = []
    for project in projects:
        cutup = [m for m in technique.mappings if m.get("framework") == project.id]
        split_mappings.append(
            {"id": project.id, "label": project.label, "mappings": cutup}
        )
    stream = template.stream(
        title=f"ATT&CK Technique {technique.id}",
        url_prefix=url_prefix,
        attack_version=attack_version,
        attack_domain=attack_domain,
        standard_headers=standard_headers,
        info_box_headers=info_box_headers,
        technique_headers=technique_headers,
        technique=technique,
        prev_page=prev_page,
        mappings=technique.mappings,
        split_mappings=split_mappings,
        subtechniques=technique.subtechniques,
        breadcrumbs=nav,
        previous_link=attack_prefix,
        table_max_count=999_999,
        full_link="",
        full_size=0,
    )
    stream.dump(str(output_path))
    logger.trace("          Created technique page {id}", id=technique.id)


def build_tactic_page(
    url_prefix: str,
    parent_dir: os.path,
    attack_version: str,
    attack_domain: str,
    tactic: Tactic,
    breadcrumbs: list,
):
    """Builds a tactic page for a given tactic

    Args:
        url_prefix: the root url for the built site
        parent_dir: folder 1 level above where the tactic page will be built
        attack_version: version of ATT&CK for the page
        attack_domain: ATT&CK domain for the page
        tactic: tactic object that the page is being built for
        breadcrumbs: the navigation tree above the page being built in this function

    """
    attack_prefix = (
        f"{url_prefix}attack/attack-{attack_version}/domain-{attack_domain.lower()}/"
    )
    previous_link = attack_prefix + "tactics/"
    nav = breadcrumbs + [
        (f"{attack_prefix}tactics/", "ATT&CK Tactics"),
        (f"{attack_prefix}tactics/{tactic.id}/", f"{tactic.id} {tactic.label}"),
    ]
    attack_prefix += "techniques/"

    standard_headers = [
        (":pfx_link:", "id", "Technique ID", "id", attack_prefix),
        (":pfx_link:", "label", "Technique Name", "id", attack_prefix),
        (":text:", "num_mappings", "Number of Mappings"),
        (":text:", "num_subtechniques", "Number of Subtechniques"),
    ]

    dir = parent_dir / tactic.id
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    prev_page = parent_dir
    template = load_template("tactic.html.j2")
    stream = template.stream(
        title=f"ATT&CK Tactic {tactic.id}",
        url_prefix=url_prefix,
        attack_version=attack_version,
        attack_domain=attack_domain,
        standard_headers=standard_headers,
        mappings=tactic.techniques,
        tactic=tactic,
        prev_page=prev_page,
        breadcrumbs=nav,
        previous_link=previous_link,
        table_max_count=999_999,
        full_link="",
        full_size=0,
    )
    stream.dump(str(output_path))
    logger.trace("          Created tactic page {id}", id=tactic.id)


def build_technique_landing_page(
    url_prefix,
    parent_dir,
    attack_version,
    attack_domain,
    techniques,
    tactics,
    breadcrumbs,
    non_mappables,
):
    """Builds default pages that list all tactics and techiniques
    Args:
        url_prefix: root url for website
        parent_dir: directory to build pages inside of
        attack_version: version of ATT&CK to build page for
        attack_domain: ATT&CK domain to build page for
        techniques: list of all techniques to be listed in technique page
        tactics: list of all tactics to be listed in tactic page
        breadcrumbs: the navigation tree above the page being built in this function
        non_mappables: list of techniques that are non_mappable
    """
    attack_prefix = (
        f"{url_prefix}attack/attack-{attack_version}/"
        f"domain-{attack_domain.lower()}/techniques/"
    )
    standard_headers = [
        (":pfx_link:", "id", "ATT&CK ID", "id", attack_prefix),
        (":pfx_link:", "label", "ATT&CK Name", "id", attack_prefix),
        (":text:", "num_mappings", "Number of Mappings"),
        (":text:", "num_subtechniques", "Number of Subtechniques"),
    ]
    non_mappable_headers = [
        (":text:", "id", "ATT&CK ID"),
        (":text:", "label", "ATT&CK Name"),
        # ("description", "Description"),
    ]
    description = """Techniques represent 'how' an adversary achieves a tactical goal by
      performing an action. For example, an adversary may dump credentials to achieve
      credential access.
    """
    valid_versions = []
    for d in attack_domains.keys():
        for version in attack_domains[d]:
            valid_versions.append((d, version))
    technique_nav = breadcrumbs + [
        (f"{attack_prefix}techniques/", "ATT&CK Techniques"),
    ]
    dir = parent_dir / "techniques"
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    prev_page = parent_dir
    template = load_template("attack_landing.html.j2")
    stream = template.stream(
        title="ATT&CK Techniques",
        description=description,
        url_prefix=url_prefix,
        attack_version=attack_version,
        attack_domain=attack_domain,
        standard_headers=standard_headers,
        prev_page=prev_page,
        mappings=techniques,
        object_type="Techniques",
        attackVersions=all_attack_versions,
        domains=attack_domains,
        valid_versions=valid_versions,
        breadcrumbs=technique_nav,
        non_mappable_headers=non_mappable_headers,
        non_mappables=non_mappables,
        table_max_count=999_999,
        full_link="",
        full_size=0,
    )
    stream.dump(str(output_path))
    description = """Tactics represent the "why" of a MITRE ATT&CK® technique or
      sub-technique.  It is the adversary's tactical goal: the reason for performing an
      action. For example, an adversary may want to achieve credential access.
    """
    attack_prefix = (
        f"{url_prefix}attack/attack-{attack_version}/"
        f"domain-{attack_domain.lower()}/tactics/"
    )
    standard_headers = [
        (":pfx_link:", "id", "ATT&CK ID", "id", attack_prefix),
        (":pfx_link:", "label", "ATT&CK Name", "id", attack_prefix),
        (":text:", "num_techniques", "Number of Techniques"),
    ]
    dir = parent_dir / "tactics"
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    prev_page = parent_dir
    template = load_template("attack_landing.html.j2")
    tactic_nav = breadcrumbs + [
        (f"{attack_prefix}tactics/", "ATT&CK Tactics"),
    ]

    stream = template.stream(
        title="ATT&CK Tactics",
        description=description,
        url_prefix=url_prefix,
        attack_version=attack_version,
        attack_domain=attack_domain,
        standard_headers=standard_headers,
        prev_page=prev_page,
        mappings=tactics,
        object_type="Tactics",
        attackVersions=all_attack_versions,
        domains=attack_domains,
        valid_versions=valid_versions,
        breadcrumbs=tactic_nav,
        table_max_count=999_999,
        full_link="",
        full_size=0,
    )
    stream.dump(str(output_path))
    logger.trace("Built techniques and tactics landing pages ")


def build_matrix(url_prefix, projects, breadcrumbs):
    external_dir = PUBLIC_DIR / "attack" / "matrix"
    external_dir.mkdir(parents=True, exist_ok=True)
    output_path = external_dir / "index.html"
    logger.info("Building ATT&CK Matrix ")
    nav = breadcrumbs + [
        (f"{url_prefix}attack/matrix/", "ATT&CK Matrix"),
    ]

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
        "13.0",
        "13.1",
        "14.0",
        "14.1",
        "15.0",
        "15.1",
        "16.1",
    ]

    attack_domain_versions_with_mappings = {}
    for project in projects:
        for valid_version in project.validVersions:
            if valid_version[2] not in attack_domain_versions_with_mappings:
                attack_domain_versions_with_mappings[valid_version[2]] = [
                    valid_version[1]
                ]
            elif (
                valid_version[1]
                not in attack_domain_versions_with_mappings[valid_version[2]]
            ):
                attack_domain_versions_with_mappings[valid_version[2]].append(
                    valid_version[1]
                )

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
            "13.0",
            "13.1",
            "14.0",
            "14.1",
            "15.0",
            "15.1",
            "16.0",
            "16.1",
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
            "13.0",
            "13.1",
            "14.0",
            "14.1",
            "15.0",
            "15.1",
            "16.0",
            "16.1",
        ],
        "Mobile": [
            "8.2",
            "9.0",
            "10.0",
            "10.1",
            "11.3",
            "12.0",
            "12.1",
            "13.0",
            "13.1",
            "14.0",
            "14.1",
            "15.0",
            "15.1",
            "16.0",
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

    json_matrices_dir = TEMPLATE_DIR / PUBLIC_DIR / "static" / "matrices"
    mappings_filepath = PUBLIC_DIR / "data"
    create_attack_jsons(attack_domains, json_matrices_dir, mappings_filepath)

    template = load_template("matrix.html.j2")
    stream = template.stream(
        title="ATT&CK Matrix",
        matrix_order=matrix_order,
        all_attack_versions=all_attack_versions,
        url_prefix=url_prefix,
        attack_domains=attack_domains,
        attack_domain_versions_with_mappings=attack_domain_versions_with_mappings,
        breadcrumbs=nav,
    )
    stream.dump(str(output_path))
    logger.info("Done building ATT&CK matrix")


def getIndexPages():
    """
    Create an array of page dictionaries for search index

    Returns:
    an array of dictionaries with the search index's url, id, and name
    """
    mappings_filepath = PUBLIC_DIR / "data"
    pages = []
    for mappings_file in mappings_filepath.rglob("**/*.json"):
        project_name_in_filepath = (
            "/nist_800_53/" in str(mappings_file)
            or "/veris/" in str(mappings_file)
            or "/aws/" in str(mappings_file)
            or "/azure/" in str(mappings_file)
            or "/gcp/" in str(mappings_file)
            or "/kev/" in str(mappings_file)
            or "/m365/" in str(mappings_file)
            or "/intel-vpro/" in str(mappings_file)
        )
        if (
            project_name_in_filepath
            and "stix" not in mappings_file.name
            and "navigator_layer" not in mappings_file.name
        ):
            mappings = json.loads(mappings_file.read_text(encoding="UTF-8"))

            for mapping in mappings["mapping_objects"]:
                mapping_framework = (
                    mappings["metadata"]["mapping_framework"]
                    if mappings["metadata"]["mapping_framework"] != "nist_800_53"
                    else "nist"
                )
                attack_version = mappings["metadata"]["attack_version"]
                domain = mappings["metadata"]["technology_domain"]
                mapping_framework_version = mappings["metadata"][
                    "mapping_framework_version"
                ].replace("/", ".")
                attack_object_id = mapping["attack_object_id"]
                if attack_object_id:
                    attack_url = (
                        f"attack/attack-{attack_version}/domain-{domain}/techniques/"
                        f"{attack_object_id}"
                    )
                    if not any(page["url"] == attack_url for page in pages):
                        pages.append(
                            {
                                "url": attack_url,
                                "id": attack_object_id,
                                "name": mapping["attack_object_name"],
                            }
                        )
                capability_id = mapping["capability_id"]
                if capability_id:
                    capability_url = (
                        f"external/{mapping_framework}/attack-{attack_version}"
                        f"/domain-{domain}/{mapping_framework}-{mapping_framework_version}"
                        f"/{capability_id.replace(' ', '%20')}"
                    )
                    if not any(page["url"] == capability_url for page in pages):
                        pages.append(
                            {
                                "url": capability_url,
                                "id": capability_id,
                                "name": mapping["capability_description"],
                            }
                        )
    return pages


def build_search_index(url_prefix: str, breadcrumbs=list):
    """
    Render the search page and also build the search index as a JSON file.

    Args:
        url_prefix - the site's URL prefix
        breadcrumbs: the navigation tree above the page being built in this function
    """
    logger.info("Creating search page")
    search_dir = PUBLIC_DIR / "search"
    search_dir.mkdir(parents=True, exist_ok=True)
    output_path = search_dir / "index.html"
    template = load_template("search.html.j2")

    nav = breadcrumbs + [(f"{url_prefix}search/", "Search")]
    logger.info("Creating search index")
    pages = getIndexPages()
    stream = template.stream(url_prefix=url_prefix, breadcrumbs=nav)
    stream.dump(str(output_path))

    index = lunr(
        ref="url",
        fields=[
            {"field_name": "id", "boost": 3},
            {"field_name": "name", "boost": 2},
        ],
        documents=pages,
    )
    pages = {p.pop("url"): p for p in pages}
    index_path = PUBLIC_DIR / "static" / "lunr-index.zip"
    lunr_index = {
        "pages": pages,
        "index": index.serialize(),
    }
    # Use the `zipfile` module
    with zipfile.ZipFile(
        index_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as zip_file:
        # Dump JSON data
        dumped_JSON: str = json.dumps(lunr_index, ensure_ascii=False, indent=4)
        # Write the JSON data into `lunr-index.json` *inside* the ZIP file
        zip_file.writestr("lunr-index.json", data=dumped_JSON)
        # Test integrity of compressed archive
        zip_file.testzip()


def build_about_page(
    url_prefix: str,
    url_suffix: str,
    breadcrumbs: list,
    template_path: str,
    title: str,
) -> list:
    """
    Build one about page.

    Args:
        url_prefix: The prefix to put in front of any internal URLs.
        url_suffix: The unique part of the URL, the part after the prefix.
        breadcrumbs: The navigation tree above the pages being built in this function.
        template_path: The jinja template to render for this page.
        title: The page title.
        output_dir: The path to write the rendered HTML to.

    Returns:
        A list of breadcrumbs to this page, which you may need for subpages
    """
    breadcrumbs = breadcrumbs + [(f"{url_prefix}{url_suffix}/", title)]
    output_dir = PUBLIC_DIR
    for url_part in url_suffix.split("/"):
        output_dir = output_dir / url_part
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "index.html"
    template = load_template(template_path)
    stream = template.stream(
        title=title,
        url_prefix=url_prefix,
        breadcrumbs=breadcrumbs,
    )
    stream.dump(str(output_path))
    logger.debug("Created {} page -> {}", url_suffix, output_path)
    return breadcrumbs


def build_about_pages(url_prefix: str, breadcrumbs: list):
    """
    Build the site's "about" pages, e.g. explaining what the site is for, who it's for,
    etc.

    Args:
        url_prefix: The prefix to put in front of any internal URLs.
        breadcrumbs: the navigation tree above the pages being built in this function
    """
    about_breadcrumbs = build_about_page(
        url_prefix=url_prefix,
        url_suffix="about",
        breadcrumbs=breadcrumbs,
        template_path="about.html.j2",
        title="About",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/use-cases",
        breadcrumbs=about_breadcrumbs,
        template_path="use_cases.html.j2",
        title="Use Cases",
    )

    methodology_breadcrumbs = build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/methodology",
        breadcrumbs=about_breadcrumbs,
        template_path="methodology.html.j2",
        title="Methodology",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/methodology/cve-methodology",
        breadcrumbs=methodology_breadcrumbs,
        template_path="methodology/cve_methodology.html.j2",
        title="CVE Mapping Methodology",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/methodology/nist-methodology",
        breadcrumbs=methodology_breadcrumbs,
        template_path="methodology/nist_methodology.html.j2",
        title="NIST 800-53 Mapping Methodology",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/methodology/nist-scope",
        breadcrumbs=methodology_breadcrumbs,
        template_path="methodology/nist_scope.html.j2",
        title="NIST 800-53 Mapping Scope",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/methodology/ssm-methodology",
        breadcrumbs=methodology_breadcrumbs,
        template_path="methodology/ssm_methodology.html.j2",
        title="Security Stack Mapping Methodology",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/methodology/veris-methodology",
        breadcrumbs=methodology_breadcrumbs,
        template_path="methodology/veris_methodology.html.j2",
        title="VERIS Mapping Methodology",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/scoring",
        breadcrumbs=about_breadcrumbs,
        template_path="scoring_rubric.html.j2",
        title="Scoring",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/related-projects",
        breadcrumbs=about_breadcrumbs,
        template_path="related_projects.html.j2",
        title="Related Projects",
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--url-prefix",
        default="http://[::]:8000/",
        help="A prefix to apply to generated (default: /public)",
    )
    parser.add_argument(
        "--reset-descriptions",
        action="store_true",
        default=False,
        help="Adds ability to refresh and load capability descriptions from API calls",
    )
    args = parser.parse_args()

    url_prefix = args.url_prefix
    reset_descriptions = args.reset_descriptions
    logger.info(f"url prefix: {url_prefix}")
    logger.info(f"Reset descriptions? {reset_descriptions}")
    projects = load_projects()

    static_dir = PUBLIC_DIR / "static"
    logger.info("Copying static resources:", static_dir)
    shutil.copytree(TEMPLATE_DIR / "static", static_dir, dirs_exist_ok=True)

    data_dir = PUBLIC_DIR / "data"
    logger.info("Copying parsed mappings to output directory:", data_dir)
    shutil.copytree(ROOT_DIR / "mappings", data_dir, dirs_exist_ok=True)

    legacy_dir = PUBLIC_DIR / "legacy"
    logger.info("Copying legacy data to output directory:", data_dir)
    shutil.copytree(ROOT_DIR / "legacy", legacy_dir, dirs_exist_ok=True)

    output_path = PUBLIC_DIR / "index.html"
    template = load_template("landing.html.j2")
    stream = template.stream(
        title="Home",
        url_prefix=url_prefix,
        public_dir=PUBLIC_DIR,
        projects=projects,
    )
    stream.dump(str(output_path))
    logger.info("Created site homepage")

    dir = PUBLIC_DIR / "external"
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    template = load_template("external_landing.html.j2")
    breadcrumbs = [
        (f"{url_prefix}", "Home"),
        (f"{url_prefix}external/", "Mapping Frameworks"),
    ]
    stream = template.stream(
        title="External Mappings Home",
        url_prefix=url_prefix,
        breadcrumbs=breadcrumbs,
        projects=projects,
    )
    stream.dump(str(output_path))
    logger.info("Created Mappings Frameworks landing page")

    if reset_descriptions:
        delete_all_descriptions(projects=projects)

    build_external_pages(
        projects=projects,
        url_prefix=url_prefix,
        breadcrumbs=breadcrumbs,
    )
    breadcrumbs = [
        (f"{url_prefix}", "Home"),
    ]
    build_about_pages(url_prefix=url_prefix, breadcrumbs=breadcrumbs)
    build_attack_pages(
        projects=projects, url_prefix=url_prefix, breadcrumbs=breadcrumbs
    )
    build_matrix(url_prefix=url_prefix, projects=projects, breadcrumbs=breadcrumbs)
    build_search_index(url_prefix, breadcrumbs)
    logger.info("Done building site")


if __name__ == "__main__":
    main()
