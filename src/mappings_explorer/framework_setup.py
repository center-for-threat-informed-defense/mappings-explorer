import json
import os

import requests
from loguru import logger
from mapex_convert.read_files import (
    read_yaml_file,
)

from .template import (
    DATA_DIR,
)


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


class Capability:
    id = ""
    label = ""
    description = ""
    mappings = []
    capability_group = ""
    num_mappings = 0
    non_mappable_comment = ""


class CapabilityGroup:
    id = ""
    label = ""
    num_mappings = ""
    mappings = []
    capabilities = []
    num_capabilities = 0


def load_projects():
    nist = ExternalControl()
    nist.id = "nist"
    nist.label = "NIST 800-53"
    nist.description = """National Institute of Standards in Technology (NIST) Special
    Publication 800-53 provides a catalog of security and privacy controls for the
    protection of information systems and organizations from a diverse set of threats
    and risks. These mappings provide resources for assessing security control coverage
    of real-world threats as described in the MITRE ATT&CK® knowledge base and provide
    a foundation for integrating ATT&CK-based threat intelligence into the risk
    management process. Shared understanding of how the implementation of NIST 800-53
    security controls in an environment can mitigate adversary techniques of interest is
    an important step to bring security operations teams and risk management teams
    together to build a structured, threat-informed approach to securing systems and
    environments. """
    nist.versions = ["rev5", "rev4"]
    nist.attackVersions = [
        "16.1",
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
        ("rev5", "16.1", "Enterprise"),
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
        platform provided by Amazon. AWS offers a range of security capabilities to
        protect cloud data, applications, and infrastructure from threats. These
        mappings connect AWS security capabilities to adversary behaviors in MITRE
        ATT&CK®, providing AWS users with a comprehensive view of how native AWS
        security capabilities can be used to prevent, detect, and respond to prevalent
        cloud threats. As a result, AWS users can evaluate the effectiveness of
        native security controls against specific ATT&CK techniques and take a
        threat-informed approach to understand, prioritize, and mitigate adversary
        behaviors that are most important for their environment."""
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
    azure.description = """Microsoft Azure is a widely used cloud computing platform
        provided by Microsoft. Azure offers a range of security capabilities to protect
        cloud data, applications, and infrastructure from threats. These mappings
        connect Azure security capabilities to adversary behaviors in MITRE ATT&CK®,
        providing Azure users with a comprehensive view of how native Azure security
        capabilities can be used to prevent, detect, and respond to prevalent cloud
        threats. As a result, Azure users can evaluate the effectiveness of native
        security controls against specific ATT&CK techniques and take a threat-informed
        approach to understand, prioritize, and mitigate adversary behaviors that are
        most important for their environment."""
    azure.attackDomains = ["Enterprise"]
    azure.attackDomain = azure.attackDomains[0]
    azure.attackVersions = ["16.1", "8.2"]
    azure.versions = ["04.26.2025", "06.29.2021"]
    azure.validVersions = [
        ("06.29.2021", "8.2", "Enterprise"),
        ("04.26.2025", "16.1", "Enterprise"),
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
        platform provided by Google. GCP offers a range of security capabilities to
        protect cloud data, applications, and infrastructure from threats. These
        mappings connect GCP security capabilities to adversary behaviors in MITRE
        ATT&CK®, providing GCP users with a comprehensive view of how native GCP
        security capabilities can be used to prevent, detect, and respond to prevalent
        cloud threats. As a result, GCP users can evaluate the effectiveness of
        native security controls against specific ATT&CK techniques and take a
        threat-informed approach to understand, prioritize, and mitigate adversary
        behaviors that are most important for their environment."""

    gcp.attackDomains = ["Enterprise"]
    gcp.attackDomain = gcp.attackDomains[0]
    gcp.attackVersions = ["16.1", "10.0"]
    gcp.attackVersion = gcp.attackVersions[0]
    gcp.versions = ["06.28.2022", "03.06.2025"]
    gcp.validVersions = [
        ("06.28.2022", "10.0", "Enterprise"),
        ("03.06.2025", "16.1", "Enterprise"),
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
    m365.attackVersions = ["16.1", "14.1"]
    m365.attackVersion = m365.attackVersions[0]
    m365.versions = ["07.18.2025", "12.11.2023"]
    m365.validVersions = [
        ("12.11.2023", "14.1", "Enterprise"),
        ("07.18.2025", "16.1", "Enterprise"),
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

    cri_profile = ExternalControl()
    cri_profile.id = "cri_profile"
    cri_profile.label = "CRI Profile"
    cri_profile.description = """The CRI Profile is a control framework to develop and
    assess cybersecurity and resiliency programs, produced by and for the global
    financial sector and maintained by the Cyber Risk Institute (CRI). These mappings
    connect the security capability coverage of the CRI Profile's Diagnostic Statements
    with threat mitigation of real-world adversarial behaviors as described in MITRE
    ATT&CK. The connection of ATT&CK with the CRI Profile control program framework
    empowers threat-informed analysis and decision-making for cybersecurity control
    program design and implementation by the financial services sector. """

    cri_profile.attackDomains = ["Enterprise"]
    cri_profile.attackDomain = cri_profile.attackDomains[0]
    cri_profile.attackVersions = ["16.1"]
    cri_profile.attackVersion = cri_profile.attackVersions[0]
    cri_profile.versions = ["v2.1"]
    cri_profile.validVersions = [
        ("v2.1", "16.1", "Enterprise"),
    ]
    cri_profile.mappings = []
    cri_profile.resources = [
        {
            "link": "about/methodology/",
            "label": "Mapping Methodology",
        },
        {
            "link": "about/methodology/cri-profile-scope/",
            "label": "Mapping Scope",
        },
        {
            "link": "https://cyberriskinstitute.org/the-profile/",
            "label": "The CRI Profile (External link)",
            "external": True,
        },
    ]
    cri_profile.has_non_mappable_comments = False

    csa_ccm = ExternalControl()
    csa_ccm.id = "csa_ccm"
    csa_ccm.label = "CSA CCM for Cloud Security Alliance Cloud Controls Matrix"
    csa_ccm.description = """TODO: add description here"""
    csa_ccm.attackDomains = ["Enterprise"]
    csa_ccm.attackDomain = csa_ccm.attackDomains[0]
    csa_ccm.attackVersions = ["16.1"]
    csa_ccm.attackVersion = csa_ccm.attackVersions[0]
    csa_ccm.versions = ["v4"]
    csa_ccm.validVersions = [
        ("v4", "16.1", "Enterprise"),
    ]
    csa_ccm.mappings = []

    projects = [
        csa_ccm,
        cri_profile,
        intel_vpro,
        nist,
        kev,
        veris,
        azure,
        gcp,
        aws,
        m365,
    ]
    return projects


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
    elif project.id == "gcp":
        folder_name = DATA_DIR / "SecurityStack" / "GCP"
    elif project.id == "azure":
        folder_name = DATA_DIR / "SecurityStack" / "Azure"
    elif project.id == "cri_profile":
        folder_name = DATA_DIR / "cri_profile"
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
