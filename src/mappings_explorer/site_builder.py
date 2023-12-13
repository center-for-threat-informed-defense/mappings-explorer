import argparse
import json
import shutil

from jinja2 import Environment, FileSystemLoader

from .attack_query import create_attack_jsons
from .template import PUBLIC_DIR, ROOT_DIR, TEMPLATE_DIR, load_template


class ExternalControl:
    id = ""
    label = ""
    description = []
    version = ""
    versions = []
    attackVersion = ""
    attackVersions = []
    attackDomain = ""
    attackDomains = []
    validVersions = []
    tableHeaders = []
    groups = []
    mappings = []


def load_projects():
    nist = ExternalControl()
    nist.id = "nist"
    nist.label = "NIST 800-53"
    nist.description = [
        """The NIST 800-53 is a cybersecurity standard and compliance framework
        developed by the National Institute of Standards in Technology. It’s a
        continuously updated framework that tries to flexibly define standards, controls
        , and assessments based on risk, cost-effectiveness, and capabilities. Currently
        , the NIST framework is mapped to ATT&CK Versions 8.2, 9.0, and 10.1.""",
        """The NIST 800-53 framework is designed to provide a foundation of guiding
         elements, strategies, systems, and controls, that can agnostically support any
         organization’s cybersecurity needs and priorities. By establishing a framework
         available to all, it fosters communication and allows organizations to speak
         using a shared language. Lastly, because it doesn’t specifically support or
         suggest specific tools, companies, or vendors (intentionally so), it’s designed
         to be used as new technologies, systems, environments, and organizational
         changes arise, shifting cybersecurity needs.""",
    ]
    nist.versions = ["rev5", "rev4"]
    nist.attackVersions = [
        "12.1",
        "10.1",
        "9.0",
        "8.2",
    ]
    nist.validVersions = [
        ("rev4", "8.2"),
        ("rev5", "8.2"),
        ("rev4", "9.0"),
        ("rev5", "9.0"),
        ("rev4", "10.1"),
        ("rev5", "10.1"),
        ("rev4", "12.1"),
        ("rev5", "12.1"),
    ]
    nist.attackDomains = ["enterprise"]
    nist.attackDomain = nist.attackDomains[0]
    nist.tableHeaders = ["ID", "Control Family", "Number of Controls", "Description"]
    veris = ExternalControl()
    veris.id = "veris"
    veris.label = "VERIS"
    veris.description = [
        """The Vocabulary for Event Recording and Incident Sharing (VERIS) is a set of
         metrics designed to provide a common language for describing security incidents
         in a structured and repeatable manner. The overall goal is to lay a foundation
         from which we can constructively and cooperatively learn from our experiences
         to better measure and manage risk. """
    ]
    veris.versions = ["1.3.7", "1.3.5"]
    veris.attackDomains = ["enterprise"]
    veris.attackDomain = veris.attackDomains[0]
    veris.attackVersions = [
        "12.1",
        "9.0",
    ]
    veris.validVersions = [("1.3.5", "9.0"), ("1.3.7", "12.1")]
    veris.tableHeaders = ["ID", "Control Family", "Number of Controls", "Description"]
    veris.mappings = []

    cve = ExternalControl()
    cve.id = "cve"
    cve.label = "CVE"
    cve.description = [
        """Common Vulnerabilities and Exposures (CVE) is a database of publicly
         available information security issues. CVE provides a convenient, reliable way
         for vendors, enterprises, academics, and all other interested parties to
         exchange information about cyber security issues. Sharing CVE details is
         beneficial to all organizations it allows organizations to set a baseline for
         evaluating the coverage of their security tools. CVE numbers allow
         organizations to see what each tool covers and how appropriate they are
         for your organization."""
    ]
    cve.attackDomains = ["enterprise"]
    cve.attackDomain = cve.attackDomains[0]
    cve.versions = ["10.21.2021"]
    cve.attackVersions = ["9.0"]
    cve.validVersions = [("10.21.2021", "9.0")]
    cve.tableHeaders = ["ID", "Control Family", "Number of Controls", "Description"]
    cve.mappings = []

    aws = ExternalControl()
    aws.id = "aws"
    aws.label = "AWS"
    aws.description = [
        """These mappings of the Amazon Web Services (AWS) security controls to MITRE
         ATT&CK® are designed to empower organizations with independent data on which
         native AWS security controls are most useful in defending against the adversary
         TTPs that they care about. These mappings are part of a collection of mappings
         of native product security controls to ATT&CK based on a common methodology,
         scoring rubric, data model, and tool set. This full set of resources is
         available on the Center’s project page."""
    ]
    aws.attackDomains = ["enterprise"]
    aws.attackDomain = aws.attackDomains[0]
    aws.attackVersions = ["9.0"]
    aws.versions = ["09.21.2021"]
    aws.validVersions = [("09.21.2021", "9.0")]
    aws.tableHeaders = ["ID", "Control Family", "Number of Controls", "Description"]
    aws.mappings = []

    azure = ExternalControl()
    azure.id = "azure"
    azure.label = "Azure"
    azure.description = [
        """These mappings of the Microsoft Azure Infrastructure as a Services (IaaS)
         security controls to MITRE ATT&CK® are designed to empower organizations with
         independent data on which native Azure security controls are most useful in
         defending against the adversary TTPs that they care about. These mappings are
         part of a collection of mappings of native product security controls to ATT&CK
         based on a common methodology, scoring rubric, data model, and tool set. This
         full set of resources is available on the Center’s project page."""
    ]
    azure.attackDomains = ["enterprise"]
    azure.attackDomain = azure.attackDomains[0]
    azure.attackVersions = ["8.2"]
    azure.versions = ["06.29.2021"]
    azure.validVersions = [("06.29.2021", "8.2")]
    azure.tableHeaders = ["ID", "Control Family", "Number of Controls", "Description"]
    azure.mappings = []

    gcp = ExternalControl()
    gcp.id = "gcp"
    gcp.label = "GCP"
    gcp.description = [
        """These mappings of the Google Cloud Platform (GCP) security controls to MITRE
         ATT&CK® are designed to empower organizations with independent data on which
         native GCP security controls are most useful in defending against the adversary
         TTPs that they care about. These mappings are part of a collection of mappings
         of native product security controls to ATT&CK based on a common methodology,
         scoring rubric, data model, and tool set. This full set of resources is
         available on the Center’s project page."""
    ]
    gcp.attackDomains = ["enterprise"]
    gcp.attackDomain = gcp.attackDomains[0]
    gcp.attackVersions = ["10.0"]
    gcp.attackVersion = gcp.attackVersions[0]
    gcp.versions = ["06.28.2022"]
    gcp.validVersions = [("06.28.2022", "10.0")]
    gcp.tableHeaders = ["ID", "Control Family", "Number of Controls", "Description"]
    gcp.mappings = []

    projects = [
        nist,
        cve,
        aws,
        azure,
        gcp,
        veris,
    ]
    return projects


def replace_mapping_type(mapping, type_list):
    for mapping_type in type_list:
        if mapping["mapping_type"] == mapping_type:
            return type_list[mapping_type]["name"]


def parse_groups(project, attack_version, project_version):
    project_id = project.id
    if project_id == "nist":
        project_id = "nist_800_53"
    filepath = PUBLIC_DIR / "data" / project_id
    full_path = (
        filepath
        / ("attack-" + attack_version)
        / (project_id + "-" + project_version.replace("/", "."))
        / project.attackDomain
        / (
            project_id
            + "-"
            + project_version.replace("/", ".")
            + "_attack-"
            + attack_version
            + "-"
            + project.attackDomain
            + ".json"
        )
    )
    f = open(full_path, "r")
    data = json.load(f)
    metadata = data["metadata"]
    project.groups = []
    project.mappings = data["mapping_objects"]
    for mapping in project.mappings:
        mapping["mapping_type"] = replace_mapping_type(
            mapping, metadata["mapping_types"]
        )
    for group in metadata["groups"]:
        project_group = {"id": group, "name": metadata["groups"][group]}
        # parse mappings such that each mapping is sorted by its group
        filtered_mappings = [m for m in project.mappings if (m["group"] == group)]
        project_group["num_mappings"] = len(filtered_mappings)
        project_group["mappings"] = filtered_mappings
        # here's where I'll parse which capabilities are under a certain group
        project_group["controls"] = []
        print(
            "     found "
            + f"{len(filtered_mappings)}"
            + " mappings in group: "
            + project_group["name"]
        )


def build_external_landing(
    project: ExternalControl,
    url_prefix,
    project_version,
    attack_version,
    project_dir,
    mappings,
):
    output_path = project_dir / "index.html"
    template = load_template("external-control.html.j2")

    headers = [
        ("attack_object_id", "ATT&CK ID"),
        ("attack_object_name", "ATT&CK Name"),
        ("mapping_type", "Mapping Type"),
        ("capability_id", "Capability ID"),
        ("capability_description", "Capability Description"),
    ]
    if project.id == "azure" or project.id == "aws" or project.id == "gcp":
        headers = [
            ("attack_object_id", "ATT&CK ID"),
            ("attack_object_name", "ATT&CK Name"),
            ("score_category", "Category"),
            ("score_value", "Value"),
            ("capability_id", "Capability ID"),
            ("capability_description", "Capability Description"),
        ]

    group_headers = [
        ("id", "ID"),
        ("name", "Control Family"),
        # ("num_controls", "Number of Controls"),
        ("num_mappings", "Number of Mappings"),
    ]
    project_id = project.id
    if project_id == "nist":
        project_id = "nist_800_53"
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
        domain=project.attackDomain,
        domains=project.attackDomains,
        tableHeaders=project.tableHeaders,
        mappings=mappings,
        headers=headers,
        group_headers=group_headers,
        groups=project.groups,
        valid_versions=project.validVersions,
    )
    stream.dump(str(output_path))
    print(
        "Created "
        + project.id
        + " landing: ATT&CK Version "
        + attack_version
        + ", control version "
        + project_version
    )
    for group in project.groups:
        build_external_control(
            project=project,
            group=group,
            url_prefix=url_prefix,
            parent_dir=project_dir,
            project_version=project_version,
            attack_version=attack_version,
            mappings=mappings,
            headers=headers,
        )


def build_external_pages(projects, url_prefix):
    for project in projects:
        external_dir = PUBLIC_DIR / "external"
        external_dir.mkdir(parents=True, exist_ok=True)
        dir = external_dir / project.id
        dir.mkdir(parents=True, exist_ok=True)

        for index, validCombo in enumerate(project.validVersions):
            print("creating pages for version combo ", str(validCombo))
            attack_version = validCombo[1]
            project_version = validCombo[0]
            a = "attack-" + attack_version
            attack_dir = dir / a
            attack_dir.mkdir(parents=True, exist_ok=True)
            p = project.id + "-" + project_version
            project_dir = attack_dir / p
            project_dir.mkdir(parents=True, exist_ok=True)
            parse_groups(
                project=project,
                attack_version=attack_version,
                project_version=project_version,
            )
            build_external_landing(
                project=project,
                url_prefix=url_prefix,
                attack_version=attack_version,
                project_version=project_version,
                project_dir=project_dir,
                mappings=project.mappings,
            )
            # for the most up to date combo, copy the pages higher up the directory
            if index == len(project.validVersions) - 1:
                print(
                    "copying the most recent version pair into main directory ",
                    str(validCombo),
                )
                shutil.copytree(project_dir, dir, dirs_exist_ok=True)


def build_external_control(
    project: ExternalControl,
    group,
    url_prefix,
    parent_dir,
    project_version,
    attack_version,
    mappings,
    headers,
):
    group_id = group["id"]
    group_name = group["name"]
    dir = parent_dir / group_id
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    template = load_template("external-group.html.j2")
    prev_page = parent_dir
    stream = template.stream(
        title=project.label + " " + group_name,
        url_prefix=url_prefix,
        control=project.label,
        group_id=group_id,
        group_name=group_name,
        project=project,
        description=project.description,
        tableHeaders=project.tableHeaders,
        control_version=project_version,
        versions=project.versions,
        attack_version=attack_version,
        attackVersions=project.attackVersions,
        domain=project.attackDomain,
        domains=project.attackDomains,
        prev_page=prev_page,
        mappings=group["mappings"],
        headers=headers,
    )
    stream.dump(str(output_path))
    print("          Created group page " + group_name)


def build_matrix(url_prefix):
    external_dir = PUBLIC_DIR / "external" / "matrix"
    external_dir.mkdir(parents=True, exist_ok=True)
    output_path = external_dir / "index.html"

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
            "13.0",
            "13.1",
            "14.0",
            "14.1",
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
        ],
    }

    json_matrices_dir = TEMPLATE_DIR / PUBLIC_DIR / "static" / "matrices"
    mappings_filepath = PUBLIC_DIR / "data"
    create_attack_jsons(attack_domains, json_matrices_dir, mappings_filepath)

    template = load_template("matrix.html.j2")
    stream = template.stream(
        title="ATT&CK Matrix",
        all_attack_versions=all_attack_versions,
        url_prefix=url_prefix,
        attack_domains=attack_domains,
    )
    stream.dump(str(output_path))
    print("Created matrix")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--url-prefix",
        default="http://[::]:8000/",
        help="A prefix to apply to generated (default: /public)",
    )
    args = parser.parse_args()

    url_prefix = args.url_prefix
    print("url prefix: ", url_prefix)
    templateLoader = FileSystemLoader(searchpath="./src/mappings_explorer/templates")
    templateEnv = Environment(loader=templateLoader, autoescape=True)
    projects = load_projects()

    static_dir = PUBLIC_DIR / "static"
    print("Copying static resources: {}", static_dir)
    shutil.copytree(TEMPLATE_DIR / "static", static_dir, dirs_exist_ok=True)

    data_dir = PUBLIC_DIR / "data"
    print("Copying parsed mappings to output directory: {}", data_dir)
    shutil.copytree(ROOT_DIR / "mappings", data_dir, dirs_exist_ok=True)

    output_path = PUBLIC_DIR / "index.html"
    template = load_template("landing.html.j2")
    stream = template.stream(
        title="Mappings Explorer", url_prefix=url_prefix, public_dir=PUBLIC_DIR
    )
    stream.dump(str(output_path))
    print("Created site index")
    dir = PUBLIC_DIR / "external"
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    template = load_template("external-landing.html.j2")
    stream = template.stream(title="External Mappings Home", url_prefix=url_prefix)
    stream.dump(str(output_path))
    print("Created external mappings home")

    TEMPLATE_FILE = "external-control.html.j2"
    template = templateEnv.get_template(TEMPLATE_FILE)

    build_external_pages(projects=projects, url_prefix=url_prefix)
    build_matrix(url_prefix)
    template.stream(title="External Mappings Home").dump(
        "./output/external-landing.html"
    )
    print("Created external mappings home")


if __name__ == "__main__":
    main()
