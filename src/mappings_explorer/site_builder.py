import argparse
import json
import os
import shutil

from jinja2 import Environment, FileSystemLoader

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


def replace_mapping_type(mapping, type_list):
    for type in type_list:
        if mapping["mapping_type"] == type["id"]:
            return type["name"]


def parse_groups(project, attack_version, project_version):
    print("attack: ", attack_version + " and project version " + project_version)
    filepath = PUBLIC_DIR / "data" / project.id
    if len(project.versions) > 1 or len(project.attackVersions) > 1:
        if project_version == "rev4":
            project_version = "r4"
        if project_version == "rev5":
            project_version = "r5"
        files = os.listdir(filepath / attack_version / project_version)
        full_path = filepath / attack_version / project_version / files[0]
        f = open(full_path, "r")
    else:
        files = os.listdir(filepath)
        full_path = filepath / files[0]
        f = open(full_path, "r")
    data = json.load(f)
    metadata = data["metadata"]
    project.groups = []
    if metadata.get("groups"):
        project.groups = metadata["groups"]
    project.mappings = data["mapping_objects"]
    for mapping in project.mappings:
        mapping["mapping_type"] = replace_mapping_type(
            mapping, metadata["mapping_types"]
        )
    for group in project.groups:
        # parse mappings such that each mapping is sorted by its group
        filtered_mappings = [m for m in project.mappings if (m["group"] == group["id"])]
        group["num_mappings"] = len(filtered_mappings)
        group["mappings"] = filtered_mappings
        # here's where I'll parse which capabilities are under a certain group
        group["controls"] = []
        group["num_controls"] = 0
        print(
            "found "
            + f"{len(filtered_mappings)}"
            + " mappings in group: "
            + group["name"]
        )


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
    cve.versions = ["21.10.21"]
    cve.attackVersions = ["9.0"]
    cve.validVersions = [("21.10.21", "9.0")]
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
    aws.versions = ["21.09.21"]
    aws.validVersions = [("21.09.21", "9.0")]
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
    azure.versions = ["21.06.29"]
    azure.validVersions = [("21.06.29", "8.2")]
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
    gcp.attackVersions = ["10.0"]
    gcp.attackVersion = gcp.attackVersions[0]
    gcp.versions = ["22.06.28"]
    gcp.validVersions = [("22.06.28", "10.0")]
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
    for type in type_list:
        if mapping["mapping_type"] == type["id"]:
            return type["name"]


def parse_groups(project, attack_version, project_version):
    print("attack: ", attack_version + " and project version " + project_version)
    project_id = project.id
    if project_id == "nist":
        project_id = "nist_800_53"
    filepath = PUBLIC_DIR / "data" / project_id
    files = os.listdir(
        filepath / ("attack-" + attack_version) / (project_id + "-" + project_version)
    )
    full_path = (
        filepath
        / ("attack-" + attack_version)
        / (project_id + "-" + project_version)
        / files[0]
    )
    f = open(full_path, "r")
    data = json.load(f)
    metadata = data["metadata"]
    project.groups = []
    if metadata.get("groups"):
        project.groups = metadata["groups"]
    project.mappings = data["mapping_objects"]
    for mapping in project.mappings:
        mapping["mapping_type"] = replace_mapping_type(
            mapping, metadata["mapping_types"]
        )
    for group in project.groups:
        # parse mappings such that each mapping is sorted by its group
        filtered_mappings = [m for m in project.mappings if (m["group"] == group["id"])]
        group["num_mappings"] = len(filtered_mappings)
        group["mappings"] = filtered_mappings
        # here's where I'll parse which capabilities are under a certain group
        group["controls"] = []
        group["num_controls"] = 0
        print(
            "found "
            + f"{len(filtered_mappings)}"
            + " mappings in group: "
            + group["name"]
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

    stream = template.stream(
        title=project.label + " Landing",
        url_prefix=url_prefix,
        control=project.label,
        description=project.description,
        project_version=project_version,
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

        for validCombo in project.validVersions:
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

    template.stream(title="External Mappings Home").dump(
        "./output/external-landing.html"
    )
    print("Created external mappings home")


if __name__ == "__main__":
    main()
