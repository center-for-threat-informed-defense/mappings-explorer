import argparse
import json
import os
import shutil

import requests
from jinja2 import Environment, FileSystemLoader
from mapex_convert.read_files import (
    read_yaml_file,
)

from .template import DATA_DIR, PUBLIC_DIR, ROOT_DIR, TEMPLATE_DIR, load_template


class Capability:
    id = ""
    label = ""
    description = ""
    mappings = []


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
    groups = []
    mappings = []
    capabilities = []


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
    gcp.mappings = []

    projects = [
        # nist,
        # cve,
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
    project_id = project.id
    if project_id == "nist":
        project_id = "nist_800_53"
    filepath = PUBLIC_DIR / "data" / project_id
    full_path = (
        filepath
        / ("attack-" + attack_version)
        / (project_id + "-" + project_version)
        / (project_id + "-" + project_version + "_attack-" + attack_version + ".json")
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
            "     found "
            + f"{len(filtered_mappings)}"
            + " mappings in group: "
            + group["name"]
        )
    project.capabilities = parse_capabilities(project)
    #  set the descriptions for each project's capability list
    if project.id == "cve":
        get_cve_descriptions(project=project)
    if project.id == "nist":
        get_nist_descriptions(project=project, version=project_version)
    if project.id == "aws" or project.id == "gcp" or project.id == "azure":
        get_security_stack_descriptions(project=project)


def get_security_stack_descriptions(project):
    root = DATA_DIR / "SecurityStack"
    data_dir = os.listdir(root)
    for dir in data_dir:
        if dir.lower() == project.id:
            rootdir = root / dir

    # iterate through mappings files
    for file in os.listdir(rootdir):
        data = read_yaml_file(rootdir / file)
        name = data["name"]
        description = data["description"]
        for c in project.capabilities:
            if c.id.lower().replace(" ", "_") == name.lower().replace(" ", "_"):
                c.description = description
                c.label = data["name"]
                break


def get_cve_descriptions(project):
    for c in project.capabilities:
        try:
            response = requests.get("https://cveawg.mitre.org/api/cve/" + c.id).json()
            descriptions = response["containers"]["cna"]["descriptions"]
            c.description = descriptions[0]["value"]
        except Exception:
            c.description = ""


def get_nist_descriptions(project, version):
    rev5_link = "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/sp_800_53_5_1_1/element/"
    rev4_link = "https://csrc.nist.gov/extensions/nudp/services/json/nudp/framework/version/sp_800_53_4_0_0/element/"
    link = ""
    if version == "rev4":
        link = rev4_link
    else:
        link = rev5_link

    for c in project.capabilities:
        try:
            id = c.id
            if len(id) < 5 and version != "rev4":
                id = c.id[0:3] + "0" + c.id[3:4]
            response = requests.get(link + id + "/graph").json()
            elements = response["response"]["elements"]
            element_array = elements[0]["elements"][0]["elements"]
            for item in element_array:
                if item["elementTypeIdentifier"] == "discussion":
                    c.description = item["text"].replace("<p>", "").replace("</p>", "")
                    break
        except Exception as e:
            print("exception ", e)


def parse_capabilities(project):
    mappings = project.mappings
    allIds = [m["capability_id"] for m in mappings]
    capabilityIds = list(set(allIds))
    capabilities = []
    for id in capabilityIds:
        c = Capability()
        c.id = id
        c.mappings = [m for m in mappings if (m["capability_id"] == id)]
        print(
            "for capability " + c.id + " number of mappings is  " + str(len(c.mappings))
        )
        capabilities.append(c)
    return capabilities


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
    attack_prefix = url_prefix + "attack/" + "attack-" + attack_version + "/"
    external_prefix = (
        url_prefix
        + "external/"
        + project.id
        + "/attack-"
        + attack_version
        + "/"
        + project.id
        + "-"
        + project_version
        + "/"
    )
    headers = [
        ("attack_object_id", "ATT&CK ID", "attack_object_id", attack_prefix),
        ("attack_object_name", "ATT&CK Name", "attack_object_id", attack_prefix),
        ("mapping_type", "Mapping Type"),
        ("capability_id", "Capability ID", "capability_id", external_prefix),
        (
            "capability_description",
            "Capability Description",
            "capability_id",
            external_prefix,
        ),
    ]
    if project.id == "azure" or project.id == "aws" or project.id == "gcp":
        headers = [
            ("attack_object_id", "ATT&CK ID", "attack_object_id", attack_prefix),
            ("attack_object_name", "ATT&CK Name", "attack_object_id", attack_prefix),
            ("score_category", "Category"),
            ("score_value", "Value"),
            ("capability_id", "Capability ID", "capability_id", external_prefix),
            (
                "capability_description",
                "Capability Description",
                "capability_id",
                external_prefix,
            ),
        ]

    group_headers = [
        ("id", "ID", "id", external_prefix),
        ("name", "Control Family", "id", external_prefix),
        # ("num_controls", "Number of Controls"),
        ("num_mappings", "Number of Mappings"),
    ]

    project_id = project.id if project.id != "nist" else "nist_800_53"
    stream = template.stream(
        title=project.label + " Landing",
        url_prefix=url_prefix,
        control=project.label,
        description=project.description,
        project_id=project_id,
        project_version=project_version,
        versions=project.versions,
        attack_version=attack_version,
        attackVersions=project.attackVersions,
        domain=project.attackDomain,
        domains=project.attackDomains,
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
            headers=headers,
        )
    for capability in project.capabilities:
        build_external_capability(
            project=project,
            url_prefix=url_prefix,
            parent_dir=project_dir,
            project_version=project_version,
            attack_version=attack_version,
            headers=headers,
            capability=capability,
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
        project_id=project.id,
        description=project.description,
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


def build_external_capability(
    project: ExternalControl,
    url_prefix,
    parent_dir,
    project_version,
    attack_version,
    headers,
    capability,
):
    dir = parent_dir / capability.id
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    template = load_template("external-capability.html.j2")
    prev_page = parent_dir
    stream = template.stream(
        title=project.label + " " + capability.id,
        url_prefix=url_prefix,
        control=project.label,
        project=project,
        project_id=project.id,
        description=capability.description,
        control_version=project_version,
        versions=project.versions,
        attack_version=attack_version,
        attackVersions=project.attackVersions,
        domain=project.attackDomain,
        domains=project.attackDomains,
        prev_page=prev_page,
        mappings=capability.mappings,
        headers=headers,
        capability=capability,
    )
    stream.dump(str(output_path))
    print("          Created capability page " + capability.id)


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


if __name__ == "__main__":
    main()
