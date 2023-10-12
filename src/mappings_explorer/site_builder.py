from jinja2 import Environment, FileSystemLoader

from .template import PUBLIC_DIR, load_template


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
    tableHeaders = []


def load_projects():
    nist = ExternalControl()
    nist.id = "nist"
    nist.label = "NIST 800-53"
    nist.description = [
        "The NIST 800-53 is a cybersecurity standard and compliance framework developed by the National Institute of Standards in Technology. It’s a continuously updated framework that tries to flexibly define standards, controls, and assessments based on risk, cost-effectiveness, and capabilities. Currently, the NIST framework is mapped to ATT&CK Versions 8.2, 9.0, and 10.1.",
        "The NIST 800-53 framework is designed to provide a foundation of guiding elements, strategies, systems, and controls, that can agnostically support any organization’s cybersecurity needs and priorities. By establishing a framework available to all, it fosters communication and allows organizations to speak using a shared language. Lastly, because it doesn’t specifically support or suggest specific tools, companies, or vendors (intentionally so), it’s designed to be used as new technologies, systems, environments, and organizational changes arise, shifting cybersecurity needs.",
    ]
    nist.versions = ["rev5", "rev4"]
    nist.version = nist.versions[0]
    nist.attackVersions = [
        "10.1",
        "9.0",
        "8.2",
    ]
    nist.attackVersion = nist.attackVersions[0]
    nist.attackDomains = ["enterprise"]
    nist.attackDomain = nist.attackDomains[0]
    nist.tableHeaders = ["ID", "Control Family", "Number of Controls", "Description"]
    veris = ExternalControl()
    veris.id = "veris"
    veris.label = "VERIS"
    veris.description = [
        "The Vocabulary for Event Recording and Incident Sharing (VERIS) is a set of metrics designed to provide a common language for describing security incidents in a structured and repeatable manner. The overall goal is to lay a foundation from which we can constructively and cooperatively learn from our experiences to better measure and manage risk. "
    ]
    veris.versions = ["1.3.7", "1.3.5"]
    veris.version = veris.versions[0]
    veris.attackDomains = ["enterprise"]
    veris.attackDomain = veris.attackDomains[0]
    veris.attackVersions = ["9.0", "12.0"]
    veris.attackVersion = veris.attackVersions[0]
    veris.tableHeaders = ["ID", "Control Family", "Number of Controls", "Description"]

    cve = ExternalControl()
    cve.id = "cve"
    cve.label = "CVE"
    cve.description = [
        "Common Vulnerabilities and Exposures (CVE) is a database of publicly available information security issues. CVE provides a convenient, reliable way for vendors, enterprises, academics, and all other interested parties to exchange information about cyber security issues. Sharing CVE details is beneficial to all organizations it allows organizations to set a baseline for evaluating the coverage of their security tools. CVE numbers allow organizations to see what each tool covers and how appropriate they are for your organization."
    ]
    cve.attackDomains = ["enterprise"]
    cve.attackDomain = cve.attackDomains[0]
    cve.attackVersions = ["9.0"]
    cve.attackVersion = cve.attackVersions[0]
    cve.tableHeaders = ["ID", "Control Family", "Number of Controls", "Description"]

    aws = ExternalControl()
    aws.id = "aws"
    aws.label = "AWS"
    aws.description = [
        "These mappings of the Amazon Web Services (AWS) security controls to MITRE ATT&CK® are designed to empower organizations with independent data on which native AWS security controls are most useful in defending against the adversary TTPs that they care about. These mappings are part of a collection of mappings of native product security controls to ATT&CK based on a common methodology, scoring rubric, data model, and tool set. This full set of resources is available on the Center’s project page."
    ]
    aws.attackDomains = ["enterprise"]
    aws.attackDomain = aws.attackDomains[0]
    aws.attackVersions = ["9.0"]
    aws.attackVersion = aws.attackVersions[0]
    aws.tableHeaders = ["ID", "Control Family", "Number of Controls", "Description"]
    azure = ExternalControl()
    azure.id = "azure"
    azure.label = "Azure"
    azure.description = [
        "These mappings of the Microsoft Azure Infrastructure as a Services (IaaS) security controls to MITRE ATT&CK® are designed to empower organizations with independent data on which native Azure security controls are most useful in defending against the adversary TTPs that they care about. These mappings are part of a collection of mappings of native product security controls to ATT&CK based on a common methodology, scoring rubric, data model, and tool set. This full set of resources is available on the Center’s project page."
    ]
    azure.attackDomains = ["enterprise"]
    azure.attackDomain = azure.attackDomains[0]
    azure.attackVersions = ["8.2"]
    azure.attackVersion = azure.attackVersions[0]
    azure.tableHeaders = ["ID", "Control Family", "Number of Controls", "Description"]
    gcp = ExternalControl()
    gcp.id = "gcp"
    gcp.label = "GCP"
    gcp.description = [
        "These mappings of the Google Cloud Platform (GCP) security controls to MITRE ATT&CK® are designed to empower organizations with independent data on which native GCP security controls are most useful in defending against the adversary TTPs that they care about. These mappings are part of a collection of mappings of native product security controls to ATT&CK based on a common methodology, scoring rubric, data model, and tool set. This full set of resources is available on the Center’s project page."
    ]
    gcp.attackDomains = ["enterprise"]
    gcp.attackDomain = gcp.attackDomains[0]
    gcp.attackVersions = ["10.0"]
    gcp.attackVersion = gcp.attackVersions[0]
    gcp.tableHeaders = ["ID", "Control Family", "Number of Controls", "Description"]

    projects = [nist, veris, cve, aws, azure, gcp]
    return projects


def build_external_landing(project: ExternalControl):
    dir = PUBLIC_DIR / project.id
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"

    template = load_template("external-control.html.j2")
    stream = template.stream(
        title=project.label + " Landing",
        control=project.label,
        description=project.description,
        version=project.version,
        versions=project.versions,
        attackVersion=project.attackVersion,
        attackVersions=project.attackVersions,
        domain=project.attackDomain,
        domains=project.attackDomains,
        tableHeaders=project.tableHeaders,
    )
    stream.dump(str(output_path))
    print("Created " + project.id + " landing")


def main():
    templateLoader = FileSystemLoader(searchpath="./src/mappings_explorer/templates")
    templateEnv = Environment(loader=templateLoader)
    projects = load_projects()

    TEMPLATE_FILE = "landing.html.j2"
    template = templateEnv.get_template(TEMPLATE_FILE)
    template.stream(title="Mappings Explorer").dump("./output/index.html")
    print("Created site index")

    TEMPLATE_FILE = "external-landing.html.j2"
    template = templateEnv.get_template(TEMPLATE_FILE)

    template.stream(title="External Mappings Home").dump(
        "./output/external-landing.html"
    )
    print("Created external mappings home")

    TEMPLATE_FILE = "external-control.html.j2"
    template = templateEnv.get_template(TEMPLATE_FILE)

    for project in projects:
        build_external_landing(project=project)
        # template.stream(
        #     title=project.label + " Landing",
        #     control=project.label,
        #     description=project.description,
        #     version=project.version,
        #     versions=project.versions,
        #     attackVersion=project.attackVersion,
        #     attackVersions=project.attackVersions,
        #     domain=project.attackDomain,
        #     domains=project.attackDomains,
        #     tableHeaders=project.tableHeaders,
        # ).dump("./output/" + project.id + "-landing.html")
        # print("Created " + project.id + " landing")


if __name__ == "__main__":
    main()
