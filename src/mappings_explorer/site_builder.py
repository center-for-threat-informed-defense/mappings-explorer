from jinja2 import Environment, FileSystemLoader


class ExternalControl:
    id = ""
    label = ""
    description = []
    version = []
    attackVersion = []
    attackDomain = []
    tableHeaders = []


def main():
    templateLoader = FileSystemLoader(searchpath="./templates")
    templateEnv = Environment(loader=templateLoader)
    nist = ExternalControl()
    nist.id = "nist"
    nist.label = "NIST 800-53"
    nist.description = [
        "The NIST 800-53 is a cybersecurity standard and compliance framework developed by the National Institute of Standards in Technology. It’s a continuously updated framework that tries to flexibly define standards, controls, and assessments based on risk, cost-effectiveness, and capabilities. Currently, the NIST framework is mapped to ATT&CK Versions 8.2, 9.0, and 10.1.",
        "The NIST 800-53 framework is designed to provide a foundation of guiding elements, strategies, systems, and controls, that can agnostically support any organization’s cybersecurity needs and priorities. By establishing a framework available to all, it fosters communication and allows organizations to speak using a shared language. Lastly, because it doesn’t specifically support or suggest specific tools, companies, or vendors (intentionally so), it’s designed to be used as new technologies, systems, environments, and organizational changes arise, shifting cybersecurity needs.",
    ]
    nist.version = ["rev4", "rev5"]
    nist.attackVersion = [
        "8.2",
        "9.0",
        "10.1",
    ]
    nist.attackDomain = ["enterprise"]
    nist.tableHeaders = ["ID", "Control Family", "Number of Controls", "Description"]

    veris = ExternalControl()
    veris.id = "veris"
    veris.label = "VERIS"
    veris.description = [
        "The Vocabulary for Event Recording and Incident Sharing (VERIS) is a set of metrics designed to provide a common language for describing security incidents in a structured and repeatable manner. The overall goal is to lay a foundation from which we can constructively and cooperatively learn from our experiences to better measure and manage risk. "
    ]
    veris.version = ["1.3.7", "1.3.5"]
    veris.attackDomain = ["enterprise"]
    veris.attackVersion = ["9.0", "12.0"]

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

    template.stream(
        title="NIST Landing",
        control=nist.label,
        description=nist.description,
        version=nist.version,
        attackVersion=nist.attackVersion,
        domain=nist.attackDomain,
        tableHeaders=nist.tableHeaders,
    ).dump("./output/nist-landing.html")
    print("Created nist landing")
    template.stream(
        title="VERIS Landing",
        control=veris.label,
        description=veris.description,
        attackVersion=veris.attackVersion,
        domain=veris.attackDomain,
    ).dump("./output/veris-landing.html")
    print("Created veris landing")


if __name__ == "__main__":
    main()
