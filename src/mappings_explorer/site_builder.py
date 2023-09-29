from jinja2 import Environment, FileSystemLoader


def main():
    templateLoader = FileSystemLoader(searchpath="./templates")
    templateEnv = Environment(loader=templateLoader)
    TEMPLATE_FILE = "landing.html.j2"
    template = templateEnv.get_template(TEMPLATE_FILE)
    template.stream(
        title="Mappings Explorer"
    ).dump('./output/index.html')
    print("Created site index")

    TEMPLATE_FILE = "external-landing.html.j2"
    template = templateEnv.get_template(TEMPLATE_FILE)

    template.stream(
        title="External Mappings Home"
    ).dump('./output/external-landing.html')
    print("Created external mappings home")

if __name__ == "__main__":
    main()
