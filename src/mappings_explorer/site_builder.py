from jinja2 import Environment, FileSystemLoader


def main():
    print("Creating site index")
    templateLoader = FileSystemLoader(searchpath="./templates")
    templateEnv = Environment(loader=templateLoader)
    TEMPLATE_FILE = "landing.html.j2"
    template = templateEnv.get_template(TEMPLATE_FILE)

    template.stream(title="Mappings Explorer").dump("./output/index.html")


if __name__ == "__main__":
    main()
