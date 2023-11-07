from pathlib import Path

from jinja2 import Environment, FileSystemLoader, Template

ROOT_DIR = Path(__file__).parents[2]
PUBLIC_DIR = ROOT_DIR / "output"
TEMPLATE_DIR = ROOT_DIR / "src" / "mappings_explorer" / "templates"
# add data directory once it's ready

_environment = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=True)


def load_template(name: str) -> Template:
    """
    Load a jinja2 template by name from the templates directory.

    Args:
        name: e.g. "nav.html"
    """
    return _environment.get_template(name)
