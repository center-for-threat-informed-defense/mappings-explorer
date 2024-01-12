from pathlib import Path

from jinja2 import Environment, FileSystemLoader, Template
from jinja_markdown import MarkdownExtension

ROOT_DIR = Path(__file__).parents[2]
PUBLIC_DIR = ROOT_DIR / "output"
TEMPLATE_DIR = ROOT_DIR / "src" / "mappings_explorer" / "templates"
DATA_DIR = ROOT_DIR / "src" / "mapex_convert" / "mappings"

_environment = Environment(loader=FileSystemLoader(TEMPLATE_DIR), autoescape=True)
_environment.add_extension(MarkdownExtension)


def load_template(name: str) -> Template:
    """
    Load a jinja2 template by name from the templates directory.

    Args:
        name: e.g. "nav.html"
    """
    return _environment.get_template(name)
