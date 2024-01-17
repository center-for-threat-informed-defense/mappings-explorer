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


def build_capability_url(mapping: dict, url_prefix: str, id: str):
    """Jinja template to handle building custom capability urls
    Args:
        mapping: mapping data that holds information on the capability to be linked
        url_prefix: base url for built site
        id: the capability id to link to

    Returns:
        url pointing to the capability referenced in mapping
    """
    return (
        f"{url_prefix}external/{mapping['project']}/attack-{mapping['attack_version']}/"
        f"domain-{mapping['attack_domain'].lower()}/{mapping['project']}-{mapping['project_version']}/{id}/"
    )


_environment.filters["build_capability_url"] = build_capability_url
