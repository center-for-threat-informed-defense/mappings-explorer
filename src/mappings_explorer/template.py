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
        f"domain-{mapping['attack_domain'].lower()}/{mapping['project']}-"
        f"{mapping['project_version']}/{id.replace(' ', '_')}/"
    )


_environment.filters["build_capability_url"] = build_capability_url


def format_int(value: int) -> str:
    """
    Format an integer value.

    Args:
        value: an integer to format

    Returns:
        formatted value
    """
    return "{:,d}".format(value)


_environment.filters["format_int"] = format_int


def data_size(value):
    """
    Format a number of bytes as a more readable unit.

    Args:
        value; a byte count

    Returns:
        A human-friendly string like "4.3MB"
    """
    units = ["bytes", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"]
    unit_idx = 0
    while value > 1000:
        value /= 1000
        unit_idx += 1
    return f"{value:0.1f} {units[unit_idx]}"


_environment.filters["data_size"] = data_size


def format_cell_value(id, value):
    """
    Formats table cell's value.

    Args:
        id; the column's identifier
        value: the cell's value.

    Returns:
        A human-friendly string.
    """
    if id == "comments":
        return value.strip()
    elif id == "references":
        links = "".join(
            [f'<li><a href="{x}" target="_blank">{x}</a></li>' for x in value]
        )
        return f"<ol>{links}</ol>"
    else:
        return value


_environment.filters["format_cell_value"] = format_cell_value
