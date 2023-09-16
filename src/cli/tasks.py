from invoke import task


@task()
def lint(c):
    """
    Run black, ruff, and mypy
    """
    print("\n→ Running Ruff (Linter)...\n")
    c.run("poetry run ruff check .")
    print("\n→ Running Black (Formatter)...\n")
    c.run("poetry run black --check ./")
    print("\n→ Running mypy (Type Checking)...\n")
    c.run("poetry run mypy --check ./mappings_cli")
    print("")


@task(help={"xml": "Include XML coverage report"})
def test(c, xml=False):
    """
    Run Python tests.
    """
    if xml:
        c.run("poetry run pytest --cov=mappings_cli/ --cov-report=xml")
    else:
        c.run("poetry run pytest --cov=mappings_cli/ --cov-report=term-missing")


@task()
def build(c):
    """
    Build the Python package.
    """
    c.run("poetry build")
