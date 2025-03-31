from pathlib import Path
from mapex_convert.read_files import read_yaml_file
from mapex_convert.cli import main as convert_main

OUTPUT = Path(__file__).parent.parent / "public" / "static" / "matrices"

if __name__ == "__main__":
    # This CLI already converts all frameworks into JSON under OUTPUT
    convert_main(args=["--output", str(OUTPUT)])