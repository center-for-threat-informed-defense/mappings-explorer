import argparse
import csv, yaml
import os

def main():
    """Main entry point for `mapex` command line."""
    args = _parse_args()
    if args.mappings == 'cve':
        parseCveMappings()
    if args.mappings == 'nist':
        parseNistMappings()


def _parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mappings',
                        type=str,
                        required=True,
                        help="Set of mappings to parse")
    args: argparse.Namespace = parser.parse_args()
    return args


def parseCveMappings():
    # read in csv file
    cve_mappings = open('./mappings/Att&ckToCveMappings.csv',
                        'r',
                        encoding='UTF-8')
    datareader = csv.reader(cve_mappings, delimiter=",", quotechar='"')
    csvToYaml(datareader)


def parseNistMappings():
    # read in tsv files
    directory = './mappings/NIST_800-53'
    # iterate over files in directory
    for filename in os.listdir(directory):
        file = os.path.join(directory, filename)
        # checking if it is a file
        if os.path.isfile(file):
            nist_mappings = open(
                f"{directory}/{filename}",
                'r',
                encoding='UTF-8')
            datareader = csv.reader(
                nist_mappings,
                delimiter="\t",
                quotechar='"'
            )
            csvToYaml(datareader)


def csvToYaml(datareader):
    result = list()
    type_index = -1
    child_fields_index = -1

    # parse csv file to yaml
    for row_index, row in enumerate(datareader):
        if row_index == 0:
            data_headings = list()
            for heading_index, heading in enumerate(row):
                fixed_heading = heading.lower().replace(" ", "_").replace("-", "")
                data_headings.append(fixed_heading)
                if fixed_heading == "type":
                    type_index = heading_index
                elif fixed_heading == "childfields":
                    child_fields_index = heading_index
        else:
            content = dict()
            is_array = False
            for cell_index, cell in enumerate(row):
                if cell_index == child_fields_index and is_array:
                    content[data_headings[cell_index]] = [{
                        "source": "fra:" + value.capitalize(),
                        "destination": value,
                        "type": "string",
                        "childfields": "null"
                    } for value in cell.split(",")]
                else:
                    content[data_headings[cell_index]] = cell
                    is_array = (cell_index == type_index) and (cell == "array")
                result.append(content)

    # print out yaml
    print(yaml.dump(result))


if __name__ == "__main__":
    main()
