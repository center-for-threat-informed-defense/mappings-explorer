import argparse
import csv
import json
import os
import yaml

ROOT_DIR = cwd = os.getcwd()

def main():
    """Main entry point for `mapex` command line."""
    args = _parse_args()
    if args.mappings == 'cve':
        parse_cve_mappings()
    elif args.mappings == 'nist':
        parse_nist_mappings()
    elif args.mappings == 'veris':
        parse_veris_mappings()
    elif args.mappings == 'security-stack':
        parse_security_stack_mappings()


def _parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mappings',
                        type=str,
                        required=True,
                        help='''Set of mappings to parse
                        Options: cve, nist, veris, security-stack
                        ''')
    args: argparse.Namespace = parser.parse_args()
    return args



def parse_cve_mappings():
    # read in csv file
    cve_mappings = open(
        f'{ROOT_DIR}/mappings/Att&ckToCveMappings.csv',
        'r',
        encoding='UTF-8')
    datareader = csv.reader(cve_mappings, delimiter=",", quotechar='"')
    print(yaml.dump(csv_to_yaml(datareader)))


def parse_nist_mappings():
    # read in tsv files
    directory = f'{ROOT_DIR}/mappings/NIST_800-53'
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
            print(yaml.dump(csv_to_yaml(datareader)))


def parse_veris_mappings():
    veris_mappings_file = f"{ROOT_DIR}/mappings/veris-mappings.json"
    with open(veris_mappings_file, encoding='UTF-8') as user_file:
        veris_mappings = user_file.read()
        result = json_to_yaml(veris_mappings)
    print(yaml.dump(result))


def parse_security_stack_mappings():
    rootdir = f"{ROOT_DIR}/mappings/SecurityStack"
    # read in all files in SecurityStack directory

    for subdir, _, files in os.walk(rootdir):
        for file in files:
            filepath = os.path.join(subdir, file)
            result = read_yaml(filepath)
            print(result)


def csv_to_yaml(datareader):
    result = []
    keys = next(datareader)

    # parse csv file to yaml
    for row in datareader:
        result.append(dict(zip(keys, row)))

    # print out yaml
    return result


def json_to_yaml(file):
    veris_mappings_dict = json.loads(file)
    return veris_mappings_dict


def read_yaml(filepath):
    with open(filepath, encoding="UTF-8") as file:
        return file.read()

