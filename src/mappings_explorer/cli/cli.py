import argparse
import csv
import json
import os
import requests
import yaml

ROOT_DIR = os.path.abspath(os.curdir)

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

    # skip the headers
    next(datareader, None)

    # BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
    # enterpise_attack_url = f"{BASE_URL}/enterprise-attack/enterprise-attack-13.0.json"
    # response = requests.get(enterpise_attack_url)
    # enterprise_attack_data = json.loads(response.text)

    # print(enterprise_attack_data)

    # put data in correct format with correct fields

    result = []
    for row in datareader:
        for i in range (1, 4):
            if row[i]:
                mapped_attack_objects = row[i].split('; ')
                for attack_object in mapped_attack_objects:
                     result.append({
                        'metadata': {
                            'mapping-verision': '1.0.0', # confirm that this value is correct
                            'attack-version': '13.1',
                            'creation-date': '02/03/21', # confirm this value is correct
                            'last-update': '10/27/21', # confirm this value is correct
                            'author': '',
                            'contact': '',
                            'organization': '',
                            'platform': 'CVE Vulnerability List',
                            'platform-version': 13, # confirm this value is correct
                            'mapping-type': 'association',
                        },
                        'attack-object': {
                            'id': attack_object,
                            'name': '',
                            'value': row[0],
                            'mapping-pattern': '',
                            'secondary-property': '',
                            'tags': [],
                            'comments': '',
                            'references': []
                        }
                      })

    print(yaml.dump(result))


def parse_nist_mappings():
    # read in tsv files
    directory = f'{ROOT_DIR}/mappings/NIST_800-53'
    # iterate over files in directory
    results = []
    nist_attack8_2_r4_filename = f"{directory}/attack-8-2-to-nist800-53-r4-mappings.tsv"
    nist_attack8_2_r5_filename = f"{directory}/attack-8-2-to-nist800-53-r5-mappings.tsv"
    nist_attack_9_0_r4_filename = f"{directory}/attack-9-0-to-nist800-53-r4-mappings.tsv"
    nist_attack_9_0_r5_filename = f"{directory}/attack-9-0-to-nist800-53-r5-mappings.tsv"
    nist_attack_10_1_r4_filename = f"{directory}/attack-10-1-to-nist800-53-r4-mappings.tsv"
    nist_attack_10_1_r5_filename = f"{directory}/attack-10-1-to-nist800-53-r5-mappings.tsv"
    nist_attack_12_1_r4_filename = f"{directory}/attack-12-1-to-nist800-53-r4-mappings.tsv"
    nist_attack_12_1_r5_filename = f"{directory}/attack-12-1-to-nist800-53-r5-mappings.tsv"

    # ATT&CK Version 8.2, NIST revision 4
    nist_mappings_8_2_r4 = open(nist_attack8_2_r4_filename, 'r', encoding='UTF-8')
    datareader = csv.reader(nist_mappings_8_2_r4, delimiter="\t", quotechar='"')

    # skip the headers
    next(datareader, None)

    for row in datareader:
        results.append({
            'metadata': {
                'mapping-verision': '',
                'attack-version': '8.2',
                'creation-date': '', # confirm this value is correct
                'last-update': '', # confirm this value is correct
                'author': '',
                'contact': '',
                'organization': '',
                'platform': 'NIST Security controls',
                'platform-version': '',
                'mapping-type': 'association',
            },
            'attack-object': {
                'id': row[2],
                'name': '',
                'value': row[3],
                'mapping-pattern': '',
                'secondary-property': '',
                'tags': [],
                'comments': '',
                'references': []
            }
        })

    # ATT&CK Version 8.2, NIST revision 5
    nist_mappings_8_2_r5 = open(nist_attack8_2_r5_filename, 'r', encoding='UTF-8')
    datareader = csv.reader(nist_mappings_8_2_r5, delimiter="\t", quotechar='"')

    # skip the headers
    next(datareader, None)

    results.append({
        'metadata': {
            'mapping-verision': '',
            'attack-version': '8.2',
            'creation-date': '', # confirm this value is correct
            'last-update': '', # confirm this value is correct
            'author': '',
            'contact': '',
            'organization': '',
            'platform': 'NIST Security controls',
            'platform-version': '',
            'mapping-type': 'association',
        },
        'attack-object': {
            'id': row[2],
            'name': '',
            'value': row[3],
            'mapping-pattern': '',
            'secondary-property': '',
            'tags': [],
            'comments': '',
            'references': []
        }
    })

    # ATT&CK Version 9.0, NIST revision 4
    nist_mappings_9_0_r4 = open(nist_attack_9_0_r4_filename, 'r', encoding='UTF-8')
    datareader = csv.reader(nist_mappings_9_0_r4, delimiter="\t", quotechar='"')
     # skip the headers
    next(datareader, None)

    for row in datareader:
        results.append({
            'metadata': {
                'mapping-verision': '',
                'attack-version': '8.2',
                'creation-date': '', # confirm this value is correct
                'last-update': '', # confirm this value is correct
                'author': '',
                'contact': '',
                'organization': '',
                'platform': 'NIST Security controls',
                'platform-version': '',
                'mapping-type': 'association',
            },
            'attack-object': {
                'id': row[2],
                'name': '',
                'value': row[3],
                'mapping-pattern': '',
                'secondary-property': '',
                'tags': [],
                'comments': '',
                'references': []
            }
        })


    # ATT&CK Version 9.0, NIST revision 5
    nist_mappings_9_0_r5 = open(nist_attack_9_0_r5_filename, 'r', encoding='UTF-8')
    datareader = csv.reader(nist_mappings_9_0_r5, delimiter="\t", quotechar='"')
 # skip the headers
    next(datareader, None)

    for row in datareader:
        results.append({
            'metadata': {
                'mapping-verision': '',
                'attack-version': '8.2',
                'creation-date': '', # confirm this value is correct
                'last-update': '', # confirm this value is correct
                'author': '',
                'contact': '',
                'organization': '',
                'platform': 'NIST Security controls',
                'platform-version': '',
                'mapping-type': 'association',
            },
            'attack-object': {
                'id': row[2],
                'name': '',
                'value': row[3],
                'mapping-pattern': '',
                'secondary-property': '',
                'tags': [],
                'comments': '',
                'references': []
            }
        })

    # ATT&CK Version 10.1, NIST revision 4
    nist_mappings_10_1_r4 = open(nist_attack_10_1_r4_filename, 'r', encoding='UTF-8')
    datareader = csv.reader(nist_mappings_10_1_r4, delimiter="\t", quotechar='"')
 # skip the headers
    next(datareader, None)

    for row in datareader:
        results.append({
            'metadata': {
                'mapping-verision': '',
                'attack-version': '8.2',
                'creation-date': '', # confirm this value is correct
                'last-update': '', # confirm this value is correct
                'author': '',
                'contact': '',
                'organization': '',
                'platform': 'NIST Security controls',
                'platform-version': '',
                'mapping-type': 'association',
            },
            'attack-object': {
                'id': row[2],
                'name': '',
                'value': row[3],
                'mapping-pattern': '',
                'secondary-property': '',
                'tags': [],
                'comments': '',
                'references': []
            }
        })

    # ATT&CK Version 10.1, NIST revision 5
    nist_mappings_10_1_r5 = open(nist_attack_10_1_r5_filename, 'r', encoding='UTF-8')
    datareader = csv.reader(nist_mappings_10_1_r5, delimiter="\t", quotechar='"')
 # skip the headers
    next(datareader, None)

    for row in datareader:
        results.append({
            'metadata': {
                'mapping-verision': '',
                'attack-version': '8.2',
                'creation-date': '', # confirm this value is correct
                'last-update': '', # confirm this value is correct
                'author': '',
                'contact': '',
                'organization': '',
                'platform': 'NIST Security controls',
                'platform-version': '',
                'mapping-type': 'association',
            },
            'attack-object': {
                'id': row[2],
                'name': '',
                'value': row[3],
                'mapping-pattern': '',
                'secondary-property': '',
                'tags': [],
                'comments': '',
                'references': []
            }
        })

    # ATT&CK Version 12.1, NIST revision 4
    nist_mappings_12_1_r4 = open(nist_attack_12_1_r4_filename, 'r', encoding='UTF-8')
    datareader = csv.reader(nist_mappings_12_1_r4, delimiter="\t", quotechar='"')
    # skip the headers
    next(datareader, None)

    for row in datareader:
        results.append({
            'metadata': {
                'mapping-verision': '',
                'attack-version': '12.1',
                'creation-date': '', # confirm this value is correct
                'last-update': '', # confirm this value is correct
                'author': '',
                'contact': '',
                'organization': '',
                'platform': 'NIST Security controls',
                'platform-version': '',
                'mapping-type': 'association',
            },
            'attack-object': {
                'id': row[3],
                'name': row[4],
                'value': row[0],
                'mapping-pattern': '',
                'secondary-property': '',
                'tags': [],
                'comments': '',
                'references': []
            }
        })

    # ATT&CK Version 12.1, NIST revision 5
    nist_mappings_12_1_r5 = open(nist_attack_12_1_r5_filename, 'r', encoding='UTF-8')
    datareader = csv.reader(nist_mappings_12_1_r5, delimiter="\t", quotechar='"')
    # skip the headers
    next(datareader, None)

    for row in datareader:
        results.append({
            'metadata': {
                'mapping-verision': '',
                'attack-version': '12.1',
                'creation-date': '', # confirm this value is correct
                'last-update': '', # confirm this value is correct
                'author': '',
                'contact': '',
                'organization': '',
                'platform': 'NIST Security controls',
                'platform-version': '',
                'mapping-type': 'association',
            },
            'attack-object': {
                'id': row[3],
                'name': row[4],
                'value': row[0],
                'mapping-pattern': '',
                'secondary-property': '',
                'tags': [],
                'comments': '',
                'references': []
            }
        })

    print(yaml.dump(results))


def parse_veris_mappings():
    veris_mappings_file = f"{ROOT_DIR}/mappings/veris-mappings.json"
    with open(veris_mappings_file, encoding='UTF-8') as user_file:
        veris_mappings = user_file.read()
        data = json.loads(veris_mappings)

    result = []
    for attack_object in data['attack_to_veris']:
        mapped_attack_object = data['attack_to_veris'][attack_object]
        for veris_object in mapped_attack_object['veris']:
            result.append({
                'metadata': {
                    'mapping-verision': data['metadata']['mappings_version'],
                    'attack-version': data['metadata']['attack_version'],
                    'creation-date': '08/26/21', # confirm this value is correct
                    'last-update': '04/05/23', # confirm this value is correct
                    'author': '',
                    'contact': '',
                    'organization': '',
                    'platform': 'VERIS Framework',
                    'platform-version': data['metadata']['veris_version'],
                    'mapping-type': 'association',
                },
                'attack-object': {
                    'id': attack_object,
                    'name': mapped_attack_object['name'],
                    'value': veris_object,
                    'mapping-pattern': '',
                    'secondary-property': '',
                    'tags': [],
                    'comments': '',
                    'references': []
                }
            })
    # print(result)
    print(yaml.dump(result))


def parse_security_stack_mappings():
    rootdir = f"{ROOT_DIR}/mappings/SecurityStack"
    # read in all files in SecurityStack directory
    results = []
    for subdir, _, files in os.walk(rootdir):
        for file in files:
            filepath = os.path.join(subdir, file)
            result = read_yaml(filepath)
            for technique in result['techniques']:
                related_score = False
                try:
                    related_score = True if technique['sub-techniques-scores'] else False
                except:
                    related_score = False
                for technique_score in technique['technique-scores']:
                    results.append({
                        'metadata': {
                            'mapping-verision': result['version'], # confirm that this value is correct
                            'attack-version': result['ATT&CK version'],
                            'creation-date': result['creation date'], # confirm that this value is correct
                            'last-update': result['creation date'], # confirm this value is correct
                            'author': '',
                            'contact': result['contact'],
                            'organization': '',
                            'platform': result['platform'],
                            'platform-version': '', # confirm this value is correct
                            'mapping-type': 'scoring',
                        },
                        'attack-object': {
                            'id': technique['id'],
                            'name': technique['name'],
                            'value': '',
                            'mapping-pattern': '',
                            'secondary-property': '',
                            'tags': [],
                            'comments': [],
                            'references': [],
                            'score-category': technique_score['category'],
                            'score-value': technique_score['value'],
                            'score-comment': '',
                            'related-score': related_score,
                            'tags': []
                        }
                    })
    print(yaml.dump(results))


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
        return yaml.safe_load(file)

