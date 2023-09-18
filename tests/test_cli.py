import csv
import os
import yaml
from src.mappings_explorer.cli.cli import csv_to_yaml, json_to_yaml, read_yaml

def read_csv_file(filename):
    csv_file = open(filename, 'r', encoding='UTF-8')
    return csv.reader(csv_file, delimiter=",", quotechar='"')


def read_tsv_file(filename):
    csv_file = open(filename, 'r', encoding='UTF-8')
    return csv.reader(csv_file, delimiter="\t", quotechar='"')


def read_json_file(filename):
    with open(filename, encoding='UTF-8') as user_file:
        return user_file.read()


def test_csv_parser():

    # ARRANGE
    filename = os.path.join(os.path.dirname(__file__), 'files/test.csv')
    datareader = read_csv_file(filename)
    expected = yaml.dump([{
          'First_Name': 'Joe',
          'Last_Name': 'Fried',
          'Shirt_Size': 'XS'
        },
        {
          'First_Name': 'Alex',
          'Last_Name': 'Fine',
          'Shirt_Size': 'L'
        }])

    # ACT
    result = yaml.dump(csv_to_yaml(datareader))

    # ASSERT
    assert result == expected


def test_tsv_parser():
    # ARRANGE
    filename = os.path.join(os.path.dirname(__file__), 'files/test.tsv')
    datareader = read_tsv_file(filename)
    expected = yaml.dump([{
          'First_Name': 'Joe',
          'Last_Name': 'Fried',
          'Shirt_Size': 'XS'
        },
        {
          'First_Name': 'Alex',
          'Last_Name': 'Fine',
          'Shirt_Size': 'L'
        }])

    # ACT
    result = yaml.dump(csv_to_yaml(datareader))

    # ASSERT
    assert result == expected

def test_json_parser():

    # ARRANGE
    filename = os.path.join(os.path.dirname(__file__), 'files/test.json')
    file = read_json_file(filename)
    expected = yaml.dump([{
          'First_Name': 'Joe',
          'Last_Name': 'Fried',
          'Shirt_Size': 'XS'
        },
        {
          'First_Name': 'Alex',
          'Last_Name': 'Fine',
          'Shirt_Size': 'L'
        }])

    # ACT
    result = yaml.dump(json_to_yaml(file))

    # ASSERT
    assert result == expected

def test_read_yaml():
    # ARRANGE
    filename = os.path.join(os.path.dirname(__file__), 'files/test.yaml')
    expected = yaml.dump([{
          'First_Name': 'Joe',
          'Last_Name': 'Fried',
          'Shirt_Size': 'XS'
        },
        {
          'First_Name': 'Alex',
          'Last_Name': 'Fine',
          'Shirt_Size': 'L'
        }])


    # ACT
    result = read_yaml(filename)

    # ASSERT
    assert result == expected
