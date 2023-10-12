import json

import pandas as pd
import yaml


def read_csv_file(filepath):
    df = pd.read_csv(filepath)
    return df


def read_excel_file(filepath):
    df = pd.read_excel(filepath)
    return df


def read_json_file(filepath):
    with open(filepath, encoding="UTF-8") as user_file:
        veris_mappings = user_file.read()
        return json.loads(veris_mappings)


def read_yaml_file(filepath):
    with open(filepath, encoding="UTF-8") as file:
        return yaml.safe_load(file)
