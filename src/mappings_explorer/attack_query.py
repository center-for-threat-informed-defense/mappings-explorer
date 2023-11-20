import json

import requests


def get_attack_data(attack_version, attack_domain):
    attack_data = load_attack_json(attack_version, attack_domain)
    attack_dict = build_attack_dict(attack_data)
    return attack_dict


def load_attack_json(attack_version, attack_domain):
    BASE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
    domain = attack_domain.lower()
    attack_url = f"{BASE_URL}/{domain}-attack/{domain}-attack-{attack_version}.json"
    response = requests.get(attack_url)
    attack_data = json.loads(response.text)
    return attack_data


def build_attack_dict(attack_data):
    attack_data_dict = {}
    for attack_object in attack_data["objects"]:
        # skip objects without IDs
        if not attack_object.get("external_references"):
            continue
        # skip deprecated and revoked objects
        # Note: False is the default value if the property is not present
        if attack_object.get("revoked", False):
            continue
        # Note: False is the default value if the property is not present
        if attack_object.get("x_mitre_deprecated", False):
            continue
        if attack_object.get("type") in ["x-mitre-tactic", "attack-pattern"]:
            external_references = attack_object.get("external_references")
            attack_object_id = external_references[0].get("external_id")
            attack_object_name = attack_object.get("name")
            attack_object_url = external_references[0].get("url")
            attack_object_description = attack_object.get("description")
            attack_data_dict[attack_object_id] = {
                "name": attack_object_name,
                "url": attack_object_url,
                "description": attack_object_description,
            }

    return attack_data_dict
