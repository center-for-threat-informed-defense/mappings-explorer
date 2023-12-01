import json
from copy import deepcopy

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
    attack_data_array = []
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
            attack_object_short_name = attack_object.get("x_mitre_shortname", "")
            attack_object_type = (
                "tactic"
                if attack_object.get("type") == "x-mitre-tactic"
                else "subtechnique"
                if attack_object.get("x_mitre_is_subtechnique")
                else "technique"
            )
            attack_object_parents = []
            if attack_object_type == "technique":
                kill_chain_phases = attack_object.get("kill_chain_phases", [])
                for phase in kill_chain_phases:
                    if phase.get("kill_chain_name") == "mitre-attack":
                        attack_object_parents.append(phase.get("phase_name"))
            attack_object_technique = (
                attack_object_id[0 : attack_object_id.index(".")]
                if attack_object_type == "subtechnique"
                else ""
            )
            attack_data_array.append(
                {
                    "id": attack_object_id,
                    "name": attack_object_name,
                    "url": attack_object_url,
                    "description": attack_object_description,
                    "type": attack_object_type,
                    "tactics": attack_object_parents,
                    "technique": attack_object_technique,
                    "short_name": attack_object_short_name,
                }
            )

    return attack_data_array


def create_attack_jsons(all_attack_versions, output_filepath, mappings_filepath):
    attack_data_dict = {}
    for attack_version in all_attack_versions:
        attack_data = load_attack_json(attack_version, "enterprise")
        formatted_attack_data = format_attack_data(attack_data)
        attack_data_dict[attack_version] = formatted_attack_data

    for mappings_file in mappings_filepath.rglob("**/*.json"):
        if (
            "stix" not in mappings_file.name
            and "navigator_layer" not in mappings_file.name
        ):
            mappings = json.loads(mappings_file.read_text(encoding="UTF-8"))
            add_mappings_to_attack_data_dict(mappings, attack_data_dict)

    for attack_version in all_attack_versions:
        add_background_colors(attack_data_dict[attack_version])
        filepath = (
            output_filepath
            / "enterprise"
            / attack_version
            / f"enterprise-{attack_version}_matrix_data.json"
        )
        filepath.parent.mkdir(parents=True, exist_ok=True)

        json_file = open(
            filepath,
            "w",
            encoding="UTF-8",
        )
        json.dump(attack_data_dict[attack_version], fp=json_file)


def add_background_colors(attack_version_data):
    max_score = 0
    min_score = 100000
    for attack_object in attack_version_data:
        score = len(attack_version_data[attack_object]["capabilities_mapped"])
        attack_version_data[attack_object]["score"] = score
        if score > max_score:
            max_score = score
        if score < min_score:
            min_score = score
    if max_score != 0:
        r = 255
        g = 180
        b = 0
        max_a = 1
        min_a = 0 if min_score == 0 else 0.13
        difference = (
            (max_a - min_a) / (max_score - min_score) if max_score != min_score else 0
        )
        for attack_object in attack_version_data:
            if attack_version_data[attack_object]["type"] != "tactic":
                attack_object_score = attack_version_data[attack_object]["score"]
                adjusted_score = attack_object_score - min_score
                background_color_opacity = min_a + (adjusted_score * difference)
                attack_version_data[attack_object][
                    "background_color"
                ] = f"rgba({r}, {g}, {b}, {background_color_opacity})"


def add_mappings_to_attack_data_dict(mappings, attack_data_dict):
    attack_data_version = attack_data_dict[mappings["metadata"]["attack_version"]]
    original_attack_data_version = deepcopy(attack_data_version)

    for mapping in mappings["mapping_objects"]:
        technique_id = mapping["attack_object_id"]
        if attack_data_version.get(technique_id):
            attack_data_version[technique_id]["capabilities_mapped"].append(
                mapping["capability_id"]
            )
    if mappings["metadata"]["mapping_framework"] == "cve":
        for technique in attack_data_version:
            current_capabilites_mapped = attack_data_version[technique][
                "capabilities_mapped"
            ]
            original_capabilites_mapped = original_attack_data_version[technique][
                "capabilities_mapped"
            ]
            amount_cves_mapped = len(current_capabilites_mapped) - len(
                original_capabilites_mapped
            )
            attack_data_version[technique][
                "capabilities_mapped"
            ] = original_capabilites_mapped
            if amount_cves_mapped > 0:
                attack_data_version[technique]["capabilities_mapped"].append(
                    f"+{amount_cves_mapped} CVEs"
                )


def format_attack_data(attack_data):
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
            attack_object_short_name = attack_object.get("x_mitre_shortname", "")
            attack_object_type = (
                "tactic"
                if attack_object.get("type") == "x-mitre-tactic"
                else "subtechnique"
                if attack_object.get("x_mitre_is_subtechnique")
                else "technique"
            )
            attack_object_parents = []
            if attack_object_type == "technique":
                kill_chain_phases = attack_object.get("kill_chain_phases", [])
                for phase in kill_chain_phases:
                    if phase.get("kill_chain_name") == "mitre-attack":
                        attack_object_parents.append(phase.get("phase_name"))
            attack_object_technique = (
                attack_object_id[0 : attack_object_id.index(".")]
                if attack_object_type == "subtechnique"
                else ""
            )
            attack_data_dict[attack_object_id] = {
                "name": attack_object_name,
                "type": attack_object_type,
                "tactics": attack_object_parents,
                "technique": attack_object_technique,
                "short_name": attack_object_short_name,
                "capabilities_mapped": [],
                "background_color": "",
                "id": attack_object_id,
            }

    return attack_data_dict
