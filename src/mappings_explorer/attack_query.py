import json

import requests
from loguru import logger
from mapex.write_parsed_mappings import create_layer, get_techniques_dict

from .template import PUBLIC_DIR


def get_attack_data(attack_version, attack_domain):
    """Creates dictionary of attack objects -- techniques and subtechniques --
    and pertinent data about the attack objects

    Args:
        attack_version: The attack version that attack objects should be fetched from.
        This must be a string with one decimal field (i.e. "9.0").
        attack_domain: The attack domain that attack objects should be fetched from.
        Must be ICS, Mobile, or Enterprise. Case does not matter

    Returns:
        A dict mapping an attack object to its id, name, url, and description

    """
    attack_data = load_attack_json(attack_version, attack_domain)
    attack_dict = build_attack_dict(attack_data, attack_domain)
    return attack_dict


def load_attack_json(attack_version, attack_domain):
    """Fetches data from STIX data

    Args:
        attack_version: The attack version that should be fetched
        attack_domain: The attack domain that should be fetched

    Returns:
       STIX data that was fetched
    """
    domain = attack_domain.lower()
    cache_path = (
        PUBLIC_DIR / "data" / "attack" / f"{domain}-attack-{attack_version}.json"
    )
    if cache_path.exists():
        logger.debug(
            f"Loading cached ATT&CK data for {attack_domain}-{attack_version}…"
        )
        with cache_path.open() as cache_file:
            attack_data = json.load(cache_file)
    else:
        logger.debug(f"Downloading ATT&CK data for {attack_domain}-{attack_version}…")
        BASE_URL = (
            "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
        )
        attack_url = f"{BASE_URL}/{domain}-attack/{domain}-attack-{attack_version}.json"
        attack_data = fetch_url(attack_url)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with cache_path.open("w") as cache_file:
            json.dump(attack_data, cache_file)

    return attack_data


def fetch_url(url):
    response = requests.get(url)
    if response.status_code != 404:
        attack_data = json.loads(response.text)
        return attack_data
    return None


def build_attack_dict(attack_data, attack_domain):
    """Creates dictionary of attack objects -- techniques and subtechniques --
    and pertinent data about the attack objects

    Args:
        attack_data: A dictionary containing ATT&CK data in STIX format.
        attack_domain: The ATT&CK domain. Case does not matter

    Returns:
        A dict mapping an attack object to its id, name, url, and description

    """
    if not attack_data:
        return []
    attack_domain = attack_domain.lower()
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
            external_reference = external_references[0]
            attack_object_id = external_reference.get("external_id")
            attack_object_name = attack_object.get("name")
            attack_object_url = external_reference.get("url")
            attack_object_description = attack_object.get("description")
            attack_data_array.append(
                {
                    "id": attack_object_id,
                    "name": attack_object_name,
                    "url": attack_object_url,
                    "description": attack_object_description,
                }
            )

    return attack_data_array


def build_attack_data_dict(attack_domains):
    """Creates dictionary of attack data from all attack domain and attack version
    combinations.

    Args:
        attack_domains: A dictionary containing attack domains and the attack versions
        they support

    Returns:
        A dictionary mapping an attack domain and version to attack information

    """
    attack_data_dict = {}
    for attack_domain in attack_domains:
        for attack_version in attack_domains[attack_domain]:
            attack_data = load_attack_json(attack_version, attack_domain.lower())
            if attack_data:
                formatted_attack_data = format_attack_data(
                    attack_data, attack_domain.lower()
                )
                if attack_version not in attack_data_dict:
                    attack_data_dict[attack_version] = {}
                attack_data_dict[attack_version][
                    attack_domain.lower()
                ] = formatted_attack_data
    return attack_data_dict


def add_mappings_to_navigator_layer_dict(mappings, navigator_layer_dict):
    """Adds mappings to a dictionary where mappings from all mapping_frameworks are
    combined and sorted by attack domain and attack version

    Args:
        mappings: mapping file contents
        navigator_layer_dict: dictionary of mappings sorted by attack domain and
        attack version
    """

    metadata = mappings["metadata"]
    domain = metadata["technology_domain"]
    attack_version = metadata["attack_version"]
    mapping_objects = mappings["mapping_objects"]
    mapping_framework = metadata["mapping_framework"]
    mapping_framework_version = metadata["mapping_framework_version"]
    # only count nist_800_53 for rev5
    if mapping_framework != "nist_800_53" or mapping_framework_version == "rev5":
        if domain in navigator_layer_dict:
            if attack_version in navigator_layer_dict[domain]:
                navigator_layer_dict[domain][attack_version].extend(mapping_objects)
            else:
                navigator_layer_dict[domain][attack_version] = mapping_objects
        else:
            navigator_layer_dict[domain] = {}
            navigator_layer_dict[domain][attack_version] = mapping_objects


def write_matrix_jsons(attack_data_dict, output_filepath):
    """Writes JSON files with attack data for the matrix to specified filepath

    Args:
        attack_data_dict: dictionary with attack data
        output_filepath: filepath to write JSON files to
    """
    for attack_version, attack_domain_dict in attack_data_dict.items():
        for domain, attack_data in attack_domain_dict.items():
            add_background_colors(attack_data)

            filepath = output_filepath / domain / attack_version
            matrix_filepath = filepath / f"{domain}-{attack_version}_matrix_data.json"
            matrix_filepath.parent.mkdir(parents=True, exist_ok=True)

            matrix_json_file = open(
                matrix_filepath,
                "w",
                encoding="UTF-8",
            )
            json.dump(
                attack_data,
                fp=matrix_json_file,
            )


def write_navigator_layer_jsons(navigator_layer_dict, output_filepath):
    """Writes JSON navigator layer files to specified filepath

    Args:
        attack_data_dict: dictionary with attack data
        output_filepath: filepath to write JSON files to
    """
    for attack_domain, attack_version_dict in navigator_layer_dict.items():
        for attack_version, layer_dict in attack_version_dict.items():
            techniques_dict = get_techniques_dict(layer_dict)
            layer = create_layer(
                techniques_dict,
                f"{attack_domain}-{attack_version}",
                attack_domain,
                attack_version,
            )
            filepath = output_filepath / attack_domain / attack_version
            navigator_layer_filepath = (
                filepath / f"{attack_domain}-{attack_version}_navigator_layer.json"
            )

            navigatory_layer_json_file = open(
                navigator_layer_filepath,
                "w",
                encoding="UTF-8",
            )
            json.dump(
                layer,
                fp=navigatory_layer_json_file,
            )


def create_attack_jsons(attack_domains, output_filepath, mappings_filepath):
    """Creates json files with attack objects and data needed for creating the attack
    matrix

    Outputs a json files needed for the matrix
        The first json is a file with attack objects mapped to the following:
            id: id of the attack object,
            name: name of the attack object,
            type: type of the attack object, can be tactic, technique, or subtechnique
            tactics: if the attack object is a technique, its tactic parent/parents)
            technique: if the attack object is a subtechnique, its parent technique
            short_name: attack object short name,
            capabilities_mapped: list of capabilities mapped to the attack object,
            background_color: color that the matrix technique/subtechnique box should
            be, based on the amount of capabilities mapped
        The second json file is a navigator layer of the matrix
    Args:
        attack_domains: a dictionary of attack domains (ICS, Mobile, and Enterprise)
        mapped to the attack versions that contain techniques and subtechniques for
        that domain
        output_filepath: the path to output the json files
        mappings_filepath: filepath to mappings files, which are used to give the
        techniques/subtechniques coverage data

    """
    attack_data_dict = build_attack_data_dict(attack_domains)
    navigator_layer_dict = {}
    for mappings_file in mappings_filepath.rglob("**/*.json"):
        if (
            mappings_file.parent.name != "attack"
            and "stix" not in mappings_file.name
            and "navigator_layer" not in mappings_file.name
        ):
            mappings = json.loads(mappings_file.read_text(encoding="UTF-8"))
            add_mappings_to_navigator_layer_dict(mappings, navigator_layer_dict)
            add_mappings_to_attack_data_dict(mappings, attack_data_dict)

    write_matrix_jsons(attack_data_dict, output_filepath)
    write_navigator_layer_jsons(navigator_layer_dict, output_filepath)


def add_background_colors(attack_version_data):
    """Adds a background_color field to techniques and subtechniques

    The background color is determined by the amount of capabilites the
    technqiue/subtechnique is mapped to. The technique/subtechnique with the largest
    amount of capabilities mapped will have an opacity of 1, and the rest of the
    technqiues/subtechniques will have lower opacities.

    Args:
        attack_version_data: the dictionary that the background field should be added to
    """
    mapping_framework_id_to_name = {
        "nist_800_53": "NIST 800-53",
        "veris": "VERIS",
        "aws": "AWS",
        "gcp": "GCP",
        "azure": "Azure",
        "m365": "M365",
        "intel-vpro": "Intel vPro",
        "kev": "Known Exploited Vulnerabilities",
    }
    max_score = 0
    min_score = 100000
    for attack_object in attack_version_data:
        score = 0
        mapped_capabilities = []
        mapping_frameworks = attack_version_data[attack_object]["mapping_frameworks"]
        for mapping_framework in mapping_frameworks:
            if len(list(mapping_frameworks[mapping_framework].keys())) > 1:
                mapping_framework_version = "rev5"
            else:
                mapping_framework_version = list(
                    mapping_frameworks[mapping_framework].keys()
                )[0]
            mapping_framework_name = mapping_framework_id_to_name[mapping_framework]
            amount_mapped_capabilities = mapping_frameworks[mapping_framework][
                mapping_framework_version
            ]
            if mapping_framework == "kev":
                score += 1
                mapped_capabilities.append(
                    f"{amount_mapped_capabilities} {mapping_framework_name}"
                )
            else:
                score += mapping_frameworks[mapping_framework][
                    mapping_framework_version
                ]
                mapped_capabilities.append(
                    f"{amount_mapped_capabilities} {mapping_framework_name}"
                )
        attack_version_data[attack_object]["score"] = score
        attack_version_data[attack_object]["mapped_capabilities"] = mapped_capabilities

        if score > max_score:
            max_score = score
        if score < min_score:
            min_score = score

    if max_score != 0:
        r = 255
        g = 138
        b = 54
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
    """Adds capabilites mapped to techniques/subtechniques

    A list of capability ids from nist-800-53, veris, and security stack mappings that
    are mapped to the specified technique/subtechnique is added to the
    capabilites_mapped field. CVE capabilites are included as well, but only count once
    toward each technique/subtechnique.

    Args:
        mappings: mappings that will be added to techniques/subtechniques
        attack_data_dict: dictionary to add the mappings to
    """
    attack_data_version = attack_data_dict[mappings["metadata"]["attack_version"]][
        mappings["metadata"]["technology_domain"]
    ]
    mapping_framework = mappings["metadata"]["mapping_framework"]
    mapping_framework_version = mappings["metadata"]["mapping_framework_version"]
    for mapping in mappings["mapping_objects"]:
        if mapping["capability_id"]:
            attack_object_id = mapping["attack_object_id"]
            if attack_data_version.get(attack_object_id):
                mapping_frameworks = attack_data_version[attack_object_id][
                    "mapping_frameworks"
                ]
                if mapping_framework in mapping_frameworks:
                    if (
                        mapping_framework_version
                        in mapping_frameworks[mapping_framework]
                    ):
                        mapping_frameworks[mapping_framework][
                            mapping_framework_version
                        ] += 1
                    else:
                        mapping_frameworks[mapping_framework][
                            mapping_framework_version
                        ] = 1
                else:
                    mapping_frameworks[mapping_framework] = {}
                    mapping_frameworks[mapping_framework][mapping_framework_version] = 1


def format_attack_data(attack_data, attack_domain):
    """Creates dictionary of attack objects -- techniques and subtechniques --
    and pertinent data about the attack objects

    Args:
        attack_data: the data fetched from STIX
        attack_domain: the domain that the data is from. Must be ICS, Mobile,
        or Enterprise. Case does not matter

    Returns:
        A dict mapping an attack object to the following fields:
            name: name of the attack object,
            type: whether the attack object is a technique, subtechnique, or tactic
            tactics: if the attack object is a technique, the tactics that it is
            included in,
            technique: if the attack object is a subtechnique, its parent technique id
            short_name: the short_name of the attack object
            capabilities_mapped: the capabilites that are mapped to the attack object,
            begins as an empty array
            background_color: the background color of the technique/subtechnique,
            determined by the amount of capabilities mapped, begins as an empty string
            id: id of the attack object,

    """
    attack_data_dict = {}
    for attack_object in attack_data["objects"]:
        # skip objects without IDs
        if not attack_object.get("external_references"):
            continue
        # skip deprecated and revoked objects
        if attack_object.get("revoked", False):
            continue
        if attack_object.get("x_mitre_deprecated", False):
            continue
        if attack_object.get("type") in ["x-mitre-tactic", "attack-pattern"]:
            external_references = attack_object.get("external_references")
            external_reference = external_references[0]
            attack_object_id = external_reference.get("external_id")
            attack_object_name = attack_object.get("name")
            attack_object_short_name = attack_object.get("x_mitre_shortname", "")
            attack_object_type = (
                "tactic"
                if attack_object.get("type") == "x-mitre-tactic"
                else (
                    "subtechnique"
                    if attack_object.get("x_mitre_is_subtechnique")
                    else "technique"
                )
            )
            attack_object_parents = []
            source_name = (
                "mitre-attack"
                if attack_domain == "enterprise"
                else f"mitre-{attack_domain}-attack"
            )
            if attack_object_type == "technique":
                kill_chain_phases = attack_object.get("kill_chain_phases", [])
                for phase in kill_chain_phases:
                    if phase.get("kill_chain_name") == source_name:
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
                "background_color": "",
                "id": attack_object_id,
                "mapping_frameworks": {},
            }

    return attack_data_dict


def load_tactic_structure(attack_version, attack_domain):
    """Creates dictionary of attack objects -- techniques and subtechniques --
    and pertinent data about the attack objects

    Args:
        attack_data: the data fetched from STIX
        attack_domain: the domain that the data is from. Must be ICS, Mobile,
        or Enterprise. Case does not matter

    Returns:
        A dict mapping an attack object to the following fields:
            name: name of the attack object,
            type: whether the attack object is a technique, subtechnique, or tactic
            tactics: if the attack object is a technique, the tactics that it is
            included in,
            technique: if the attack object is a subtechnique, its parent technique id
            short_name: the short_name of the attack object
            capabilities_mapped: the capabilites that are mapped to the attack object,
            begins as an empty array
            id: id of the attack object,
    """
    attack_data_dict = {}
    attack_data = load_attack_json(attack_version, attack_domain.lower())
    if attack_data:
        formatted_attack_data = format_attack_data(attack_data, attack_domain.lower())
        if attack_version not in attack_data_dict:
            attack_data_dict[attack_version] = {}
        attack_data_dict[attack_version][attack_domain.lower()] = formatted_attack_data
    return attack_data_dict[attack_version][attack_domain.lower()]
