import argparse
import json
import os
import shutil
import zipfile
from urllib.parse import quote

from loguru import logger
from lunr import lunr

from .attack_query import create_attack_jsons, get_attack_data, load_tactic_structure
from .attack_setup import Tactic, Technique, all_attack_versions, attack_domains
from .framework_setup import (
    Capability,
    CapabilityGroup,
    ExternalControl,
    delete_all_descriptions,
    get_description_for_capability,
    get_description_for_capability_group,
    get_security_stack_descriptions,
    load_projects,
)
from .template import (
    PUBLIC_DIR,
    ROOT_DIR,
    TEMPLATE_DIR,
    load_template,
)


def is_attack_project(project: ExternalControl) -> bool:
    return project.target_id == "attack"


def get_mapping_file_path(
    project: ExternalControl,
    project_version: str,
    target_version: str,
    target_domain: str,
):
    project_id = "nist_800_53" if project.id == "nist" else project.id
    target_prefix = f"{project.target_id}-{target_version}"
    framework_version = project_version.replace("/", ".")
    filename = (
        f"{project_id}-{framework_version}_"
        f"{project.target_id}-{target_version}-"
        f"{target_domain.lower()}.json"
    )
    return (
        PUBLIC_DIR
        / "data"
        / project_id
        / target_prefix
        / f"{project_id}-{framework_version}"
        / target_domain.lower()
        / filename
    )


def get_external_base_url(
    project: ExternalControl,
    url_prefix: str,
    project_version: str,
    target_version: str,
    target_domain: str,
) -> str:
    return (
        f"{url_prefix}external/{project.id}/"
        f"{project.target_id}-{target_version}/"
        f"domain-{target_domain.lower()}/"
        f"{project.id}-{project_version.replace('/', '.')}/"
    )


def replace_mapping_type(mapping: dict, type_list: dict):
    """Replace the mapping_type value with the more descriptive name found in mappings
    file metadata

    Args:
        mapping: individual mapping object to replace mapping_type value on
        type_list: table of mapping_type values to lookup and replace
    """
    if (
        mapping.get("mapping_type") == "non_mappable"
        or mapping.get("status") == "non_mappable"
    ):
        return "non_mappable"

    mapping_type = mapping.get("mapping_type")
    if mapping_type in type_list:
        return type_list[mapping_type]["name"]

    return mapping_type


def normalize_mapping_object(project: ExternalControl, mapping: dict, metadata: dict):
    normalized = dict(mapping)

    normalized["capability_id"] = (
        mapping.get("capability_id")
        or mapping.get("source_capability_id")
    )
    normalized["capability_description"] = (
        mapping.get("capability_description")
        or mapping.get("source_capability_description")
    )
    normalized["capability_group"] = (
        mapping.get("capability_group")
        or mapping.get("source_capability_group")
    )

    normalized["target_object_id"] = (
        mapping.get("target_object_id")
        or mapping.get(project.mapping_object_id_field)
        or mapping.get("attack_object_id")
        or mapping.get("target_id")
    )
    normalized["target_object_name"] = (
        mapping.get("target_object_name")
        or mapping.get(project.mapping_object_name_field)
        or mapping.get("attack_object_name")
        or mapping.get("target_capability_description")
    )

    normalized["mapping_type"] = replace_mapping_type(
        mapping, metadata.get("mapping_types", {})
    )
    normalized["framework"] = project.id

    if is_attack_project(project):
        normalized["attack_object_id"] = normalized["target_object_id"]
        normalized["attack_object_name"] = normalized["target_object_name"]

    return normalized


def parse_capability_groups(
    project: ExternalControl,
    target_version: str,
    project_version: str,
    target_domain: str,
):
    """Load mappings data from files, then find and create capability group objects
    and capability objects for the objects in the mapping files

    Args:
        project: the mapping framework to parse mappings for
        target_version: version of the target framework to parse mappings for
        project_version: version of project to parse mappings for
        target_domain: domain of target framework to parse mappings for
    """
    full_path = get_mapping_file_path(
        project=project,
        project_version=project_version,
        target_version=target_version,
        target_domain=target_domain,
    )
    with open(full_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    metadata = data["metadata"]
    project.capability_groups = []

    mappings = [
        normalize_mapping_object(project, mapping, metadata)
        for mapping in data["mapping_objects"]
    ]

    if metadata.get("capability_groups"):
        for i in metadata["capability_groups"]:
            g = CapabilityGroup()
            g.id = i
            g.label = metadata["capability_groups"][i]
            g.capabilities = []
            project.capability_groups.append(g)
            filtered_mappings = [
                m
                for m in mappings
                if (m.get("capability_group") == g.id and m["status"] != "non_mappable")
            ]
            g.num_mappings = len(filtered_mappings)
            g.mappings = filtered_mappings
            logger.trace(
                "     found {count} mappings in group {g_label}",
                count=len(filtered_mappings),
                g_label=g.label,
            )

    parse_capabilities(
        mappings=mappings,
        project=project,
        project_version=project_version,
        target_version=target_version,
        target_domain=target_domain,
    )

    mapping_bundle = {
        "target_version": target_version,
        "project_version": project_version,
        "target_domain": target_domain,
        "mappings": [m for m in mappings if m["status"] != "non_mappable"],
    }

    if is_attack_project(project):
        mapping_bundle["attack_version"] = target_version
        mapping_bundle["attack_domain"] = target_domain

    project.mappings.append(mapping_bundle)

    if (
        project.id == "nist"
        or project.id == "kev"
        or project.id == "intel-vpro"
        or project.id == "gcp"
        or project.id == "azure"
        or project.id == "cri_profile"
        or project.id == "csa_ccm"
    ):
        if not project.has_non_mappable_comments:
            capabilities_to_get_description = project.capabilities
        else:
            capabilities_to_get_description = (
                project.capabilities + project.non_mappables
            )
        for capability in capabilities_to_get_description:
            get_description_for_capability(
                capability=capability,
                project=project,
                version=project_version,
            )
        for group in project.capability_groups:
            get_description_for_capability_group(
                group=group,
                project=project,
                version=project_version,
            )

    if project.id == "aws" or project.id == "m365":
        get_security_stack_descriptions(project=project)


def parse_capabilities(
    mappings: list,
    project: ExternalControl,
    project_version: str,
    target_version: str,
    target_domain: str,
):
    """Create capability objects for each unique capability id found in list of mappings

    Args:
        mappings: list of mappings to build capability list from
        project: project associated with list of mappings
        project_version: version of project associated with list of mappings
        target_version: version of target framework associated with list of mappings
        target_domain: domain of target framework associated with list of mappings

    Returns:
        List of capability objects
    """
    all_ids = [m["capability_id"] for m in mappings if m.get("capability_id")]
    capability_ids = list(set(all_ids))
    capabilities = []
    non_mappables = []

    for id in capability_ids:
        c = Capability()
        c.id = id

        capability_mappable_mappings = [
            m
            for m in mappings
            if (m["capability_id"] == id) and m["status"] != "non_mappable"
        ]
        capability_non_mappables = [
            m
            for m in mappings
            if (m["capability_id"] == id) and m["status"] == "non_mappable"
        ]
        capability_not_mappable = (
            len(capability_mappable_mappings) == 0 and len(capability_non_mappables) > 0
        )

        c.num_mappings = len(capability_mappable_mappings)
        c.mappings = capability_mappable_mappings

        if not capability_not_mappable:
            c.label = capability_mappable_mappings[0]["capability_description"]
            for mapping in capability_mappable_mappings:
                mapping["project"] = project.id
                mapping["project_version"] = project_version
                mapping["target_version"] = target_version
                mapping["target_domain"] = target_domain
                if is_attack_project(project):
                    mapping["attack_version"] = target_version
                    mapping["attack_domain"] = target_domain

            if capability_mappable_mappings[0].get("capability_group"):
                capability_group = [
                    g
                    for g in project.capability_groups
                    if g.id == capability_mappable_mappings[0]["capability_group"]
                ]
                if capability_group:
                    capability_group[0].capabilities.append(c)
                    capability_group[0].num_capabilities += 1
                    c.capability_group = capability_group[0]

            logger.trace(
                "for capability {id} the number of mappings is {count}",
                id=c.id,
                count=str(len(c.mappings)),
            )
            capabilities.append(c)
        else:
            c.label = capability_non_mappables[0]["capability_description"]
            if capability_non_mappables[0].get("capability_group"):
                capability_group = [
                    g
                    for g in project.capability_groups
                    if g.id == capability_non_mappables[0]["capability_group"]
                ]
                if capability_group:
                    c.capability_group = capability_group[0]
            c.non_mappable_comment = capability_non_mappables[0].get("comments", None)
            non_mappables.append(c)

    project.non_mappables = non_mappables
    project.capabilities = capabilities


def build_external_landing(
    project: ExternalControl,
    url_prefix,
    project_version,
    target_version,
    domain_dir,
    mappings,
    target_domain,
    breadcrumbs,
):
    """Create landing page for each project and build pages for each capability group
    and capability for the specified project and version combination
    """
    output_path = domain_dir / "index.html"
    template = load_template("framework_landing.html.j2")

    external_prefix = get_external_base_url(
        project=project,
        url_prefix=url_prefix,
        project_version=project_version,
        target_version=target_version,
        target_domain=target_domain,
    )
    capability_group_prefix = f"{external_prefix}capability-groups/"

    attack_prefix = None
    if is_attack_project(project) and project.has_target_pages:
        attack_prefix = (
            f"{url_prefix}attack/attack-{target_version}/"
            f"domain-{target_domain.lower()}/techniques/"
        )

    def target_header(field, label):
        if attack_prefix:
            return (
                ":pfx_link:",
                field,
                label,
                field,
                attack_prefix,
            )
        return (":text:", field, label)

    standard_headers = [
        (
            ":pfx_link:",
            "capability_id",
            "Capability ID",
            "capability_id",
            external_prefix,
        ),
        (
            ":pfx_link:",
            "capability_description",
            "Capability Description",
            "capability_id",
            external_prefix,
        ),
        (":text:", "mapping_type", "Mapping Type"),
        target_header("target_object_id", project.target_object_id_label),
        target_header("target_object_name", project.target_object_name_label),
    ]
    info_box_headers = []

    if project.id == "kev":
        info_box_headers = [
            ("comments", "Comments"),
            ("references", "References"),
        ]

    if project.id in {"azure", "aws", "gcp", "m365"}:
        standard_headers = [
            (
                ":pfx_link:",
                "capability_id",
                "Capability ID",
                "capability_id",
                external_prefix,
            ),
            (
                ":pfx_link:",
                "capability_description",
                "Capability Description",
                "capability_id",
                external_prefix,
            ),
            (":text:", "score_category", "Category"),
            (":text:", "score_value", "Value"),
            target_header("target_object_id", project.target_object_id_label),
            target_header("target_object_name", project.target_object_name_label),
        ]
        info_box_headers = [
            ("comments", "Comments"),
            ("references", "References"),
        ]

    if project.id == "intel-vpro":
        standard_headers = [
            (
                ":pfx_link:",
                "capability_id",
                "Capability ID",
                "capability_id",
                external_prefix,
            ),
            (
                ":pfx_link:",
                "capability_description",
                "Capability Description",
                "capability_id",
                external_prefix,
            ),
            (":text:", "mapping_type", "Enables"),
            (":text:", "score_category", "Category"),
            (":text:", "score_value", "Value"),
            target_header("target_object_id", project.target_object_id_label),
            target_header("target_object_name", project.target_object_name_label),
        ]
        info_box_headers = [
            ("comments", "Comments"),
            ("references", "References"),
        ]

    if project.id == "cri_profile" or project.id == "csa_ccm":
        info_box_headers = [
            ("comments", "Comments"),
        ]

    additional_artifacts = []
    if project_version in project.additional_artifacts:
        project_artifacts = project.additional_artifacts[project_version]
        if target_version in project_artifacts:
            additional_artifacts = project_artifacts[target_version]

    capability_group_headers = [
        (":pfx_link:", "id", "ID", "id", capability_group_prefix),
        (":pfx_link:", "label", "Capability Group Name", "id", capability_group_prefix),
        (":text:", "num_mappings", "Number of Mappings"),
        (":text:", "num_capabilities", "Number of Capabilities"),
    ]
    non_mappable_headers = [
        (":text:", "id", "Capability ID"),
        (":text:", "label", "Capability Description"),
    ]

    if project.has_non_mappable_comments:
        non_mappable_headers = [
            (":pfx_link:", "id", "Capability ID", "id", external_prefix),
            (
                ":pfx_link:",
                "label",
                "Capability Description",
                "id",
                external_prefix,
            ),
        ]

    project_id = project.id
    if project_id == "nist":
        project_id = "nist_800_53"

    table_max_count = 550
    stream = template.stream(
        title=project.label + " Landing",
        url_prefix=url_prefix,
        control=project.label,
        description=project.description,
        project_version=project_version.replace("/", "."),
        project_id=project_id,
        versions=project.versions,
        target_version=target_version,
        targetVersions=project.targetVersions,
        target_domain=target_domain,
        domains=project.targetDomains,
        target_label=project.target_label,
        target_version_label=project.target_version_label,
        target_domain_label=project.target_domain_label,
        mappings=mappings,
        standard_headers=standard_headers,
        info_box_headers=info_box_headers,
        group_headers=capability_group_headers,
        capability_groups=[g for g in project.capability_groups if g.num_mappings > 0],
        valid_versions=project.validVersions,
        breadcrumbs=breadcrumbs,
        non_mappable_headers=non_mappable_headers,
        non_mappables=project.non_mappables,
        project=project,
        additional_artifacts=additional_artifacts,
        table_max_count=999_999,
        full_link="",
        full_size=0,
        attack_version=target_version,
        attack_domain=target_domain,
        attackDomains=project.attackDomains,
    )
    stream.dump(str(output_path))

    if len(mappings) > table_max_count:
        full_size = output_path.stat().st_size
        full_path = output_path.parent / "all-data.html"
        output_path.rename(full_path)

        stream = template.stream(
            title=project.label + " Landing",
            url_prefix=url_prefix,
            control=project.label,
            description=project.description,
            project_version=project_version.replace("/", "."),
            project_id=project_id,
            versions=project.versions,
            target_version=target_version,
            targetVersions=project.targetVersions,
            target_domain=target_domain,
            domains=project.targetDomains,
            target_label=project.target_label,
            target_version_label=project.target_version_label,
            target_domain_label=project.target_domain_label,
            mappings=mappings,
            standard_headers=standard_headers,
            info_box_headers=info_box_headers,
            group_headers=capability_group_headers,
            capability_groups=[
                g for g in project.capability_groups if g.num_mappings > 0
            ],
            valid_versions=project.validVersions,
            breadcrumbs=breadcrumbs,
            non_mappable_headers=non_mappable_headers,
            non_mappables=project.non_mappables,
            project=project,
            additional_artifacts=additional_artifacts,
            table_max_count=table_max_count,
            full_link="all-data.html",
            full_size=full_size,
            attack_version=target_version,
            attack_domain=target_domain,
            attackDomains=project.attackDomains,
        )
        stream.dump(str(output_path))

    logger.trace(
        "Created {project_id} landing: target version {target_version}, framework "
        "version {project_version}, target domain {target_domain}",
        project_id=project.id,
        target_version=target_version,
        project_version=project_version,
        target_domain=target_domain,
    )

    capability_group_headers = [
        (":pfx_link:", "id", "Capability ID", "id", external_prefix),
        (":pfx_link:", "label", "Capability Name", "id", external_prefix),
        (":text:", "num_mappings", "Number of Mappings"),
    ]
    capability_group_dir = domain_dir / "capability-groups"
    previous_link = external_prefix

    for capability_group in project.capability_groups:
        if capability_group.num_mappings > 0:
            nav = breadcrumbs + [
                (
                    f"{external_prefix}capability-groups/{capability_group.id}/",
                    f"{capability_group.label} Capability Group",
                )
            ]
            build_capability_group(
                project=project,
                capability_group=capability_group,
                url_prefix=url_prefix,
                parent_dir=capability_group_dir,
                project_version=project_version,
                target_version=target_version,
                standard_headers=standard_headers,
                info_box_headers=info_box_headers,
                target_domain=target_domain,
                breadcrumbs=nav,
                capability_group_headers=capability_group_headers,
                previous_link=previous_link,
            )

    for capability in project.capabilities:
        capability_nav = breadcrumbs + [
            (
                f"{external_prefix}{capability.id}/",
                f"{capability.label if capability.label else capability.id}",
            ),
        ]
        build_external_capability(
            project=project,
            url_prefix=url_prefix,
            parent_dir=domain_dir,
            project_version=project_version,
            target_version=target_version,
            standard_headers=standard_headers,
            info_box_headers=info_box_headers,
            capability=capability,
            target_domain=target_domain,
            breadcrumbs=capability_nav,
            previous_link=previous_link,
        )

    if project.has_non_mappable_comments:
        for non_mappable in project.non_mappables:
            capability_nav = breadcrumbs + [
                (
                    f"{external_prefix}{non_mappable.id}/",
                    f"{non_mappable.label if non_mappable.label else non_mappable.id}",
                ),
            ]
            build_external_capability(
                project=project,
                url_prefix=url_prefix,
                parent_dir=domain_dir,
                project_version=project_version,
                target_version=target_version,
                standard_headers=standard_headers,
                info_box_headers=info_box_headers,
                capability=non_mappable,
                target_domain=target_domain,
                breadcrumbs=capability_nav,
                previous_link=previous_link,
            )


def build_external_pages(projects: list, url_prefix: str, breadcrumbs: list):
    """Parse framework mappings and build all external pages"""
    logger.info("Parsing and building external pages...")
    for project in projects:
        external_dir = PUBLIC_DIR / "external"
        external_dir.mkdir(parents=True, exist_ok=True)
        dir = external_dir / project.id
        dir.mkdir(parents=True, exist_ok=True)
        logger.info("Parsing project " + project.id)

        for index, valid_combo in enumerate(project.validVersions):
            logger.debug(f"Creating pages for version combo: {valid_combo}")
            target_version = valid_combo[1]
            project_version = valid_combo[0]
            target_domain = valid_combo[2]
            a = f"{project.target_id}-{target_version}"
            d = f"domain-{target_domain.lower()}"
            p = f"{project.id}-{project_version.replace('/', '.')}"
            domain_dir = dir / a / d / p
            domain_dir.mkdir(parents=True, exist_ok=True)

            parse_capability_groups(
                project=project,
                target_version=target_version,
                project_version=project_version,
                target_domain=target_domain,
            )
            m = [
                m
                for m in project.mappings
                if m["target_version"] == target_version
                and m["project_version"] == project_version
                and m["target_domain"] == target_domain
            ][0]
            mappings = m["mappings"]
            logger.trace("project parsed successfully")
            nav = breadcrumbs + [
                (f"{url_prefix}external/{project.id}/", f"{project.label} Home")
            ]

            build_external_landing(
                project=project,
                url_prefix=url_prefix,
                target_version=target_version,
                project_version=project_version,
                domain_dir=domain_dir,
                mappings=mappings,
                target_domain=target_domain,
                breadcrumbs=nav,
            )
            logger.debug(f"Built all pages for version combo: {valid_combo}")

            if index == len(project.validVersions) - 1:
                logger.debug(
                    "Copying the most recent version pair into main directory {}",
                    str(valid_combo),
                )
                shutil.copytree(domain_dir, dir, dirs_exist_ok=True)


def build_capability_group(
    project: ExternalControl,
    capability_group,
    url_prefix,
    parent_dir,
    project_version,
    target_version,
    standard_headers,
    info_box_headers,
    target_domain,
    breadcrumbs,
    capability_group_headers,
    previous_link,
):
    capability_group_id = capability_group.id
    dir = parent_dir / capability_group_id
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    template = load_template("capability_group.html.j2")
    prev_page = parent_dir
    stream = template.stream(
        title=f"{project.label} {capability_group.label}",
        url_prefix=url_prefix,
        control=project.label,
        capability_group_id=capability_group.id,
        capability_group_name=capability_group.label,
        capability_group=capability_group,
        project=project,
        description=capability_group.description,
        control_version=project_version,
        versions=project.versions,
        target_version=target_version,
        targetVersions=project.targetVersions,
        target_domain=target_domain,
        domains=project.targetDomains,
        target_label=project.target_label,
        target_version_label=project.target_version_label,
        target_domain_label=project.target_domain_label,
        prev_page=prev_page,
        mappings=capability_group.mappings,
        standard_headers=standard_headers,
        info_box_headers=info_box_headers,
        breadcrumbs=breadcrumbs,
        capability_group_headers=capability_group_headers,
        previous_link=previous_link,
        table_max_count=999_999,
        full_link="",
        full_size=0,
        attack_version=target_version,
        attack_domain=target_domain,
        attackDomains=project.attackDomains,
    )
    stream.dump(str(output_path))
    logger.trace(
        "          Created capability group page {group}", group=capability_group.label
    )


def build_external_capability(
    project: ExternalControl,
    url_prefix: str,
    parent_dir: os.path,
    project_version: str,
    target_version: str,
    standard_headers: list,
    info_box_headers: list,
    capability: Capability,
    target_domain: str,
    breadcrumbs: list,
    previous_link: str,
):
    """Builds a capability page for a given capability"""
    dir = parent_dir / capability.id.replace(" ", "_")
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    template = load_template("capability.html.j2")
    prev_page = parent_dir
    stream = template.stream(
        title=f"{project.label} {capability.id}",
        url_prefix=url_prefix,
        control=project.label,
        project=project,
        project_id=project.id,
        description=capability.description,
        control_version=project_version,
        versions=project.versions,
        target_version=target_version,
        targetVersions=project.targetVersions,
        target_domain=target_domain,
        domains=project.targetDomains,
        target_label=project.target_label,
        target_version_label=project.target_version_label,
        target_domain_label=project.target_domain_label,
        prev_page=prev_page,
        mappings=capability.mappings,
        standard_headers=standard_headers,
        info_box_headers=info_box_headers,
        capability=capability,
        breadcrumbs=breadcrumbs,
        previous_link=previous_link,
        table_max_count=999_999,
        full_link="",
        full_size=0,
        attack_version=target_version,
        attack_domain=target_domain,
        attackDomains=project.attackDomains,
    )
    stream.dump(str(output_path))
    logger.trace("          Created capability page {id}", id=capability.id)


def parse_techniques(
    attack_version: str, attack_domain: str, attack_data: dict, projects: list
):
    """Create a list of technique objects for all ATT&CK techniques that have mappings
    in a given version of ATT&CK
    """
    techniques = []
    for project in projects:
        mappings = []
        logger.trace("adding mappings in project {id}", id=project.id)
        m = [
            m
            for m in project.mappings
            if float(m["attack_version"]) == float(attack_version)
            and m["attack_domain"] == attack_domain
        ]
        if len(m) > 0:
            m = m[len(m) - 1]
            mappings = m["mappings"]
            all_ids = [m["attack_object_id"] for m in mappings if m.get("attack_object_id")]
            attack_ids = list(set(all_ids))
            for id in attack_ids:
                if id in [t.id for t in techniques]:
                    technique = [t for t in techniques if t.id == id][0]
                    additional_mappings = [
                        m for m in mappings if (m["attack_object_id"] == id)
                    ]
                    technique.mappings = technique.mappings + additional_mappings
                    technique.num_mappings = len(technique.mappings)

                else:
                    t = Technique()
                    t.id = id
                    dict_item = [t for t in attack_data if t.get("id") == id]
                    if len(dict_item) > 0:
                        t.label = dict_item[0].get("name")
                        t.description = dict_item[0].get("description")
                    t.subtechniques = []
                    t.mappings = [m for m in mappings if (m["attack_object_id"] == id)]
                    t.num_mappings = len(t.mappings)
                    techniques.append(t)
    return techniques


def parse_unmapped_techniques(attack_data: dict, techniques: list):
    """Create a list of unmapped ATT&CK techniques"""
    unmapped = []
    for technique in attack_data:
        if technique["id"] not in [t.id for t in techniques]:
            if technique.get("id")[:2] != "TA":
                t = Technique()
                t.id = technique["id"]
                t.label = technique["name"]
                t.description = technique["description"]
                unmapped.append(t)
    return unmapped


def parse_tactics(
    attack_version: str,
    attack_domain: str,
    attack_data: dict,
    projects: list,
    techniques: list,
):
    """Create a list of tactic objects for all ATT&CK tactics in one version of ATT&CK"""
    tactic_dict = load_tactic_structure(
        attack_version=attack_version,
        attack_domain=attack_domain,
    )
    tactic_list = []
    tactics = [t for t in attack_data if t.get("id")[:2] == "TA"]
    for tactic in tactics:
        ta = Tactic()
        ta.id = tactic.get("id")
        ta.description = tactic.get("description")
        ta.label = tactic.get("name")
        ta.techniques = []
        tactic_list.append(ta)
    for item in tactic_dict:
        if tactic_dict[item].get("tactics"):
            ta = [
                ta
                for ta in tactic_list
                if ta.label.lower().replace(" ", "-")
                in tactic_dict[item].get("tactics")
            ]
            for tactic in ta:
                technique = [t for t in techniques if t.id == item]
                if technique:
                    tactic.techniques.append(technique[0])
                    tactic.num_techniques = len(tactic.techniques)
        if tactic_dict[item].get("type") == "subtechnique":
            technique_id = tactic_dict[item].get("technique")
            supertechnique = [t for t in techniques if t.id == technique_id]
            technique = [t for t in techniques if t.id == item]
            if supertechnique and technique:
                supertechnique[0].subtechniques.append(technique[0])
                supertechnique[0].num_subtechniques += 1

    return tactic_list


def build_attack_pages(projects: list, url_prefix: str, breadcrumbs: list):
    """Parse ATT&CK data and build all ATT&CK object pages"""
    attack_projects = [p for p in projects if is_attack_project(p)]

    for attack_domain in list(attack_domains.keys()):
        all_techniques = []
        all_tactics = []
        unmapped = []
        for attack_version in attack_domains[attack_domain]:
            logger.info(
                f"Creating pages for ATT&CK {attack_version} {attack_domain}..."
            )
            attack_data = get_attack_data(attack_version, attack_domain)
            all_techniques = parse_techniques(
                attack_version=attack_version,
                attack_domain=attack_domain,
                attack_data=attack_data,
                projects=attack_projects,
            )
            all_tactics = parse_tactics(
                attack_version=attack_version,
                attack_domain=attack_domain,
                attack_data=attack_data,
                projects=attack_projects,
                techniques=all_techniques,
            )
            unmapped = parse_unmapped_techniques(
                attack_data=attack_data,
                techniques=all_techniques,
            )
            external_dir = (
                PUBLIC_DIR
                / "attack"
                / ("attack-" + attack_version)
                / ("domain-" + attack_domain.lower())
            )
            external_dir.mkdir(parents=True, exist_ok=True)
            build_technique_landing_page(
                url_prefix=url_prefix,
                parent_dir=external_dir,
                attack_version=attack_version,
                attack_domain=attack_domain,
                techniques=all_techniques,
                tactics=all_tactics,
                breadcrumbs=breadcrumbs,
                non_mappables=unmapped,
            )
            for technique in unmapped:
                external_dir = (
                    PUBLIC_DIR
                    / "attack"
                    / ("attack-" + attack_version)
                    / ("domain-" + attack_domain.lower())
                    / "techniques"
                )

                if technique.id:
                    build_technique_page(
                        url_prefix=url_prefix,
                        parent_dir=external_dir,
                        attack_version=attack_version,
                        attack_domain=attack_domain,
                        technique=technique,
                        breadcrumbs=breadcrumbs,
                        projects=attack_projects,
                    )

            for technique in all_techniques:
                external_dir = (
                    PUBLIC_DIR
                    / "attack"
                    / ("attack-" + attack_version)
                    / ("domain-" + attack_domain.lower())
                    / "techniques"
                )
                if technique.id:
                    build_technique_page(
                        url_prefix=url_prefix,
                        parent_dir=external_dir,
                        attack_version=attack_version,
                        attack_domain=attack_domain,
                        technique=technique,
                        breadcrumbs=breadcrumbs,
                        projects=attack_projects,
                    )
            logger.trace("built all technique pages")
            for tactic in all_tactics:
                external_dir = (
                    PUBLIC_DIR
                    / "attack"
                    / ("attack-" + attack_version)
                    / ("domain-" + attack_domain.lower())
                    / "tactics"
                )
                if tactic.id:
                    build_tactic_page(
                        url_prefix=url_prefix,
                        parent_dir=external_dir,
                        attack_version=attack_version,
                        attack_domain=attack_domain,
                        tactic=tactic,
                        breadcrumbs=breadcrumbs,
                    )
            logger.trace("built all tactic pages")
            logger.info(f"Built pages for ATT&CK {attack_version} {attack_domain}")

    logger.info("Done building all ATT&CK pages ")


def build_technique_page(
    url_prefix: str,
    parent_dir: os.path,
    attack_version: str,
    attack_domain: str,
    technique: Technique,
    breadcrumbs: list,
    projects: list,
):
    """Builds a technique page for a given technique"""
    attack_prefix = (
        f"{url_prefix}attack/attack-{attack_version}/"
        f"domain-{attack_domain.lower()}/techniques/"
    )
    technique_headers = [
        (":pfx_link:", "id", "Technique ID", "id", attack_prefix),
        (":pfx_link:", "label", "Technique Name", "id", attack_prefix),
        (":text:", "num_mappings", "Number of Mappings"),
    ]
    nav = breadcrumbs + [
        (f"{attack_prefix}", "ATT&CK Techniques"),
        (
            f"{attack_prefix}{technique.id}/",
            f"{technique.id} {technique.label}",
        ),
    ]
    standard_headers = [
        (":link:", "capability_id", "Capability ID", "capability_id"),
        (
            ":link:",
            "capability_description",
            "Capability Description",
            "capability_id",
        ),
        (":text:", "mapping_type", "Mapping Type"),
        (
            ":pfx_link:",
            "attack_object_id",
            "ATT&CK ID",
            "attack_object_id",
            attack_prefix,
        ),
        (
            ":pfx_link:",
            "attack_object_name",
            "ATT&CK Name",
            "attack_object_id",
            attack_prefix,
        ),
    ]
    info_box_headers = [
        ("comments", "Comments"),
        ("references", "References"),
    ]
    dir = parent_dir / technique.id
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    prev_page = parent_dir
    template = load_template("technique.html.j2")
    split_mappings = []
    for project in projects:
        cutup = [m for m in technique.mappings if m.get("framework") == project.id]
        split_mappings.append(
            {"id": project.id, "label": project.label, "mappings": cutup}
        )
    stream = template.stream(
        title=f"ATT&CK Technique {technique.id}",
        url_prefix=url_prefix,
        attack_version=attack_version,
        attack_domain=attack_domain,
        standard_headers=standard_headers,
        info_box_headers=info_box_headers,
        technique_headers=technique_headers,
        technique=technique,
        prev_page=prev_page,
        mappings=technique.mappings,
        split_mappings=split_mappings,
        subtechniques=technique.subtechniques,
        breadcrumbs=nav,
        previous_link=attack_prefix,
        table_max_count=999_999,
        full_link="",
        full_size=0,
    )
    stream.dump(str(output_path))
    logger.trace("          Created technique page {id}", id=technique.id)


def build_tactic_page(
    url_prefix: str,
    parent_dir: os.path,
    attack_version: str,
    attack_domain: str,
    tactic: Tactic,
    breadcrumbs: list,
):
    """Builds a tactic page for a given tactic"""
    attack_prefix = (
        f"{url_prefix}attack/attack-{attack_version}/domain-{attack_domain.lower()}/"
    )
    previous_link = attack_prefix + "tactics/"
    nav = breadcrumbs + [
        (f"{attack_prefix}tactics/", "ATT&CK Tactics"),
        (f"{attack_prefix}tactics/{tactic.id}/", f"{tactic.id} {tactic.label}"),
    ]
    attack_prefix += "techniques/"

    standard_headers = [
        (":pfx_link:", "id", "Technique ID", "id", attack_prefix),
        (":pfx_link:", "label", "Technique Name", "id", attack_prefix),
        (":text:", "num_mappings", "Number of Mappings"),
        (":text:", "num_subtechniques", "Number of Subtechniques"),
    ]

    dir = parent_dir / tactic.id
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    prev_page = parent_dir
    template = load_template("tactic.html.j2")
    stream = template.stream(
        title=f"ATT&CK Tactic {tactic.id}",
        url_prefix=url_prefix,
        attack_version=attack_version,
        attack_domain=attack_domain,
        standard_headers=standard_headers,
        mappings=tactic.techniques,
        tactic=tactic,
        prev_page=prev_page,
        breadcrumbs=nav,
        previous_link=previous_link,
        table_max_count=999_999,
        full_link="",
        full_size=0,
    )
    stream.dump(str(output_path))
    logger.trace("          Created tactic page {id}", id=tactic.id)


def build_technique_landing_page(
    url_prefix,
    parent_dir,
    attack_version,
    attack_domain,
    techniques,
    tactics,
    breadcrumbs,
    non_mappables,
):
    """Builds default pages that list all tactics and techniques"""
    attack_prefix = (
        f"{url_prefix}attack/attack-{attack_version}/"
        f"domain-{attack_domain.lower()}/techniques/"
    )
    standard_headers = [
        (":pfx_link:", "id", "ATT&CK ID", "id", attack_prefix),
        (":pfx_link:", "label", "ATT&CK Name", "id", attack_prefix),
        (":text:", "num_mappings", "Number of Mappings"),
        (":text:", "num_subtechniques", "Number of Subtechniques"),
    ]
    non_mappable_headers = [
        (":text:", "id", "ATT&CK ID"),
        (":text:", "label", "ATT&CK Name"),
    ]
    description = """Techniques represent 'how' an adversary achieves a tactical goal by
      performing an action. For example, an adversary may dump credentials to achieve
      credential access.
    """
    valid_versions = []
    for d in attack_domains.keys():
        for version in attack_domains[d]:
            valid_versions.append((d, version))
    technique_nav = breadcrumbs + [
        (f"{attack_prefix}techniques/", "ATT&CK Techniques"),
    ]
    dir = parent_dir / "techniques"
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    prev_page = parent_dir
    template = load_template("attack_landing.html.j2")
    stream = template.stream(
        title="ATT&CK Techniques",
        description=description,
        url_prefix=url_prefix,
        attack_version=attack_version,
        attack_domain=attack_domain,
        standard_headers=standard_headers,
        prev_page=prev_page,
        mappings=techniques,
        object_type="Techniques",
        targetVersions=all_attack_versions,
        domains=attack_domains,
        valid_versions=valid_versions,
        breadcrumbs=technique_nav,
        non_mappable_headers=non_mappable_headers,
        non_mappables=non_mappables,
        table_max_count=999_999,
        full_link="",
        full_size=0,
    )
    stream.dump(str(output_path))
    description = """Tactics represent the "why" of a MITRE ATT&CK® technique or
      sub-technique. It is the adversary's tactical goal: the reason for performing an
      action. For example, an adversary may want to achieve credential access.
    """
    attack_prefix = (
        f"{url_prefix}attack/attack-{attack_version}/"
        f"domain-{attack_domain.lower()}/tactics/"
    )
    standard_headers = [
        (":pfx_link:", "id", "ATT&CK ID", "id", attack_prefix),
        (":pfx_link:", "label", "ATT&CK Name", "id", attack_prefix),
        (":text:", "num_techniques", "Number of Techniques"),
    ]
    dir = parent_dir / "tactics"
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    prev_page = parent_dir
    template = load_template("attack_landing.html.j2")
    tactic_nav = breadcrumbs + [
        (f"{attack_prefix}tactics/", "ATT&CK Tactics"),
    ]

    stream = template.stream(
        title="ATT&CK Tactics",
        description=description,
        url_prefix=url_prefix,
        attack_version=attack_version,
        attack_domain=attack_domain,
        standard_headers=standard_headers,
        prev_page=prev_page,
        mappings=tactics,
        object_type="Tactics",
        targetVersions=all_attack_versions,
        domains=attack_domains,
        valid_versions=valid_versions,
        breadcrumbs=tactic_nav,
        table_max_count=999_999,
        full_link="",
        full_size=0,
    )
    stream.dump(str(output_path))
    logger.trace("Built techniques and tactics landing pages ")


def build_matrix(url_prefix, projects, breadcrumbs):
    projects = [p for p in projects if is_attack_project(p)]

    external_dir = PUBLIC_DIR / "attack" / "matrix"
    external_dir.mkdir(parents=True, exist_ok=True)
    output_path = external_dir / "index.html"
    logger.info("Building ATT&CK Matrix ")
    nav = breadcrumbs + [
        (f"{url_prefix}attack/matrix/", "ATT&CK Matrix"),
    ]

    all_attack_versions_local = [
        "8.2",
        "9.0",
        "10.0",
        "10.1",
        "11.0",
        "11.1",
        "11.2",
        "11.3",
        "12.0",
        "12.1",
        "13.0",
        "13.1",
        "14.0",
        "14.1",
        "15.0",
        "15.1",
        "16.1",
        "17.1",
    ]

    attack_domain_versions_with_mappings = {}
    for project in projects:
        for valid_version in project.validVersions:
            if valid_version[2] not in attack_domain_versions_with_mappings:
                attack_domain_versions_with_mappings[valid_version[2]] = [
                    valid_version[1]
                ]
            elif (
                valid_version[1]
                not in attack_domain_versions_with_mappings[valid_version[2]]
            ):
                attack_domain_versions_with_mappings[valid_version[2]].append(
                    valid_version[1]
                )

    attack_domains_local = {
        "Enterprise": [
            "8.2",
            "9.0",
            "10.0",
            "10.1",
            "11.0",
            "11.1",
            "11.2",
            "11.3",
            "12.0",
            "12.1",
            "13.0",
            "13.1",
            "14.0",
            "14.1",
            "15.0",
            "15.1",
            "16.0",
            "16.1",
            "17.1",
        ],
        "ICS": [
            "8.2",
            "9.0",
            "10.0",
            "10.1",
            "11.0",
            "11.1",
            "11.2",
            "11.3",
            "12.0",
            "12.1",
            "13.0",
            "13.1",
            "14.0",
            "14.1",
            "15.0",
            "15.1",
            "16.0",
            "16.1",
            "17.1",
        ],
        "Mobile": [
            "8.2",
            "9.0",
            "10.0",
            "10.1",
            "11.3",
            "12.0",
            "12.1",
            "13.0",
            "13.1",
            "14.0",
            "14.1",
            "15.0",
            "15.1",
            "16.0",
            "16.1",
            "17.1",
        ],
    }
    matrix_order = {
        "enterprise": [
            "TA0043",
            "TA0042",
            "TA0001",
            "TA0002",
            "TA0003",
            "TA0004",
            "TA0005",
            "TA0006",
            "TA0007",
            "TA0008",
            "TA0009",
            "TA0011",
            "TA0010",
            "TA0040",
        ],
        "ics": [
            "TA0108",
            "TA0104",
            "TA0110",
            "TA0111",
            "TA0103",
            "TA0102",
            "TA0109",
            "TA0100",
            "TA0101",
            "TA0107",
            "TA0106",
            "TA0105",
        ],
        "mobile": [
            "TA0027",
            "TA0041",
            "TA0028",
            "TA0029",
            "TA0030",
            "TA0031",
            "TA0032",
            "TA0033",
            "TA0035",
            "TA0037",
            "TA0036",
            "TA0034",
            "TA0038",
            "TA0039",
        ],
    }

    json_matrices_dir = TEMPLATE_DIR / PUBLIC_DIR / "static" / "matrices"
    mappings_filepath = PUBLIC_DIR / "data"
    create_attack_jsons(attack_domains_local, json_matrices_dir, mappings_filepath)

    template = load_template("matrix.html.j2")
    stream = template.stream(
        title="ATT&CK Matrix",
        matrix_order=matrix_order,
        all_attack_versions=all_attack_versions_local,
        url_prefix=url_prefix,
        attack_domains=attack_domains_local,
        attack_domain_versions_with_mappings=attack_domain_versions_with_mappings,
        breadcrumbs=nav,
    )
    stream.dump(str(output_path))
    logger.info("Done building ATT&CK matrix")


def getIndexPages():
    """
    Create an array of page dictionaries for search index

    Returns:
        an array of dictionaries with the search index's url, id, and name
    """
    mappings_filepath = PUBLIC_DIR / "data"
    pages = []

    for mappings_file in mappings_filepath.rglob("**/*.json"):
        if "stix" in mappings_file.name or "navigator_layer" in mappings_file.name:
            continue

        try:
            mappings = json.loads(mappings_file.read_text(encoding="UTF-8"))
        except Exception:
            continue

        metadata = mappings.get("metadata", {})
        mapping_framework = metadata.get("mapping_framework")
        if not mapping_framework:
            continue

        framework_version = metadata.get("mapping_framework_version", "").replace("/", ".")
        target_version = metadata.get("target_version") or metadata.get("attack_version")
        target_id = metadata.get("target_id") or (
            "attack" if metadata.get("attack_version") else "ocsf"
        )
        domain = metadata.get("technology_domain", "").lower()

        for raw_mapping in mappings.get("mapping_objects", []):
            capability_id = (
                raw_mapping.get("capability_id")
                or raw_mapping.get("source_capability_id")
            )
            capability_name = (
                raw_mapping.get("capability_description")
                or raw_mapping.get("source_capability_description")
            )

            if capability_id:
                capability_url = (
                    f"external/{mapping_framework}/"
                    f"{target_id}-{target_version}/"
                    f"domain-{domain}/"
                    f"{mapping_framework}-{framework_version}/"
                    f"{quote(capability_id.replace(' ', '_'))}"
                )
                if not any(page["url"] == capability_url for page in pages):
                    pages.append(
                        {
                            "url": capability_url,
                            "id": capability_id,
                            "name": capability_name or capability_id,
                        }
                    )

            if target_id == "attack":
                attack_object_id = raw_mapping.get("attack_object_id")
                attack_object_name = raw_mapping.get("attack_object_name")
                if attack_object_id:
                    attack_url = (
                        f"attack/attack-{target_version}/"
                        f"domain-{domain}/"
                        f"techniques/{attack_object_id}"
                    )
                    if not any(page["url"] == attack_url for page in pages):
                        pages.append(
                            {
                                "url": attack_url,
                                "id": attack_object_id,
                                "name": attack_object_name or attack_object_id,
                            }
                        )
    return pages


def build_search_index(url_prefix: str, breadcrumbs=list):
    """
    Render the search page and also build the search index as a JSON file.
    """
    logger.info("Creating search page")
    search_dir = PUBLIC_DIR / "search"
    search_dir.mkdir(parents=True, exist_ok=True)
    output_path = search_dir / "index.html"
    template = load_template("search.html.j2")

    nav = breadcrumbs + [(f"{url_prefix}search/", "Search")]
    logger.info("Creating search index")
    pages = getIndexPages()
    stream = template.stream(url_prefix=url_prefix, breadcrumbs=nav)
    stream.dump(str(output_path))

    index = lunr(
        ref="url",
        fields=[
            {"field_name": "id", "boost": 3},
            {"field_name": "name", "boost": 2},
        ],
        documents=pages,
    )
    pages = {p.pop("url"): p for p in pages}
    index_path = PUBLIC_DIR / "static" / "lunr-index.zip"
    lunr_index = {
        "pages": pages,
        "index": index.serialize(),
    }
    with zipfile.ZipFile(
        index_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as zip_file:
        dumped_JSON: str = json.dumps(lunr_index, ensure_ascii=False, indent=4)
        zip_file.writestr("lunr-index.json", data=dumped_JSON)
        zip_file.testzip()


def build_about_page(
    url_prefix: str,
    url_suffix: str,
    breadcrumbs: list,
    template_path: str,
    title: str,
) -> list:
    """
    Build one about page.
    """
    breadcrumbs = breadcrumbs + [(f"{url_prefix}{url_suffix}/", title)]
    output_dir = PUBLIC_DIR
    for url_part in url_suffix.split("/"):
        output_dir = output_dir / url_part
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "index.html"
    template = load_template(template_path)
    stream = template.stream(
        title=title,
        url_prefix=url_prefix,
        breadcrumbs=breadcrumbs,
    )
    stream.dump(str(output_path))
    logger.debug("Created {} page -> {}", url_suffix, output_path)
    return breadcrumbs


def build_about_pages(url_prefix: str, breadcrumbs: list):
    """
    Build the site's about pages.
    """
    about_breadcrumbs = build_about_page(
        url_prefix=url_prefix,
        url_suffix="about",
        breadcrumbs=breadcrumbs,
        template_path="about.html.j2",
        title="About",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/use-cases",
        breadcrumbs=about_breadcrumbs,
        template_path="use_cases.html.j2",
        title="Use Cases",
    )

    methodology_breadcrumbs = build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/methodology",
        breadcrumbs=about_breadcrumbs,
        template_path="methodology.html.j2",
        title="Methodology",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/methodology/cve-methodology",
        breadcrumbs=methodology_breadcrumbs,
        template_path="methodology/cve_methodology.html.j2",
        title="CVE Mapping Methodology",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/methodology/nist-methodology",
        breadcrumbs=methodology_breadcrumbs,
        template_path="methodology/nist_methodology.html.j2",
        title="Control Framework Mapping Methodology",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/methodology/nist-scope",
        breadcrumbs=methodology_breadcrumbs,
        template_path="methodology/nist_scope.html.j2",
        title="NIST 800-53 Mapping Scope",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/methodology/cri-profile-scope",
        breadcrumbs=methodology_breadcrumbs,
        template_path="methodology/cri_profile_scope.html.j2",
        title="CRI Profile Mapping Scope",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/methodology/csa-ccm-scope",
        breadcrumbs=methodology_breadcrumbs,
        template_path="methodology/csa_ccm_scope.html.j2",
        title="CSA CCM Mapping Scope",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/methodology/ssm-methodology",
        breadcrumbs=methodology_breadcrumbs,
        template_path="methodology/ssm_methodology.html.j2",
        title="Security Stack Mapping Methodology",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/methodology/veris-methodology",
        breadcrumbs=methodology_breadcrumbs,
        template_path="methodology/veris_methodology.html.j2",
        title="VERIS Mapping Methodology",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/scoring",
        breadcrumbs=about_breadcrumbs,
        template_path="scoring_rubric.html.j2",
        title="Scoring",
    )

    build_about_page(
        url_prefix=url_prefix,
        url_suffix="about/related-projects",
        breadcrumbs=about_breadcrumbs,
        template_path="related_projects.html.j2",
        title="Related Projects",
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--url-prefix",
        default="http://[::]:8000/",
        help="A prefix to apply to generated (default: /public)",
    )
    parser.add_argument(
        "--reset-descriptions",
        action="store_true",
        default=False,
        help="Adds ability to refresh and load capability descriptions from API calls",
    )
    args = parser.parse_args()

    url_prefix = args.url_prefix
    reset_descriptions = args.reset_descriptions
    logger.info(f"url prefix: {url_prefix}")
    logger.info(f"Reset descriptions? {reset_descriptions}")
    projects = load_projects()

    static_dir = PUBLIC_DIR / "static"
    logger.info("Copying static resources:", static_dir)
    shutil.copytree(TEMPLATE_DIR / "static", static_dir, dirs_exist_ok=True)

    data_dir = PUBLIC_DIR / "data"
    logger.info("Copying parsed mappings to output directory:", data_dir)
    shutil.copytree(ROOT_DIR / "mappings", data_dir, dirs_exist_ok=True)

    legacy_dir = PUBLIC_DIR / "legacy"
    logger.info("Copying legacy data to output directory:", data_dir)
    shutil.copytree(ROOT_DIR / "legacy", legacy_dir, dirs_exist_ok=True)

    output_path = PUBLIC_DIR / "index.html"
    template = load_template("landing.html.j2")
    stream = template.stream(
        title="Home",
        url_prefix=url_prefix,
        public_dir=PUBLIC_DIR,
        projects=projects,
    )
    stream.dump(str(output_path))
    logger.info("Created site homepage")

    dir = PUBLIC_DIR / "external"
    dir.mkdir(parents=True, exist_ok=True)
    output_path = dir / "index.html"
    template = load_template("external_landing.html.j2")
    breadcrumbs = [
        (f"{url_prefix}", "Home"),
        (f"{url_prefix}external/", "Mapping Frameworks"),
    ]
    stream = template.stream(
        title="External Mappings Home",
        url_prefix=url_prefix,
        breadcrumbs=breadcrumbs,
        projects=projects,
    )
    stream.dump(str(output_path))
    logger.info("Created Mappings Frameworks landing page")

    if reset_descriptions:
        delete_all_descriptions(projects=projects)

    build_external_pages(
        projects=projects,
        url_prefix=url_prefix,
        breadcrumbs=breadcrumbs,
    )
    breadcrumbs = [
        (f"{url_prefix}", "Home"),
    ]
    build_about_pages(url_prefix=url_prefix, breadcrumbs=breadcrumbs)
    build_attack_pages(
        projects=projects, url_prefix=url_prefix, breadcrumbs=breadcrumbs
    )
    build_matrix(url_prefix=url_prefix, projects=projects, breadcrumbs=breadcrumbs)
    build_search_index(url_prefix, breadcrumbs)
    logger.info("Done building site")


if __name__ == "__main__":
    main()
