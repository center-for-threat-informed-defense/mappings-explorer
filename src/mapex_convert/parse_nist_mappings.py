import uuid

control_family_lookup_dict = {
    "AC": "Access Control",
    "AU": "Audit and Accountability",
    "AT": "Awareness and Training",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PS": "Personnel Security",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "RA": "Risk Assessment",
    "CA": "Security Assessment and Authorization",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SA": "System and Services Acquisition",
    "SR": "Supply Chain Risk Management",
}


def configure_nist_mappings(dataframe, attack_version, mapping_framework_version):
    # put data in correct format with correct fields
    mapping_framework_version = "rev" + mapping_framework_version[-1]
    mapping_types = {str(uuid.uuid4()): {"name": "mitigates", "description": ""}}
    parsed_mappings = {
        "metadata": {
            "mapping_version": "",
            "attack_version": attack_version,
            # this is an assumption that all cve mappings are enterprise
            # this assumption is not currently true
            # need to clarify how we will handle non-enterprise cve mappings
            "technology_domain": "enterprise",
            "author": "",
            "contact": "",
            # confirm creation-data value is correct
            "creation_date": "01/13/2022",
            # confirm last-update value is correct
            "last_update": "01/13/2022",
            "organization": "",
            "mapping_framework": "nist_800_53",
            "mapping_framework_version": mapping_framework_version,
            "mapping_types": mapping_types,
            "groups": {},
        },
        "mapping_objects": [],
    }

    groups = {}
    for _, row in dataframe.iterrows():
        # get mapping type uuid
        mapping_type_uuid = [
            mapping_type
            for mapping_type in mapping_types
            if mapping_types[mapping_type]["name"] == "mitigates"
        ][0]

        # get group id and name
        control_id = row["Control ID"]
        control_family_id = control_id[0 : control_id.index("-")]
        if control_family_id not in list(groups.keys()):
            groups[control_family_id] = (
                control_family_lookup_dict.get(control_family_id, ""),
            )

        parsed_mappings["mapping_objects"].append(
            {
                "comments": "",
                "attack_object_id": row["Technique ID"],
                "attack_object_name": row["Technique Name"],
                "references": [],
                "capability_description": row["Control Name"],
                "capability_id": row["Control ID"],
                "mapping_type": mapping_type_uuid,
                "group": control_family_id,
                "status": "complete",
            }
        )

    parsed_mappings["metadata"]["groups"] = groups
    return parsed_mappings
