"""
Parse Summiting the Pyramid (STP) spreadsheet mappings to ATT&CK techniques.

This module enriches the STP ``all-event-and-field-data-consolidated`` workbook
with ATT&CK technique IDs derived from data component relationships. The output
is intended as an intermediate artifact for eventual publication to
`Mappings Explorer <https://github.com/center-for-threat-informed-defense/mappings-explorer>`_.

ATT&CK v18+ no longer maps data components directly to techniques via STIX
``detects`` relationships. Instead, techniques are linked through:

    data component -> analytic -> detection strategy -> technique

Relationship resolution
-----------------------
* **Analytics** reference data components through ``x_mitre_log_source_references``.
* **Detection strategies** reference analytics through ``x_mitre_analytic_refs``.
* **Techniques** link to detection strategies via STIX ``detects`` relationships.

Input normalization
-------------------
STP spreadsheets often store Windows event descriptions in the data component
column instead of official ATT&CK data component names. When normalization is
enabled (the default), values are resolved using, in order:

1. Exact match against official ATT&CK data component names
2. ``Log Source`` + ``EventID`` lookups from ATT&CK analytics EventCode rules
3. Substring patterns for common Windows event descriptions

Usage
-----
Run as a module or script::

    python -m mapex_convert.parse_stp_mappings \\
        path/to/all-event-and-field-data-consolidated.xlsx \\
        --attack-analytics-xlsx path/to/enterprise-attack-analytics.xlsx \\
        --attack-relationships-xlsx path/to/enterprise-attack-relationships.xlsx
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pandas as pd
from mitreattack.stix20 import MitreAttackData

# Column names and indices used when reading/writing STP spreadsheets.
DATA_COMPONENT_COLUMN_INDEX = 2  # Column C (0-based) in the STP consolidated workbook.
TECHNIQUES_COLUMN_NAME = "ATT&CK Techniques"
TECHNIQUE_COLUMN_NAME = "ATT&CK Technique"
ANALYTIC_COLUMN_NAME = "ATT&CK Analytic"
DETECTION_STRATEGY_COLUMN_NAME = "ATT&CK Detection Strategy"
CHAIN_COLUMN_NAMES = (
    ANALYTIC_COLUMN_NAME,
    DETECTION_STRATEGY_COLUMN_NAME,
    TECHNIQUE_COLUMN_NAME,
)
NORMALIZED_DATA_COMPONENT_COLUMN_NAME = "ATT&CK Data Component (normalized)"
NORMALIZATION_METHOD_COLUMN_NAME = "Normalization method"
DEFENSIVE_MAPPINGS_SHEET = "defensive mappings"
RELATIONSHIPS_SHEET = "relationships"

# Map STP log source labels to ATT&CK analytics log source names.
LOG_SOURCE_ATTACK_ALIASES = {
    "winlog": "wineventlog:security",
    "sysmon": "wineventlog:sysmon",
}

SUPPLEMENTAL_EVENT_TO_DATACOMPONENT: dict[tuple[str, str], tuple[str, ...]] = {
    ("wineventlog:security", "4625"): ("User Account Authentication",),
    ("wineventlog:security", "4634"): ("Logon Session Metadata",),
    ("wineventlog:security", "4647"): ("User Account Authentication",),
    ("wineventlog:security", "4648"): ("User Account Authentication",),
    ("wineventlog:security", "4656"): ("File Access",),
    ("wineventlog:security", "4657"): ("Windows Registry Key Modification",),
    ("wineventlog:security", "4658"): ("File Access",),
    ("wineventlog:security", "4660"): ("File Deletion",),
    ("wineventlog:security", "4670"): ("File Modification",),
    ("wineventlog:security", "4672"): ("Logon Session Metadata",),
    ("wineventlog:security", "4673"): ("OS API Execution",),
    ("wineventlog:security", "4674"): ("OS API Execution",),
    ("wineventlog:security", "4689"): ("Process Termination",),
    ("wineventlog:security", "4698"): ("Scheduled Job Creation",),
    ("wineventlog:security", "4699"): ("Scheduled Job Modification",),
    ("wineventlog:security", "4700"): ("Scheduled Job Modification",),
    ("wineventlog:security", "4701"): ("Scheduled Job Modification",),
    ("wineventlog:security", "4719"): ("Application Log Content",),
    ("wineventlog:security", "4722"): ("User Account Modification",),
    ("wineventlog:security", "4724"): ("User Account Modification",),
    ("wineventlog:security", "4725"): ("User Account Modification",),
    ("wineventlog:security", "4728"): ("User Account Modification",),
    ("wineventlog:security", "4729"): ("User Account Modification",),
    ("wineventlog:security", "4732"): ("User Account Modification",),
    ("wineventlog:security", "4733"): ("User Account Modification",),
    ("wineventlog:security", "4738"): ("User Account Modification",),
    ("wineventlog:security", "4741"): ("User Account Creation",),
    ("wineventlog:security", "4742"): ("User Account Modification",),
    ("wineventlog:security", "4743"): ("User Account Deletion",),
    ("wineventlog:security", "4768"): ("User Account Authentication",),
    ("wineventlog:security", "4769"): ("User Account Authentication",),
    ("wineventlog:security", "4771"): ("User Account Authentication",),
    ("wineventlog:security", "4776"): ("User Account Authentication",),
    ("wineventlog:security", "4778"): ("Logon Session Metadata",),
    ("wineventlog:security", "4779"): ("Logon Session Metadata",),
    ("wineventlog:security", "4798"): ("User Account Metadata",),
    ("wineventlog:security", "4799"): ("User Account Metadata",),
    ("wineventlog:security", "5140"): ("File Access",),
    ("wineventlog:security", "5145"): ("File Access",),
    ("wineventlog:security", "5156"): ("Network Connection Creation",),
    ("wineventlog:security", "5158"): ("Network Connection Creation",),
    ("wineventlog:security", "5447"): ("Network Connection Creation",),
    ("wineventlog:security", "5448"): ("Network Connection Creation",),
    ("wineventlog:security", "5449"): ("Network Connection Creation",),
    ("wineventlog:security", "5450"): ("Network Connection Creation",),
    ("wineventlog:security", "5451"): ("Network Connection Creation",),
    ("wineventlog:security", "5452"): ("Network Connection Creation",),
    ("wineventlog:security", "624"): ("User Account Creation",),
    ("wineventlog:security", "642"): ("User Account Modification",),
    ("wineventlog:security", "643"): ("User Account Modification",),
    ("wineventlog:security", "645"): ("User Account Creation",),
    ("wineventlog:security", "646"): ("User Account Modification",),
    ("wineventlog:sysmon", "12"): ("Windows Registry Key Creation",),
    ("wineventlog:sysmon", "17"): ("Named Pipe Metadata",),
    ("wineventlog:sysmon", "18"): ("Named Pipe Metadata",),
    ("wineventlog:sysmon", "22"): ("Active DNS",),
    ("wineventlog:sysmon", "24"): ("Windows Registry Key Deletion",),
    ("wineventlog:sysmon", "25"): ("Process Access",),
    ("wineventlog:sysmon", "26"): ("File Deletion",),
    ("wineventlog:sysmon", "27"): ("File Modification",),
    ("wineventlog:sysmon", "28"): ("File Metadata",),
    ("wineventlog:sysmon", "29"): ("File Modification",),
}

DESCRIPTION_TO_DATACOMPONENT: tuple[tuple[str, str], ...] = (
    ("audit log was cleared", "Application Log Content"),
    ("event logging service was stopped", "Application Log Content"),
    ("new process has been created", "Process Creation"),
    ("process was terminated", "Process Termination"),
    ("account was successfully logged on", "Logon Session Creation"),
    ("account failed to log on", "User Account Authentication"),
    ("special privileges assigned", "Logon Session Metadata"),
    ("computer account was created", "User Account Creation"),
    ("computer account was changed", "User Account Modification"),
    ("computer account created", "User Account Creation"),
    ("computer account changed", "User Account Modification"),
    ("user account was created", "User Account Creation"),
    ("user account was changed", "User Account Modification"),
    ("user account was deleted", "User Account Deletion"),
    ("user account created", "User Account Creation"),
    ("user account changed", "User Account Modification"),
    ("handle to an object was requested", "File Access"),
    ("object was accessed", "File Access"),
    ("object was deleted", "File Deletion"),
    ("registry", "Windows Registry Key Modification"),
    ("scheduled task", "Scheduled Job Modification"),
    ("service was installed", "Service Creation"),
    ("windows filtering platform", "Network Connection Creation"),
    ("ipsec", "Network Connection Creation"),
    ("network policy server", "Application Log Content"),
    ("kerberos", "User Account Authentication"),
    ("firewall", "Application Log Content"),
    ("domain policy changed", "User Account Modification"),
)


@dataclass
class NormalizationContext:
    """Lookup tables used to normalize spreadsheet values to ATT&CK data components."""

    official_datacomponent_names: dict[str, str]
    event_id_to_datacomponents: dict[tuple[str, str], set[str]]


def get_stix_id(obj: Any) -> str:
    """Return a STIX object's ID for both dict-backed and object-backed shapes."""
    return obj.id if hasattr(obj, "id") else obj["id"]


def build_official_datacomponent_names_from_stix(
    mitre_attack_data: MitreAttackData,
) -> dict[str, str]:
    """Return lowercased data component name -> canonical ATT&CK display name."""
    names: dict[str, str] = {}
    for data_component in mitre_attack_data.get_datacomponents(
        remove_revoked_deprecated=True
    ):
        name = str(mitre_attack_data.get_field(data_component, "name", "")).strip()
        if name:
            names[name.lower()] = name
    return names


def build_official_datacomponent_names_from_xlsx(
    analytics_xlsx: Path,
) -> dict[str, str]:
    """Return lowercased data component name -> canonical ATT&CK display name."""
    defensive = pd.read_excel(analytics_xlsx, sheet_name=DEFENSIVE_MAPPINGS_SHEET)
    names: dict[str, str] = {}
    for value in defensive["data_component_name"].dropna().unique():
        name = str(value).strip()
        if name:
            names[name.lower()] = name
    return names


def build_event_id_to_datacomponents_from_stix(
    mitre_attack_data: MitreAttackData,
) -> dict[tuple[str, str], set[str]]:
    """Parse ATT&CK analytics channels for EventCode=#### -> data component names."""
    event_lookup: dict[tuple[str, str], set[str]] = {}
    for analytic in mitre_attack_data.get_analytics(remove_revoked_deprecated=True):
        for log_ref in (
            mitre_attack_data.get_field(analytic, "x_mitre_log_source_references", [])
            or []
        ):
            log_source = (
                str(mitre_attack_data.get_field(log_ref, "name", "")).strip().lower()
            )
            channel = str(mitre_attack_data.get_field(log_ref, "channel", "") or "")
            data_component_ref = mitre_attack_data.get_field(
                log_ref, "x_mitre_data_component_ref", None
            )
            if not data_component_ref:
                continue
            data_component = mitre_attack_data.get_object_by_stix_id(data_component_ref)
            data_component_name = str(
                mitre_attack_data.get_field(data_component, "name", "")
            ).strip()
            if not log_source or not data_component_name:
                continue
            for match in re.finditer(r"EventCode\s*=\s*(\d+)", channel, re.IGNORECASE):
                event_lookup.setdefault((log_source, match.group(1)), set()).add(
                    data_component_name
                )
    return event_lookup


def build_event_id_to_datacomponents_from_xlsx(
    analytics_xlsx: Path,
) -> dict[tuple[str, str], set[str]]:
    """Build (attack_log_source, event_id) -> data component names from defensive
    mappings."""
    defensive = pd.read_excel(analytics_xlsx, sheet_name=DEFENSIVE_MAPPINGS_SHEET)
    event_lookup: dict[tuple[str, str], set[str]] = {}
    for _, row in defensive.iterrows():
        log_source = str(row.get("log_source_name", "")).strip().lower()
        channel = str(row.get("channel", "") or "")
        data_component_name = str(row.get("data_component_name", "")).strip()
        if not log_source or not data_component_name:
            continue
        for match in re.finditer(r"EventCode\s*=\s*(\d+)", channel, re.IGNORECASE):
            event_lookup.setdefault((log_source, match.group(1)), set()).add(
                data_component_name
            )
    return event_lookup


def supplemental_datacomponents_for_event(
    attack_log_source: str, event_id: str
) -> set[str]:
    """Return supplemental data component names for event IDs missing from ATT&CK
    analytics."""
    data_components = set(
        SUPPLEMENTAL_EVENT_TO_DATACOMPONENT.get((attack_log_source, event_id), ())
    )
    event_number = int(event_id)
    if attack_log_source == "wineventlog:security":
        if 4651 <= event_number <= 4662 or 4976 <= event_number <= 4999:
            data_components.add("Network Connection Creation")
        if 6272 <= event_number <= 6278:
            data_components.add("Application Log Content")
    return data_components


def canonicalize_datacomponent_names(
    data_component_names: set[str], official_names: dict[str, str]
) -> list[str]:
    """Keep only names that exist in ATT&CK, using canonical capitalization."""
    canonical_names: list[str] = []
    for name in data_component_names:
        canonical = official_names.get(name.strip().lower())
        if canonical:
            canonical_names.append(canonical)
    return sorted(set(canonical_names))


def normalize_row_datacomponents(
    row: pd.Series,
    raw_data_component: Any,
    context: NormalizationContext,
) -> tuple[list[str], str]:
    """
    Normalize a spreadsheet row to official ATT&CK data component name(s).

    Resolution order: exact match -> event ID -> description pattern.
    """
    if raw_data_component is None or (
        isinstance(raw_data_component, float) and pd.isna(raw_data_component)
    ):
        raw_text = ""
    else:
        raw_text = str(raw_data_component).strip()

    if raw_text and raw_text.lower() in context.official_datacomponent_names:
        return (
            [context.official_datacomponent_names[raw_text.lower()]],
            "exact_match",
        )

    event_id = row.get("EventID")
    log_source = str(row.get("Log Source", "")).strip().lower()
    attack_log_source = LOG_SOURCE_ATTACK_ALIASES.get(log_source)

    if (
        attack_log_source
        and event_id is not None
        and not (isinstance(event_id, float) and pd.isna(event_id))
    ):
        event_id_text = str(int(float(event_id)))
        data_components = set(
            context.event_id_to_datacomponents.get(
                (attack_log_source, event_id_text), set()
            )
        )
        data_components.update(
            supplemental_datacomponents_for_event(attack_log_source, event_id_text)
        )
        canonical_names = canonicalize_datacomponent_names(
            data_components, context.official_datacomponent_names
        )
        if canonical_names:
            return canonical_names, "event_id"

    lowered_text = raw_text.lower()
    for pattern, data_component_name in DESCRIPTION_TO_DATACOMPONENT:
        if pattern in lowered_text:
            canonical = context.official_datacomponent_names.get(
                data_component_name.lower()
            )
            if canonical:
                return [canonical], "description_pattern"

    return [], "unmapped"


def build_normalization_context_from_stix(
    mitre_attack_data: MitreAttackData,
) -> NormalizationContext:
    """Build normalization lookups from an ATT&CK STIX bundle."""
    return NormalizationContext(
        official_datacomponent_names=build_official_datacomponent_names_from_stix(
            mitre_attack_data
        ),
        event_id_to_datacomponents=build_event_id_to_datacomponents_from_stix(
            mitre_attack_data
        ),
    )


def build_normalization_context_from_xlsx(analytics_xlsx: Path) -> NormalizationContext:
    """Build normalization lookups from an ATT&CK analytics Excel export."""
    return NormalizationContext(
        official_datacomponent_names=build_official_datacomponent_names_from_xlsx(
            analytics_xlsx
        ),
        event_id_to_datacomponents=build_event_id_to_datacomponents_from_xlsx(
            analytics_xlsx
        ),
    )


def get_technique_id(
    mitre_attack_data: MitreAttackData, technique_entry: dict
) -> str | None:
    """
    Given a RelationshipEntry-like dict, return the technique ATT&CK ID
    (T#### or T####.###).

    mitreattack-python RelationshipEntry objects are represented as dicts with:
      - "object": the technique object
      - "relationships": relationship objects
    """
    technique = technique_entry["object"]
    attack_id = mitre_attack_data.get_attack_id(get_stix_id(technique))
    if attack_id:
        return attack_id

    # Fallback if get_attack_id() doesn't find the external reference for some reason.
    for ref in mitre_attack_data.get_field(technique, "external_references", []) or []:
        external_id = ref.get("external_id", "")
        if ref.get("source_name") == "mitre-attack" and external_id.startswith("T"):
            return external_id
    return None


def build_datacomponent_name_to_stix_id(
    mitre_attack_data: MitreAttackData,
) -> dict[str, str]:
    """
    Build a lookup from normalized data component name -> data component STIX ID.

    This is used to go from the STP spreadsheet string value to a STIX object reference.
    """
    name_to_id: dict[str, str] = {}
    for data_component in mitre_attack_data.get_datacomponents(
        remove_revoked_deprecated=True
    ):
        name = mitre_attack_data.get_field(data_component, "name", "")
        if name:
            name_to_id[name.strip().lower()] = get_stix_id(data_component)
    return name_to_id


def build_datacomponent_to_analytic_ids(
    mitre_attack_data: MitreAttackData,
) -> dict[str, set[str]]:
    """
    Build a mapping: data component STIX ID -> set of analytic STIX IDs.

    ATT&CK analytics link to data components through x_mitre_log_source_references
     entries, which may contain either:
      - x_mitre_data_component_ref (single)
      - x_mitre_data_component_refs (list)
    """
    datacomponent_to_analytics: dict[str, set[str]] = {}
    for analytic in mitre_attack_data.get_analytics(remove_revoked_deprecated=True):
        analytic_id = get_stix_id(analytic)
        log_refs = (
            mitre_attack_data.get_field(analytic, "x_mitre_log_source_references", [])
            or []
        )
        for log_ref in log_refs:
            data_component_ref = mitre_attack_data.get_field(
                log_ref, "x_mitre_data_component_ref", None
            )
            data_component_refs = (
                [data_component_ref]
                if data_component_ref
                else mitre_attack_data.get_field(
                    log_ref, "x_mitre_data_component_refs", []
                )
                or []
            )
            for data_component_stix_id in data_component_refs:
                if data_component_stix_id:
                    datacomponent_to_analytics.setdefault(
                        data_component_stix_id, set()
                    ).add(analytic_id)
    return datacomponent_to_analytics


def build_analytic_to_detection_strategy_ids(
    mitre_attack_data: MitreAttackData,
) -> dict[str, set[str]]:
    """
    Build a mapping: analytic STIX ID -> set of detection strategy STIX IDs.

    Detection strategies reference analytics via the x_mitre_analytic_refs list.
    """
    analytic_to_strategies: dict[str, set[str]] = {}
    for detection_strategy in mitre_attack_data.get_detectionstrategies(
        remove_revoked_deprecated=True
    ):
        strategy_id = get_stix_id(detection_strategy)
        analytic_refs = (
            mitre_attack_data.get_field(detection_strategy, "x_mitre_analytic_refs", [])
            or []
        )
        for analytic_ref in analytic_refs:
            analytic_to_strategies.setdefault(analytic_ref, set()).add(strategy_id)
    return analytic_to_strategies


def get_techniques_for_datacomponent(
    mitre_attack_data: MitreAttackData,
    datacomponent_stix_id: str,
    datacomponent_to_analytics: dict[str, set[str]],
    analytic_to_strategies: dict[str, set[str]],
) -> list[str]:
    """
    Resolve a data component (STIX ID) to techniques (ATT&CK IDs).

    Relationship traversal:
      datacomponent_stix_id -> analytic_ids -> detection_strategy_ids -> techniques
    """
    technique_ids: set[str] = set()

    for analytic_id in datacomponent_to_analytics.get(datacomponent_stix_id, set()):
        for strategy_id in analytic_to_strategies.get(analytic_id, set()):
            for (
                technique_entry
            ) in mitre_attack_data.get_techniques_detected_by_detection_strategy(
                strategy_id
            ):
                technique_id = get_technique_id(mitre_attack_data, technique_entry)
                if technique_id:
                    technique_ids.add(technique_id)

    return sorted(technique_ids)


def get_mapping_chains_for_datacomponent(
    mitre_attack_data: MitreAttackData,
    datacomponent_stix_id: str,
    datacomponent_to_analytics: dict[str, set[str]],
    analytic_to_strategies: dict[str, set[str]],
) -> list[dict[str, str]]:
    """
    Resolve a data component to full defensive-mapping chains.

    Each chain records analytic, detection strategy, and technique ATT&CK IDs.
    """
    chains: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    for analytic_stix_id in datacomponent_to_analytics.get(
        datacomponent_stix_id, set()
    ):
        analytic_attack_id = mitre_attack_data.get_attack_id(analytic_stix_id) or ""
        for strategy_stix_id in analytic_to_strategies.get(analytic_stix_id, set()):
            detection_strategy_attack_id = (
                mitre_attack_data.get_attack_id(strategy_stix_id) or ""
            )
            for (
                technique_entry
            ) in mitre_attack_data.get_techniques_detected_by_detection_strategy(
                strategy_stix_id
            ):
                technique_id = get_technique_id(mitre_attack_data, technique_entry)
                if not technique_id:
                    continue
                chain_key = (
                    analytic_attack_id,
                    detection_strategy_attack_id,
                    technique_id,
                )
                if chain_key in seen:
                    continue
                seen.add(chain_key)
                chains.append(
                    {
                        ANALYTIC_COLUMN_NAME: analytic_attack_id,
                        DETECTION_STRATEGY_COLUMN_NAME: detection_strategy_attack_id,
                        TECHNIQUE_COLUMN_NAME: technique_id,
                    }
                )

    return sorted(
        chains, key=lambda chain: tuple(chain[column] for column in CHAIN_COLUMN_NAMES)
    )


def map_data_component_name_to_techniques(
    mitre_attack_data: MitreAttackData,
    data_component_name: Any,
    name_to_stix_id: dict[str, str],
    datacomponent_to_analytics: dict[str, set[str]],
    analytic_to_strategies: dict[str, set[str]],
) -> list[str]:
    """
    Resolve a spreadsheet cell value (data component name) to techniques (ATT&CK IDs).

    This is the spreadsheet-facing entry point for the STIX-based mode.
    """
    if data_component_name is None or (
        isinstance(data_component_name, float) and pd.isna(data_component_name)
    ):
        return []

    normalized_name = str(data_component_name).strip().lower()
    if not normalized_name:
        return []

    datacomponent_stix_id = name_to_stix_id.get(normalized_name)
    if not datacomponent_stix_id:
        return []

    return get_techniques_for_datacomponent(
        mitre_attack_data,
        datacomponent_stix_id,
        datacomponent_to_analytics,
        analytic_to_strategies,
    )


def resolve_mapping_chains_for_datacomponent_names(
    data_component_names: list[str],
    mitre_attack_data: MitreAttackData | None,
    mapping_chains_by_datacomponent_name: dict[str, list[dict[str, str]]] | None,
    name_to_stix_id: dict[str, str],
    datacomponent_to_analytics: dict[str, set[str]],
    analytic_to_strategies: dict[str, set[str]],
) -> list[dict[str, str]]:
    """Union mapping chains across one or more normalized data component names."""
    chains: list[dict[str, str]] = []
    seen: set[tuple[str, str, str]] = set()

    for data_component_name in data_component_names:
        normalized_name = data_component_name.strip().lower()
        if not normalized_name:
            continue

        if mapping_chains_by_datacomponent_name is not None:
            component_chains = mapping_chains_by_datacomponent_name.get(
                normalized_name, []
            )
        else:
            datacomponent_stix_id = name_to_stix_id.get(normalized_name)
            if not datacomponent_stix_id:
                continue
            component_chains = get_mapping_chains_for_datacomponent(
                mitre_attack_data,  # type: ignore[arg-type]
                datacomponent_stix_id,
                datacomponent_to_analytics,
                analytic_to_strategies,
            )

        for chain in component_chains:
            chain_key = tuple(chain[column] for column in CHAIN_COLUMN_NAMES)
            if chain_key in seen:
                continue
            seen.add(chain_key)
            chains.append(chain)

    return sorted(
        chains, key=lambda chain: tuple(chain[column] for column in CHAIN_COLUMN_NAMES)
    )


def technique_ids_from_mapping_chains(
    mapping_chains: list[dict[str, str]],
) -> list[str]:
    """Extract sorted unique technique IDs from mapping chains."""
    return sorted(
        {
            chain[TECHNIQUE_COLUMN_NAME]
            for chain in mapping_chains
            if chain.get(TECHNIQUE_COLUMN_NAME)
        }
    )


def resolve_techniques_for_datacomponent_names(
    data_component_names: list[str],
    mitre_attack_data: MitreAttackData | None,
    techniques_by_datacomponent_name: dict[str, set[str]] | None,
    name_to_stix_id: dict[str, str],
    datacomponent_to_analytics: dict[str, set[str]],
    analytic_to_strategies: dict[str, set[str]],
) -> list[str]:
    """Union technique IDs across one or more normalized data component names."""
    if techniques_by_datacomponent_name is not None:
        technique_ids: set[str] = set()
        for data_component_name in data_component_names:
            normalized_name = data_component_name.strip().lower()
            if normalized_name:
                technique_ids.update(
                    techniques_by_datacomponent_name.get(normalized_name, set())
                )
        return sorted(technique_ids)

    mapping_chains = resolve_mapping_chains_for_datacomponent_names(
        data_component_names,
        mitre_attack_data,
        None,
        name_to_stix_id,
        datacomponent_to_analytics,
        analytic_to_strategies,
    )
    return technique_ids_from_mapping_chains(mapping_chains)


# ---------------------------------------------------------------------------
# Excel output formatting and collapsible row grouping
# ---------------------------------------------------------------------------


def _empty_mapping_chain() -> dict[str, str]:
    return {column: "" for column in CHAIN_COLUMN_NAMES}


def format_techniques_in_dataframe(
    result: pd.DataFrame,
    mapping_chains_by_row: list[list[dict[str, str]]],
    technique_format: str,
) -> pd.DataFrame:
    """
    Attach mapped defensive chains to the dataframe in the requested Excel layout.

    Each chain includes analytic, detection strategy, and technique ATT&CK IDs.

    - rows: one output row per chain (analytic + detection strategy + technique)
    - columns: one technique column slot per mapped technique
    - combined: comma-separated IDs per chain object type
    """
    if technique_format == "combined":
        result[ANALYTIC_COLUMN_NAME] = [
            ", ".join(
                sorted(
                    {
                        chain[ANALYTIC_COLUMN_NAME]
                        for chain in chains
                        if chain[ANALYTIC_COLUMN_NAME]
                    }
                )
            )
            for chains in mapping_chains_by_row
        ]
        result[DETECTION_STRATEGY_COLUMN_NAME] = [
            ", ".join(
                sorted(
                    {
                        chain[DETECTION_STRATEGY_COLUMN_NAME]
                        for chain in chains
                        if chain[DETECTION_STRATEGY_COLUMN_NAME]
                    }
                )
            )
            for chains in mapping_chains_by_row
        ]
        result[TECHNIQUES_COLUMN_NAME] = [
            ", ".join(technique_ids_from_mapping_chains(chains))
            for chains in mapping_chains_by_row
        ]
        return result

    if technique_format == "columns":
        max_chains = max((len(chains) for chains in mapping_chains_by_row), default=0)
        for index in range(max_chains):
            slot = index + 1
            result[f"{ANALYTIC_COLUMN_NAME} {slot}"] = [
                chains[index][ANALYTIC_COLUMN_NAME] if index < len(chains) else ""
                for chains in mapping_chains_by_row
            ]
            result[f"{DETECTION_STRATEGY_COLUMN_NAME} {slot}"] = [
                (
                    chains[index][DETECTION_STRATEGY_COLUMN_NAME]
                    if index < len(chains)
                    else ""
                )
                for chains in mapping_chains_by_row
            ]
            result[f"{TECHNIQUE_COLUMN_NAME} {slot}"] = [
                chains[index][TECHNIQUE_COLUMN_NAME] if index < len(chains) else ""
                for chains in mapping_chains_by_row
            ]
        return result

    if technique_format == "rows":
        result["_source_row_index"] = range(len(result))
        result["_mapping_chains"] = [
            chains if chains else [_empty_mapping_chain()]
            for chains in mapping_chains_by_row
        ]
        exploded = result.explode("_mapping_chains", ignore_index=True)
        chain_columns = pd.json_normalize(exploded["_mapping_chains"])
        for column in CHAIN_COLUMN_NAMES:
            exploded[column] = chain_columns.get(column, "")
        return exploded.drop(columns=["_mapping_chains"])

    raise ValueError(
        f"Unsupported technique_format {technique_format!r}; "
        "expected 'rows', 'columns', or 'combined'"
    )


SOURCE_ROW_INDEX_COLUMN = "_source_row_index"
LOG_SOURCE_COLUMN_NAME = "Log Source"
EVENT_ID_COLUMN_NAME = "EventID"
DATA_COMPONENT_COLUMN_NAME = "ATT&CK Data Component"
LARGE_EXPORT_ROW_WARNING = 50_000
LARGE_EXPORT_GROUPING_SKIP = 100_000


def resolve_data_component_column_name(dataframe: pd.DataFrame) -> str:
    """Pick the column that best represents the mapped ATT&CK data component."""
    if NORMALIZED_DATA_COMPONENT_COLUMN_NAME in dataframe.columns:
        return NORMALIZED_DATA_COMPONENT_COLUMN_NAME
    if DATA_COMPONENT_COLUMN_NAME in dataframe.columns:
        return DATA_COMPONENT_COLUMN_NAME
    if len(dataframe.columns) > DATA_COMPONENT_COLUMN_INDEX:
        return str(dataframe.columns[DATA_COMPONENT_COLUMN_INDEX])
    raise ValueError("No ATT&CK data component column found for row grouping")


def build_group_key_series(dataframe: pd.DataFrame, group_by: str) -> pd.Series:
    """Build a per-row key used to form consecutive Excel outline groups."""
    if group_by == "source_row":
        if SOURCE_ROW_INDEX_COLUMN not in dataframe.columns:
            raise ValueError(
                f"""Missing {SOURCE_ROW_INDEX_COLUMN!r}; row grouping requires rows
                  technique format"""
            )
        return dataframe[SOURCE_ROW_INDEX_COLUMN].astype(str)

    if group_by == "data_component":
        data_component_column = resolve_data_component_column_name(dataframe)
        return (
            dataframe[data_component_column]
            .fillna("")
            .astype(str)
            .str.strip()
            .str.lower()
        )

    if group_by == "event_id":
        log_source = (
            dataframe[LOG_SOURCE_COLUMN_NAME]
            if LOG_SOURCE_COLUMN_NAME in dataframe.columns
            else pd.Series([""] * len(dataframe), index=dataframe.index)
        )
        event_id = (
            dataframe[EVENT_ID_COLUMN_NAME]
            if EVENT_ID_COLUMN_NAME in dataframe.columns
            else pd.Series([""] * len(dataframe), index=dataframe.index)
        )
        return (
            log_source.fillna("").astype(str).str.strip().str.lower()
            + "|"
            + event_id.fillna("").astype(str).str.strip()
        )

    raise ValueError(
        f"Unsupported group_by {group_by!r}; "
        "expected 'data_component', 'source_row', or 'event_id'"
    )


def sort_dataframe_for_grouping(dataframe: pd.DataFrame, group_by: str) -> pd.DataFrame:
    """Sort exploded rows so each outline group is a contiguous block in Excel."""
    if group_by == "source_row":
        return dataframe

    sort_columns: list[str] = []
    if group_by == "data_component":
        sort_columns.append(resolve_data_component_column_name(dataframe))
    elif group_by == "event_id":
        if LOG_SOURCE_COLUMN_NAME in dataframe.columns:
            sort_columns.append(LOG_SOURCE_COLUMN_NAME)
        if EVENT_ID_COLUMN_NAME in dataframe.columns:
            sort_columns.append(EVENT_ID_COLUMN_NAME)

    if SOURCE_ROW_INDEX_COLUMN in dataframe.columns:
        sort_columns.append(SOURCE_ROW_INDEX_COLUMN)
    for column in CHAIN_COLUMN_NAMES:
        if column in dataframe.columns:
            sort_columns.append(column)

    if not sort_columns:
        return dataframe
    return dataframe.sort_values(sort_columns, kind="stable").reset_index(drop=True)


def find_consecutive_group_ranges(group_keys: list[str]) -> list[tuple[int, int]]:
    """
    Return (detail_start_row, last_row) pairs for Excel groups with 2+ data rows.

    Row numbers are 1-based and include the header row on row 1.
    """
    ranges: list[tuple[int, int]] = []
    index = 0
    while index < len(group_keys):
        end_index = index + 1
        while (
            end_index < len(group_keys) and group_keys[end_index] == group_keys[index]
        ):
            end_index += 1
        if end_index - index > 1:
            first_data_row = index + 2
            last_data_row = end_index + 1
            detail_start_row = first_data_row + 1
            ranges.append((detail_start_row, last_data_row))
        index = end_index
    return ranges


def apply_excel_row_grouping(
    excel_path: Path,
    group_keys: list[str],
    *,
    collapse_groups: bool = True,
) -> int:
    """Apply Excel outline row groups so technique rows can be expanded on demand."""
    from openpyxl import load_workbook

    ranges = find_consecutive_group_ranges(group_keys)
    if not ranges:
        return 0

    workbook = load_workbook(excel_path)
    worksheet = workbook.active
    worksheet.sheet_properties.outlinePr.summaryBelow = False

    for detail_start_row, last_row in ranges:
        worksheet.row_dimensions.group(
            detail_start_row, last_row, hidden=collapse_groups
        )

    workbook.save(excel_path)
    return len(ranges)


# ---------------------------------------------------------------------------
# Spreadsheet enrichment: normalize data components and attach techniques
# ---------------------------------------------------------------------------


def map_source_rows(
    dataframe: pd.DataFrame,
    mitre_attack_data: MitreAttackData | None,
    data_component_column: str | int,
    *,
    mapping_chains_by_datacomponent_name: dict[str, list[dict[str, str]]] | None = None,
    normalization_context: NormalizationContext | None = None,
) -> tuple[list[list[dict[str, str]]], list[str], list[str], pd.DataFrame]:
    """
    Map each source spreadsheet row to defensive chains and collect per-row summary
      stats.

    Returns mapping chains per row (analytic -> detection strategy -> technique),
    normalized component labels, normalization methods, and a summary dataframe.
    """
    name_to_stix_id: dict[str, str] = {}
    datacomponent_to_analytics: dict[str, set[str]] = {}
    analytic_to_strategies: dict[str, set[str]] = {}

    if mapping_chains_by_datacomponent_name is None:
        if mitre_attack_data is None:
            raise ValueError("""mitre_attack_data is required when
                 mapping_chains_by_datacomponent_name is not provided""")
        name_to_stix_id = build_datacomponent_name_to_stix_id(mitre_attack_data)
        datacomponent_to_analytics = build_datacomponent_to_analytic_ids(
            mitre_attack_data
        )
        analytic_to_strategies = build_analytic_to_detection_strategy_ids(
            mitre_attack_data
        )

    mapping_chains_by_row: list[list[dict[str, str]]] = []
    normalized_components_by_row: list[str] = []
    normalization_methods_by_row: list[str] = []
    summary_rows: list[dict[str, Any]] = []
    unmatched_data_components: set[str] = set()

    for _, row in dataframe.iterrows():
        if isinstance(data_component_column, int):
            raw_data_component = row.iloc[data_component_column]
        else:
            raw_data_component = row[data_component_column]

        if normalization_context is not None:
            normalized_datacomponents, normalization_method = (
                normalize_row_datacomponents(
                    row, raw_data_component, normalization_context
                )
            )
        else:
            normalized_datacomponents = []
            normalization_method = "disabled"
            if raw_data_component is not None and not (
                isinstance(raw_data_component, float) and pd.isna(raw_data_component)
            ):
                text = str(raw_data_component).strip()
                if text:
                    normalized_datacomponents = [text]

        mapping_chains = resolve_mapping_chains_for_datacomponent_names(
            normalized_datacomponents,
            mitre_attack_data,
            mapping_chains_by_datacomponent_name,
            name_to_stix_id,
            datacomponent_to_analytics,
            analytic_to_strategies,
        )
        technique_ids = technique_ids_from_mapping_chains(mapping_chains)

        mapping_chains_by_row.append(mapping_chains)
        normalized_label = "; ".join(normalized_datacomponents)
        normalized_components_by_row.append(normalized_label)
        normalization_methods_by_row.append(normalization_method)

        raw_text = (
            ""
            if raw_data_component is None
            or (isinstance(raw_data_component, float) and pd.isna(raw_data_component))
            else str(raw_data_component).strip()
        )
        if raw_text and not technique_ids and normalization_method == "unmapped":
            unmatched_data_components.add(raw_text)

        event_id = row.get(EVENT_ID_COLUMN_NAME, "")
        if event_id is not None and not (
            isinstance(event_id, float) and pd.isna(event_id)
        ):
            event_id_text = str(int(float(event_id))) if str(event_id).strip() else ""
        else:
            event_id_text = ""

        summary_rows.append(
            {
                LOG_SOURCE_COLUMN_NAME: str(
                    row.get(LOG_SOURCE_COLUMN_NAME, "")
                ).strip(),
                EVENT_ID_COLUMN_NAME: event_id_text,
                DATA_COMPONENT_COLUMN_NAME: raw_text,
                NORMALIZED_DATA_COMPONENT_COLUMN_NAME: normalized_label,
                NORMALIZATION_METHOD_COLUMN_NAME: normalization_method,
                "Technique Count": len(technique_ids),
                "Chain Count": len(mapping_chains),
                "Mapped": "Yes" if technique_ids else "No",
            }
        )

    if unmatched_data_components:
        print(
            "Warning: could not normalize "
            f"{len(unmatched_data_components)} unique value(s):"
        )
        for name in sorted(unmatched_data_components)[:20]:
            print(f"  - {name}")
        if len(unmatched_data_components) > 20:
            print(f"  ... and {len(unmatched_data_components) - 20} more")

    return (
        mapping_chains_by_row,
        normalized_components_by_row,
        normalization_methods_by_row,
        pd.DataFrame(summary_rows),
    )


def build_unmapped_summary_sheets(
    summary_dataframe: pd.DataFrame,
) -> dict[str, pd.DataFrame]:
    """Build overview and breakdown sheets for unmapped / mapping coverage reporting."""
    total_rows = len(summary_dataframe)
    mapped_rows = int((summary_dataframe["Mapped"] == "Yes").sum())
    unmapped_rows = total_rows - mapped_rows
    unmapped_values = int(
        summary_dataframe.loc[
            summary_dataframe[NORMALIZATION_METHOD_COLUMN_NAME] == "unmapped",
            DATA_COMPONENT_COLUMN_NAME,
        ]
        .astype(str)
        .str.strip()
        .replace("", pd.NA)
        .dropna()
        .nunique()
    )
    normalized_without_techniques = int(
        (
            (summary_dataframe["Mapped"] == "No")
            & (summary_dataframe[NORMALIZATION_METHOD_COLUMN_NAME] != "unmapped")
        ).sum()
    )

    overview = pd.DataFrame(
        {
            "Metric": [
                "Total source rows",
                "Rows with mapped techniques",
                "Rows without mapped techniques",
                "Rows mapped (%)",
                "Rows without techniques (%)",
                "Unique unmapped column C values",
                "Rows normalized but with zero techniques",
            ],
            "Count": [
                total_rows,
                mapped_rows,
                unmapped_rows,
                round((mapped_rows / total_rows) * 100, 2) if total_rows else 0,
                round((unmapped_rows / total_rows) * 100, 2) if total_rows else 0,
                unmapped_values,
                normalized_without_techniques,
            ],
        }
    )

    by_method = (
        summary_dataframe.groupby(NORMALIZATION_METHOD_COLUMN_NAME, dropna=False)
        .agg(
            Rows=(NORMALIZATION_METHOD_COLUMN_NAME, "size"),
            Mapped_Rows=("Mapped", lambda values: int((values == "Yes").sum())),
        )
        .reset_index()
        .rename(
            columns={
                NORMALIZATION_METHOD_COLUMN_NAME: "Normalization Method",
                "Mapped_Rows": "Mapped Rows",
            }
        )
    )
    by_method["Unmapped Rows"] = by_method["Rows"] - by_method["Mapped Rows"]
    by_method["Mapped (%)"] = (
        by_method["Mapped Rows"] / by_method["Rows"] * 100
    ).round(2)

    unmapped_value_counts = (
        summary_dataframe.loc[
            summary_dataframe["Mapped"] == "No", DATA_COMPONENT_COLUMN_NAME
        ]
        .fillna("")
        .astype(str)
        .str.strip()
    )
    unmapped_values_table = (
        unmapped_value_counts[unmapped_value_counts != ""]
        .value_counts()
        .rename_axis(DATA_COMPONENT_COLUMN_NAME)
        .reset_index(name="Row Count")
    )

    by_log_source = (
        summary_dataframe.groupby(LOG_SOURCE_COLUMN_NAME, dropna=False)
        .agg(
            Rows=(LOG_SOURCE_COLUMN_NAME, "size"),
            Mapped_Rows=("Mapped", lambda values: int((values == "Yes").sum())),
        )
        .reset_index()
        .rename(
            columns={
                LOG_SOURCE_COLUMN_NAME: "Log Source",
                "Mapped_Rows": "Mapped Rows",
            }
        )
    )
    by_log_source["Unmapped Rows"] = (
        by_log_source["Rows"] - by_log_source["Mapped Rows"]
    )
    by_log_source["Mapped (%)"] = (
        by_log_source["Mapped Rows"] / by_log_source["Rows"] * 100
    ).round(2)

    by_event = (
        summary_dataframe.groupby(
            [LOG_SOURCE_COLUMN_NAME, EVENT_ID_COLUMN_NAME], dropna=False
        )
        .agg(
            Rows=(EVENT_ID_COLUMN_NAME, "size"),
            Mapped_Rows=("Mapped", lambda values: int((values == "Yes").sum())),
        )
        .reset_index()
        .rename(columns={"Mapped_Rows": "Mapped Rows"})
    )
    by_event["Unmapped Rows"] = by_event["Rows"] - by_event["Mapped Rows"]
    by_event["Mapped (%)"] = (by_event["Mapped Rows"] / by_event["Rows"] * 100).round(2)
    by_event = by_event.sort_values(
        ["Unmapped Rows", "Rows"], ascending=[False, False]
    ).reset_index(drop=True)

    return {
        "Overview": overview,
        "By Normalization Method": by_method,
        "Unmapped Values": unmapped_values_table,
        "By Log Source": by_log_source,
        "By Event ID": by_event,
    }


def alternate_output_path(path: Path, attempt: int) -> Path:
    """Return an alternate output path when the target file is locked."""
    if attempt == 0:
        return path
    return path.with_name(f"{path.stem}_{attempt}{path.suffix}")


def write_excel_path_with_fallback(
    path: Path, write: Any, *, label: str = "output"
) -> Path:
    """
    Write an Excel file, retrying with a numbered suffix if the target is locked.

    On Windows this usually means the workbook is open in Excel.
    """
    for attempt in range(10):
        candidate = alternate_output_path(path, attempt)
        try:
            write(candidate)
            if candidate != path:
                print(
                    f"Warning: could not write {label} to {path} "
                    f"(file may be open in Excel); wrote to {candidate}"
                )
            return candidate
        except PermissionError:
            continue
        except OSError as exc:
            if getattr(exc, "winerror", None) == 32:
                continue
            raise
    raise PermissionError(
        f"Could not write {label} to {path} or alternate paths; "
        "close the workbook in Excel or pass an explicit output path."
    )


def write_unmapped_summary_excel(
    output_path: Path, summary_dataframe: pd.DataFrame
) -> Path:
    """Write unmapped mapping statistics to a multi-sheet Excel workbook."""

    def write(path: Path) -> None:
        sheets = build_unmapped_summary_sheets(summary_dataframe)
        with pd.ExcelWriter(path, engine="openpyxl") as writer:
            for sheet_name, sheet_dataframe in sheets.items():
                sheet_dataframe.to_excel(writer, sheet_name=sheet_name, index=False)

    return write_excel_path_with_fallback(output_path, write, label="unmapped summary")


def add_techniques_column(
    dataframe: pd.DataFrame,
    mitre_attack_data: MitreAttackData | None,
    data_component_column: str | int = DATA_COMPONENT_COLUMN_INDEX,
    *,
    mapping_chains_by_datacomponent_name: dict[str, list[dict[str, str]]] | None = None,
    normalization_context: NormalizationContext | None = None,
    technique_format: str = "rows",
) -> pd.DataFrame:
    """
    Return a copy of the dataframe with normalized data components and mapped chains.

    When `normalization_context` is provided, raw spreadsheet values are normalized to
    official ATT&CK data component names before defensive chain mapping.
    """
    (
        mapping_chains_by_row,
        normalized_components_by_row,
        normalization_methods_by_row,
        _,
    ) = map_source_rows(
        dataframe,
        mitre_attack_data,
        data_component_column,
        mapping_chains_by_datacomponent_name=mapping_chains_by_datacomponent_name,
        normalization_context=normalization_context,
    )

    result = dataframe.copy()
    if normalization_context is not None:
        result[NORMALIZED_DATA_COMPONENT_COLUMN_NAME] = normalized_components_by_row
        result[NORMALIZATION_METHOD_COLUMN_NAME] = normalization_methods_by_row
    return format_techniques_in_dataframe(
        result, mapping_chains_by_row, technique_format
    )


# ---------------------------------------------------------------------------
# ATT&CK Excel export mode (alternative to STIX JSON parsing)
# ---------------------------------------------------------------------------


def build_mapping_chains_by_datacomponent_name_from_attack_xlsx(
    analytics_xlsx: Path, relationships_xlsx: Path
) -> dict[str, list[dict[str, str]]]:
    """
    Build mapping of data component name -> full defensive chains using ATT&CK excel
     exports:

      analytics.xlsx / sheet "defensive mappings" provides:
        data_component_name, analytic_name (AN####), detection_strategy_attack_id
          (DET####)

      relationships.xlsx / sheet "relationships" provides:
        DET#### --detects--> T####(.###)
    """
    defensive = pd.read_excel(analytics_xlsx, sheet_name=DEFENSIVE_MAPPINGS_SHEET)
    rel = pd.read_excel(relationships_xlsx, sheet_name=RELATIONSHIPS_SHEET)

    rel_detects = rel[rel["mapping type"].astype(str).str.lower() == "detects"]
    det_to_techs: dict[str, set[str]] = {}
    for _, row in rel_detects.iterrows():
        det = str(row.get("source ID", "")).strip().upper()
        tid = str(row.get("target ID", "")).strip().upper()
        if det and tid and det.startswith("DET") and tid.startswith("T"):
            det_to_techs.setdefault(det, set()).add(tid)

    chains_by_dc: dict[str, list[dict[str, str]]] = {}
    seen_by_dc: dict[str, set[tuple[str, str, str]]] = {}

    for _, row in defensive.iterrows():
        dc_name = str(row.get("data_component_name", "")).strip().lower()
        analytic = str(row.get("analytic_name", "")).strip().upper()
        det = str(row.get("detection_strategy_attack_id", "")).strip().upper()
        if not dc_name or not det:
            continue

        for tid in det_to_techs.get(det, set()):
            chain_key = (analytic, det, tid)
            seen = seen_by_dc.setdefault(dc_name, set())
            if chain_key in seen:
                continue
            seen.add(chain_key)
            chains_by_dc.setdefault(dc_name, []).append(
                {
                    ANALYTIC_COLUMN_NAME: analytic,
                    DETECTION_STRATEGY_COLUMN_NAME: det,
                    TECHNIQUE_COLUMN_NAME: tid,
                }
            )

    for dc_name, chains in chains_by_dc.items():
        chains_by_dc[dc_name] = sorted(
            chains,
            key=lambda chain: tuple(chain[column] for column in CHAIN_COLUMN_NAMES),
        )

    return chains_by_dc


def build_techniques_by_datacomponent_name_from_attack_xlsx(
    analytics_xlsx: Path, relationships_xlsx: Path
) -> dict[str, set[str]]:
    """
    Build mapping of data component name -> technique IDs using ATT&CK excel exports.

    This is a convenience wrapper around the full defensive-chain builder.
    """
    techniques_by_dc: dict[str, set[str]] = {}
    for dc_name, chains in build_mapping_chains_by_datacomponent_name_from_attack_xlsx(
        analytics_xlsx, relationships_xlsx
    ).items():
        techniques_by_dc[dc_name] = set(technique_ids_from_mapping_chains(chains))
    return techniques_by_dc


# ---------------------------------------------------------------------------
# Command-line interface
# ---------------------------------------------------------------------------


def main() -> None:
    """CLI entry point: read STP spreadsheet, map techniques, write updated
    spreadsheet.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Add ATT&CK technique mappings to an STP spreadsheet using "
            "data component -> analytic -> detection strategy -> technique."
        )
    )
    parser.add_argument(
        "input_spreadsheet",
        type=Path,
        help="Path to all-event-and-field-data-consolidated spreadsheet",
    )
    parser.add_argument(
        "attack_stix",
        type=Path,
        nargs="?",
        default=Path("data/attack/enterprise-attack.json"),
        help=(
            "Path to enterprise-attack STIX JSON "
            "(used when ATT&CK Excel exports are not provided)"
        ),
    )
    parser.add_argument(
        "--attack-analytics-xlsx",
        type=Path,
        help=(
            """ATT&CK analytics excel export
            (e.g., enterprise-attack-v19.1-analytics.xlsx). """
            """If provided with --attack-relationships-xlsx, the script will use the
             excel exports """
            "instead of parsing STIX JSON."
        ),
    )
    parser.add_argument(
        "--attack-relationships-xlsx",
        type=Path,
        help=(
            """ATT&CK relationships excel export
             (e.g., enterprise-attack-v19.1-relationships.xlsx). """
            "Must be provided with --attack-analytics-xlsx."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output spreadsheet path (default: <input>_with_techniques.xlsx)",
    )
    parser.add_argument(
        "--sheet",
        default=0,
        help="Worksheet name or index to read (default: first sheet)",
    )
    parser.add_argument(
        "--data-component-column",
        default=str(DATA_COMPONENT_COLUMN_INDEX),
        help=(
            "Column containing ATT&CK data components (name or 0-based index; "
            "default: 2 for column C)"
        ),
    )
    parser.add_argument(
        "--no-normalize",
        action="store_true",
        help="""Disable normalization of event descriptions to official ATT&CK data
          components""",
    )
    parser.add_argument(
        "--technique-format",
        choices=("rows", "columns", "combined"),
        default="rows",
        help=(
            "How to write techniques in Excel: "
            "'rows' = one technique per row (default), "
            "'combined' = comma-separated in one cell, "
            "'columns' = one technique per column"
        ),
    )
    parser.add_argument(
        "--group-by",
        choices=("data_component", "event_id", "source_row", "none"),
        default="event_id",
        help=(
            """For --technique-format rows, group technique rows in Excel with +/-
             toggles. """
            "'event_id' groups by Log Source + EventID (default), "
            "'data_component' groups by ATT&CK Data Component, "
            "'source_row' groups techniques for each input spreadsheet row, "
            "'none' disables grouping"
        ),
    )
    parser.add_argument(
        "--summary-output",
        type=Path,
        help=(
            "Write unmapped mapping statistics to a multi-sheet Excel workbook "
            "(default: <input>_unmapped_summary.xlsx)"
        ),
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="""Only write the unmapped summary workbook (skip technique output
         spreadsheet)""",
    )
    parser.add_argument(
        "--no-collapse",
        action="store_true",
        help="Leave grouped technique rows expanded when the workbook opens",
    )
    args = parser.parse_args()

    output_path = args.output or args.input_spreadsheet.with_name(
        f"{args.input_spreadsheet.stem}_with_techniques{args.input_spreadsheet.suffix}"
    )
    summary_output_path = args.summary_output or args.input_spreadsheet.with_name(
        f"{args.input_spreadsheet.stem}_unmapped_summary{args.input_spreadsheet.suffix}"
    )

    data_component_column: str | int
    if str(args.data_component_column).isdigit():
        data_component_column = int(args.data_component_column)
    else:
        data_component_column = args.data_component_column

    mapping_chains_by_datacomponent_name: dict[str, list[dict[str, str]]] | None = None
    mitre_attack_data: MitreAttackData | None
    normalization_context: NormalizationContext | None = None

    if args.attack_analytics_xlsx or args.attack_relationships_xlsx:
        if not (args.attack_analytics_xlsx and args.attack_relationships_xlsx):
            raise SystemExit(
                """If using ATT&CK excel exports, both --attack-analytics-xlsx and
                  --attack-relationships-xlsx are required."""
            )
        mapping_chains_by_datacomponent_name = (
            build_mapping_chains_by_datacomponent_name_from_attack_xlsx(
                args.attack_analytics_xlsx, args.attack_relationships_xlsx
            )
        )
        mitre_attack_data = None
        if not args.no_normalize:
            normalization_context = build_normalization_context_from_xlsx(
                args.attack_analytics_xlsx
            )
    else:
        mitre_attack_data = MitreAttackData(str(args.attack_stix))
        if not args.no_normalize:
            normalization_context = build_normalization_context_from_stix(
                mitre_attack_data
            )

    dataframe = pd.read_excel(args.input_spreadsheet, sheet_name=args.sheet)
    (
        mapping_chains_by_row,
        normalized_components_by_row,
        normalization_methods_by_row,
        summary_dataframe,
    ) = map_source_rows(
        dataframe,
        mitre_attack_data,
        data_component_column,
        mapping_chains_by_datacomponent_name=mapping_chains_by_datacomponent_name,
        normalization_context=normalization_context,
    )

    summary_output_path = write_unmapped_summary_excel(
        summary_output_path, summary_dataframe
    )
    print(f"Wrote unmapped summary to {summary_output_path}")

    if args.summary_only:
        mapped_source_rows = int((summary_dataframe["Mapped"] == "Yes").sum())
        print(
            f"Mapped techniques for {mapped_source_rows} of "
            f"{len(summary_dataframe)} source row(s)"
        )
        return

    result = dataframe.copy()
    if normalization_context is not None:
        result[NORMALIZED_DATA_COMPONENT_COLUMN_NAME] = normalized_components_by_row
        result[NORMALIZATION_METHOD_COLUMN_NAME] = normalization_methods_by_row
    result = format_techniques_in_dataframe(
        result, mapping_chains_by_row, args.technique_format
    )
    print(f"Prepared {len(result):,} output row(s)", flush=True)

    group_count = 0
    if args.technique_format == "rows" and args.group_by != "none":
        result = sort_dataframe_for_grouping(result, args.group_by)
        group_keys = build_group_key_series(result, args.group_by).tolist()
        export_result = result.drop(columns=[SOURCE_ROW_INDEX_COLUMN], errors="ignore")
        apply_grouping = len(export_result) <= LARGE_EXPORT_GROUPING_SKIP

        if not apply_grouping:
            print(
                f"Skipping Excel row grouping for {len(export_result):,} rows "
                f"(>{LARGE_EXPORT_GROUPING_SKIP:,}). "
                "Use --group-by none on smaller exports if you need grouping.",
                flush=True,
            )
        elif len(export_result) > LARGE_EXPORT_ROW_WARNING:
            print(
                f"Writing {len(export_result):,} rows with Excel grouping may take "
                "10-30+ minutes. Use --group-by none for a faster export.",
                flush=True,
            )

        def write_grouped(path: Path) -> None:
            nonlocal group_count
            print(f"Writing {len(export_result):,} rows to {path} ...", flush=True)
            export_result.to_excel(path, index=False)
            if apply_grouping:
                print(
                    "Applying Excel row grouping (this can take several minutes) ...",
                    flush=True,
                )
                group_count = apply_excel_row_grouping(
                    path,
                    group_keys,
                    collapse_groups=not args.no_collapse,
                )

        output_path = write_excel_path_with_fallback(
            output_path, write_grouped, label="output spreadsheet"
        )
    else:
        export_result = result.drop(columns=[SOURCE_ROW_INDEX_COLUMN], errors="ignore")

        def write_plain(path: Path) -> None:
            print(f"Writing {len(export_result):,} rows to {path} ...", flush=True)
            export_result.to_excel(path, index=False)

        output_path = write_excel_path_with_fallback(
            output_path, write_plain, label="output spreadsheet"
        )

    if args.technique_format == "combined":
        mapped_rows = sum(1 for value in result[TECHNIQUES_COLUMN_NAME] if value)
    elif args.technique_format == "columns":
        chain_columns = [
            column
            for column in result.columns
            if str(column).startswith(f"{TECHNIQUE_COLUMN_NAME} ")
        ]
        mapped_rows = (
            int(result[chain_columns].ne("").any(axis=1).sum()) if chain_columns else 0
        )
    else:
        mapped_rows = int(
            result[TECHNIQUE_COLUMN_NAME].astype(str).str.strip().ne("").sum()
        )

    print(f"Wrote {len(export_result)} rows to {output_path}")
    print(f"Mapped techniques for {mapped_rows} row(s)")
    if group_count:
        collapse_state = "collapsed" if not args.no_collapse else "expanded"
        print(f"""Applied {group_count} Excel row group(s) by {args.group_by}
            ({collapse_state})""")


if __name__ == "__main__":
    main()
