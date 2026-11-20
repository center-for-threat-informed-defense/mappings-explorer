"""Tests for the STP data component to ATT&CK technique parser."""

from pathlib import Path

import pandas as pd
import pytest
from mitreattack.stix20 import MitreAttackData

from mapex_convert.parse_stp_mappings import (
    TECHNIQUES_COLUMN_NAME,
    add_techniques_column,
)

STP_SAMPLE = Path(__file__).parent / "files" / "test_stp_sample.xlsx"
ATTACK_STIX = Path(__file__).parent.parent / "data" / "attack" / "enterprise-attack.json"


@pytest.mark.skipif(not ATTACK_STIX.exists(), reason="enterprise-attack STIX bundle not present")
def test_add_techniques_column_maps_known_data_components():
    """Rows with official ATT&CK data component names should receive technique IDs."""
    dataframe = pd.read_excel(STP_SAMPLE)
    mitre_attack_data = MitreAttackData(str(ATTACK_STIX))
    result = add_techniques_column(
        dataframe,
        mitre_attack_data,
        data_component_column="Data Component",
        technique_format="combined",
        normalization_context=None,
    )

    process_creation = result.loc[
        result["Data Component"] == "Process Creation", TECHNIQUES_COLUMN_NAME
    ]
    assert not process_creation.empty
    assert process_creation.iloc[0]
