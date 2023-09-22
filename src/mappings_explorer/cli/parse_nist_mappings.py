def configure_nist_mappings(dataframe, parsed_mappings, attack_version, mappings_version):

    for _, row in dataframe.iterrows():
        parsed_mappings.append({
            'metadata': {
                'mapping-verision': mappings_version,
                'attack-version': attack_version,
                'creation-date': '',
                'last-update': '',
                'author': '',
                'contact': '',
                'organization': '',
                'platform': 'NIST Security controls',
                'platform-version': '', # get correct value
                'mapping-type': 'association',
            },
            'attack-object': {
                'id': row['Technique ID'],
                'name': row['Technique Name'],
                'value': row['Control ID'],
                'mapping-pattern': row['Mapping Type'],
                'secondary-property': '',
                'tags': [],
                'comments': '',
                'references': []
            }
        })

    return parsed_mappings
