def configure_veris_mappings(veris_mappings, parsed_mappings):

    for attack_object in veris_mappings['attack_to_veris']:
        mapped_attack_object = veris_mappings['attack_to_veris'][attack_object]
        for veris_object in mapped_attack_object['veris']:
            parsed_mappings.append({
                'metadata': {
                    'mapping-verision': veris_mappings['metadata']['mappings_version'],
                    'attack-version': veris_mappings['metadata']['attack_version'],
                    'creation-date': '', # get correct value
                    'last-update': '', # get correct value
                    'author': '',
                    'contact': '',
                    'organization': '',
                    'platform': 'VERIS Framework',
                    'platform-version': veris_mappings['metadata']['veris_version'],
                    'mapping-type': 'association',
                },
                'attack-object': {
                    'id': attack_object,
                    'name': mapped_attack_object['name'],
                    'value': veris_object,
                    'mapping-pattern': '',
                    'secondary-property': '',
                    'tags': [],
                    'comments': '',
                    'references': []
                }
            })

    return parsed_mappings
