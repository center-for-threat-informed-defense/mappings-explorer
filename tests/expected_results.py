import yaml

expected_nist_mapping = yaml.dump([{
      'metadata': {
        'mapping-verision': '1',
        'attack-version': '13.0',
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
          'id': 'T1137',
          'name': 'Office Application Startup',
          'value': 'AC-10',
          'mapping-pattern': 'mitigates',
          'secondary-property': '',
          'tags': [],
          'comments': '',
          'references': []
      }
    },
    {
      'metadata': {
        'mapping-verision': '1',
        'attack-version': '13.0',
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
        'id': 'T1137.002',
        'name': 'Office Test',
        'value': 'AC-10',
        'mapping-pattern': 'mitigates',
        'secondary-property': '',
        'tags': [],
        'comments': '',
        'references': []
    }
    }])

expected_security_stack_mapping = yaml.dump([{
    'metadata': {
        'mapping-verision': 1,
        'attack-version': 9,
        'creation-date': '05/27/2021', # confirm that this value is correct
        'last-update': '05/27/2021', # confirm this value is correct
        'author': '',
        'contact': 'ctid@mitre-engenuity.org',
        'organization': '',
        'platform': 'AWS',
        'platform-version': '', # get correct value
        'mapping-type': 'scoring',
    },
    'attack-object': {
        'id': 'T1078',
        'name': 'Valid Accounts',
        'value': 'Amazon Cognito',
        'mapping-pattern': '',
        'secondary-property': '',
        'comments': 'comment',
        'references': [
          'https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html',
          'https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-compromised-credentials.html',
          'https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html',
        ],
        'score-category': 'Protect',
        'score-value': 'Minimal',
        'score-comment': 'comment',
        'related-score': True,
        'tags': ['Identity']
    }},
    {'metadata': {
        'mapping-verision': 1,
        'attack-version': 9,
        'creation-date': '05/27/2021', # confirm that this value is correct
        'last-update': '05/27/2021', # confirm this value is correct
        'author': '',
        'contact': 'ctid@mitre-engenuity.org',
        'organization': '',
        'platform': 'AWS',
        'platform-version': '', # get correct value
        'mapping-type': 'scoring',
    },
    'attack-object': {
        'id': 'T1110',
        'name': 'Brute Force',
        'value': 'Amazon Cognito',
        'mapping-pattern': '',
        'secondary-property': '',
        'comments': 'comment',
        'references': [
          'https://docs.aws.amazon.com/cognito/latest/developerguide/what-is-amazon-cognito.html',
          'https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-compromised-credentials.html',
          'https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-adaptive-authentication.html',
        ],
        'score-category': 'Protect',
        'score-value': 'Significant',
        'score-comment': 'technique score comment',
        'related-score': True,
        'tags': ['Identity']
    }}
  ])


expected_veris_mapping = yaml.dump(
    [{
        'metadata': {
            'mapping-verision': '1.9',
            'attack-version': '9.0',
            'creation-date': '', # get correct value
            'last-update': '', # get correct value
            'author': '',
            'contact': '',
            'organization': '',
            'platform': 'VERIS Framework',
            'platform-version': '1.3.5',
            'mapping-type': 'association',
        },
        'attack-object': {
            'id': 'T1047',
            'name': "Windows Management Instrumentation",
            'value':  "action.hacking.variety.Abuse of functionality",
            'mapping-pattern': '',
            'secondary-property': '',
            'tags': [],
            'comments': '',
            'references': []
        }
    },
    {
     'metadata': {
        'mapping-verision': '1.9',
        'attack-version': '9.0',
        'creation-date': '', # get correct value
        'last-update': '', # get correct value
        'author': '',
        'contact': '',
        'organization': '',
        'platform': 'VERIS Framework',
        'platform-version': '1.3.5',
        'mapping-type': 'association',
    },
    'attack-object': {
        'id': 'T1047',
        'name': "Windows Management Instrumentation",
        'value': "action.hacking.vector.Command shell",
        'mapping-pattern': '',
        'secondary-property': '',
        'tags': [],
        'comments': '',
        'references': []
    }
  },
  {
    'metadata': {
        'mapping-verision': '1.9',
        'attack-version': '9.0',
        'creation-date': '', # get correct value
        'last-update': '', # get correct value
        'author': '',
        'contact': '',
        'organization': '',
        'platform': 'VERIS Framework',
        'platform-version': '1.3.5',
        'mapping-type': 'association',
    },
    'attack-object': {
        'id': 'T1053',
        'name': "Scheduled Task/Job",
        'value': "action.hacking.variety.Abuse of functionality",
        'mapping-pattern': '',
        'secondary-property': '',
        'tags': [],
        'comments': '',
        'references': []
    },
  }
])
