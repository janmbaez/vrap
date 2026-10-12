"""Versioned, source-controlled Asset Classification Quest contract.

Question IDs are durable evidence keys. New versions may add questions but must
never reinterpret an answer stored under a prior version.
"""
QUESTIONNAIRE = {
    'version': '1.0-provisional',
    'title': 'Asset Classification Quest',
    'approval_state': 'Pending GRC approval',
    'steps': [
        {'id': 'identity', 'title': 'Identity & ownership', 'questions': [
            {'id': 'identity.business_owner', 'field': 'business_owner', 'type': 'text', 'required': False, 'source_types': ['BIA', 'CMDB', 'owner_attestation']},
            {'id': 'identity.it_owner', 'field': 'it_owner', 'type': 'text', 'required': False, 'source_types': ['CMDB', 'owner_attestation']},
            {'id': 'identity.application_owner', 'field': 'application_owner', 'type': 'text', 'required': False, 'source_types': ['CMDB', 'owner_attestation']},
        ]},
        {'id': 'business', 'title': 'Business context', 'questions': [
            {'id': 'business.criticality', 'field': 'business_criticality', 'type': 'choice', 'values': ['Low', 'Medium', 'High', 'Critical'], 'required': False, 'source_types': ['BIA', 'owner_attestation']},
            {'id': 'business.asset_criticality', 'field': 'asset_criticality', 'type': 'choice', 'values': ['Low', 'Medium', 'High', 'Critical'], 'required': False, 'source_types': ['BIA', 'CMDB']},
        ]},
        {'id': 'data_scope', 'title': 'Data & regulatory scope', 'questions': [
            {'id': 'data.classification', 'field': 'data_classification', 'type': 'choice', 'values': ['Public', 'Internal', 'Confidential', 'Restricted'], 'required': False, 'source_types': ['BIA', 'data_inventory']},
            {'id': 'scope.regulatory', 'field': 'regulatory', 'type': 'multi', 'values': ['PCI DSS', 'SOC 2', 'SOX', 'HIPAA', 'GDPR', 'Other'], 'required': False, 'source_types': ['BIA', 'GRC_scope']},
        ]},
        {'id': 'exposure', 'title': 'Exposure & controls', 'questions': [
            {'id': 'exposure.environment', 'field': 'environment', 'type': 'choice', 'values': ['Development', 'Test', 'QA', 'Staging', 'Production'], 'required': False, 'source_types': ['CMDB', 'owner_attestation']},
            {'id': 'exposure.network', 'field': 'exposure', 'type': 'choice', 'values': ['Internet Facing', 'Internal', 'Restricted Network', 'Isolated'], 'required': False, 'source_types': ['network_evidence', 'owner_attestation']},
        ]},
    ],
}
