"""Explicit bootstrap. Demo data is opt-in and refuses a nonempty findings table."""
import argparse
import os
from datetime import date, timedelta
from sqlalchemy import select
from .db import SessionLocal
from .auth import passwords
from .models import User, Methodology, Finding, Audit, Assessment, AssessmentControl, RiskScore
from .schemas import FindingCreate, Context
from .services import ingest
from .risk.policy import DEFAULT
from .risk.engine import calculate


def seed(demo=False):
    password = os.environ.get('BOOTSTRAP_PASSWORD', '')
    username = os.environ.get('BOOTSTRAP_USER', 'admin')
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.username == username))
        if not user:
            if len(password) < 14:
                raise SystemExit('Set BOOTSTRAP_PASSWORD to at least 14 characters')
            user = User(username=username, role='Administrator', password_hash=passwords.hash(password))
            db.add(user)
            db.flush()
        method = db.scalar(select(Methodology))
        if not method:
            method = Methodology(version='1.0-provisional', configuration=DEFAULT, created_by=user.id)
            db.add(method)
            db.flush()
        if demo and not db.scalar(select(Finding.id).limit(1)):
            assets = ['PAYMENT-API-01', 'FINANCE-SQL-01', 'CUSTOMER-WEB-01', 'IDENTITY-DC-01', 'ERP-APP-01', 'BACKUP-01', 'DEV-BUILD-01', 'QA-WEB-01', 'HR-FILES-01', 'ANALYTICS-01']
            names = ['Remote code execution in web framework', 'Database privilege escalation', 'Authentication bypass in reverse proxy', 'Directory service elevation of privilege', 'Unpatched application runtime', 'Backup agent command injection', 'Build runner insecure permissions', 'TLS configuration weakness', 'File service information disclosure', 'Outdated analytics component', 'HTTP request smuggling', 'Database client library overflow', 'Web server path traversal', 'Kerberos service misconfiguration', 'ERP dependency deserialization', 'Backup console session weakness', 'Development package vulnerable dependency', 'Test service certificate expiry', 'SMB signing not required', 'Analytics debug endpoint exposed']
            for i, name in enumerate(names):
                level = ['Critical', 'Critical', 'Critical', 'Medium', 'High', 'High', 'Medium', 'Low', 'Medium', 'Low'][i % 10]
                score = {'Critical': 9.8, 'High': 8.1, 'Medium': 6.1, 'Low': 3.1}[level]
                critical = i % 10 < 5
                context = Context(asset_criticality='Critical' if critical else 'Medium', business_criticality='Critical' if critical else 'Medium', data_classification='Restricted' if critical else 'Internal', regulatory=['PCI DSS', 'SOC 2'] if i % 10 < 3 else ['SOC 2'], environment='Production' if critical else 'Development', exposure='Internet Facing' if i % 10 in (0, 2) else 'Internal', privileged=critical, critical_process=critical, authentication_required=True, web_applicable=i % 10 in (0, 2, 7), threat_intelligence='High' if critical else 'Low')
                data = FindingCreate(hostname=assets[i % 10], ip=f'10.20.{i % 3}.{10 + i % 10}', os='Ubuntu 24.04 LTS' if i % 2 == 0 else 'Windows Server 2022', plugin_id=f'DEMO-{1000+i}', name=name, cves=[f'DEMO-CVE-{i+1:04}'], cvss=score, vpr=max(0, score - .4), severity=level, exploit_available=level in ('Critical', 'High'), kev=True if i == 0 else False, first_seen=date.today() - timedelta(days=14+i*8), last_seen=date.today(), port=443 if i % 2 == 0 else 445, description='Synthetic demonstration finding. A vulnerable component could allow unauthorized access or disruption depending on asset context.', solution='Apply the vendor-supported update, validate the fix, and rescan the affected asset.', context=context)
                f, _ = ingest(db, data, 'Demo', workspace='Demo')
                if i < 12:
                    controls = []
                    if i in (1, 2, 5, 7, 9, 10):
                        controls.append({'name': 'Network segmentation', 'effectiveness': .5, 'applicable': True, 'validated': True, 'evidence': 'DEMO-NET-104: simulated reachability test confirms restricted paths.', 'notes': 'Synthetic control evidence.'})
                    if i == 2:
                        controls += [{'name': 'WAF', 'effectiveness': .5, 'applicable': True, 'validated': True, 'evidence': 'DEMO-WAF-208: simulated exploit replay blocked.', 'notes': ''}, {'name': 'EDR', 'effectiveness': .35, 'applicable': True, 'validated': True, 'evidence': 'DEMO-EDR-110: simulated response drill.', 'notes': ''}]
                    result = calculate(data.model_dump(mode='json'), context.engine_values(), controls, method.configuration, date.today())
                    result.update({'methodology_id': method.id, 'methodology_version': method.version})
                    f.revision = 1
                    a = Assessment(instance_id=f.id, revision=1, methodology_id=method.id, analyst_id=user.id, context=context.model_dump(), notes='Synthetic demo assessment. Validate context and evidence before operational use.', justification='Demo scenario demonstrates contextual risk and validated controls.', decision='Remediation Required' if result['above_appetite'] else 'Within Risk Appetite', status='Exception Requested' if i == 5 else 'Assessed')
                    db.add(a)
                    db.flush()
                    for c in controls:
                        db.add(AssessmentControl(assessment_id=a.id, component='likelihood', **c))
                    db.add(RiskScore(assessment_id=a.id, result=result))
                    db.add(Audit(actor_id=user.id, action='assessment.seeded', entity='finding', entity_id=f.id, details={'new_residual': result['residual'], 'demo': True}))
            db.add(Audit(actor_id=user.id, action='demo.seeded', entity='system', details={'findings': 20, 'assets': 10}))
        db.commit()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--demo', action='store_true')
    seed(parser.parse_args().demo)
