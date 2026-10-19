from datetime import date, datetime, timedelta, timezone

from app.kpis import calculate_kpis, evaluate_sla
from app.models import Asset, Finding, FindingWorkflow, RemediationSLAPolicy, Vulnerability


def test_sla_defaults_overlap_closed_and_distinct_denominators(db):
    today = date(2026, 10, 19)
    vuln = Vulnerability(identity='sla-high', name='High', plugin_id='sla-high', technical={'severity': 'High'})
    low = Vulnerability(identity='sla-low', name='Low', plugin_id='sla-low', technical={'severity': 'Low'})
    db.add_all([vuln, low]); db.flush()
    pci = Asset(hostname='pci', workspace='Production', context={'regulatory': ['PCI DSS', 'SOC 2']})
    other = Asset(hostname='other', workspace='Production', context={'regulatory': ['SOC 2']})
    hidden = Asset(hostname='hidden', workspace='Demo', context={'regulatory': ['PCI DSS']})
    db.add_all([pci, other, hidden]); db.flush()
    findings = [
        Finding(asset_id=pci.id, vulnerability_id=vuln.id, source='test', workspace='Production',
                observed={'severity': 'High', 'first_seen': '2026-09-01'}, source_last_seen=today),
        Finding(asset_id=other.id, vulnerability_id=vuln.id, source='test', workspace='Production',
                observed={'severity': 'High', 'first_seen': '2026-09-01'}, source_last_seen=today),
        Finding(asset_id=other.id, vulnerability_id=low.id, source='test', workspace='Production',
                observed={'severity': 'Low', 'first_seen': '2026-01-01'}, source_last_seen=today),
        Finding(asset_id=pci.id, vulnerability_id=low.id, source='test', workspace='Production',
                observed={'severity': 'Low', 'first_seen': '2026-01-01'}, source_last_seen=today),
        Finding(asset_id=hidden.id, vulnerability_id=vuln.id, source='test', workspace='Demo',
                observed={'severity': 'High', 'first_seen': '2026-01-01'}),
    ]
    db.add_all(findings); db.flush()
    db.add(FindingWorkflow(finding_id=findings[3].id, status='Closed', updated_by=1,
                           remediation_due_at=datetime(2026, 2, 1, tzinfo=timezone.utc)))
    db.commit()
    as_of = datetime(2026, 10, 19, tzinfo=timezone.utc)
    sla = evaluate_sla(db, 'Production', as_of)
    assert [row['sla_days'] for row in sla['items']] == [30, 60, None, 180]
    assert [row['overdue'] for row in sla['items']] == [True, False, False, False]
    assert sla['total'] == 4 and sla['overdue'] == 1
    assert sla['sla_applicable'] == 2 and sla['sla_compliant'] == 1 and sla['sla_compliance_percent'] == 50
    assert sla['items'][2]['monitored'] is True and sla['items'][0]['first_seen'] == '2026-09-01'
    kpis = calculate_kpis(db, 'Production', as_of)
    assert (kpis['total_findings'], kpis['distinct_vulnerabilities'], kpis['unique_affected_assets']) == (4, 2, 2)
    assert kpis['backlog_aging'] == 3 and kpis['backlog_denominator'] == 4
    assert kpis['overdue'] == 0 and kpis['sla_overdue'] == 1
    assert calculate_kpis(db, 'Demo', as_of)['total_findings'] == 1


def test_sla_uses_latest_approved_effective_policy_and_unknown_age(db):
    today = date(2026, 10, 19)
    vuln = Vulnerability(identity='sla-policy', name='High policy', plugin_id='policy', technical={'severity': 'High'})
    asset = Asset(hostname='policy-asset', workspace='Production', context={'regulatory': ['SOC 2']})
    db.add_all([vuln, asset]); db.flush()
    db.add(Finding(asset_id=asset.id, vulnerability_id=vuln.id, source='test', workspace='Production', observed={'severity': 'High'}))
    for version, days, approved, effective in [(1, 20, True, today-timedelta(days=1)),
                                                (2, 45, True, today-timedelta(days=1)),
                                                (3, 5, False, today-timedelta(days=1)),
                                                (4, 10, True, today+timedelta(days=1))]:
        db.add(RemediationSLAPolicy(workspace='Production', version=version, name=f'v{version}',
                                    regulatory_scope='SOC 2', severity='High', days=days,
                                    approved=approved, effective_from=effective, created_by=1))
    db.commit()
    result = evaluate_sla(db, 'Production', datetime(2026, 10, 19, tzinfo=timezone.utc))
    row = result['items'][0]
    assert row['sla_days'] == 45 and row['first_seen'] is None and row['due_date'] is None
    assert result['sla_applicable'] == 0 and result['sla_compliance_percent'] == 0
