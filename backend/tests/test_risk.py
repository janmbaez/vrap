from copy import deepcopy
from datetime import date
from math import isclose
import pytest
from pydantic import ValidationError
from app.risk.engine import calculate, classify
from app.risk.policy import DEFAULT
from app.schemas import Policy, Context
TECH = {'cvss':9.8,'vpr':9.4,'severity':'Critical','exploit_available':True,'kev':True,'first_seen':'2026-01-01'}
CTX = {'asset_criticality':'Critical','business_criticality':'Critical','data_classification':'Restricted','regulatory':['PCI DSS'],'environment':'Production','production':True,'exposure':'Internet Facing','privileged':True,'critical_process':True,'threat_intelligence':'High','web_applicable':True,'authentication_required':True}
def calc(controls=None,ctx=None,tech=None): return calculate(tech or TECH, ctx if ctx is not None else CTX, controls or [], DEFAULT, date(2026,9,30))
def control(name='WAF',**kw): return {'name':name,'validated':True,'applicable':True,'effectiveness':.5,'evidence':'Verified test','notes':'',**kw}
def test_policy_and_boundaries():
    Policy(**DEFAULT)
    assert [classify(x,DEFAULT) for x in [0,24.999,25,49.999,50,74.999,75,100]] == ['Low','Low','Medium','Medium','High','High','Critical','Critical']
def test_critical_scenarios():
    assert calc()['residual_level']=='Critical'
    assert calc([control('Network segmentation')])['residual_level']=='High'
    assert calc([control('Network segmentation'),control('WAF'),control('EDR',effectiveness=.35)])['residual_level']=='Medium'
    assert calc(tech={**TECH,'cvss':6.1,'vpr':6.1,'severity':'Medium'})['inherent_level'] in ('High','Critical')
@pytest.mark.parametrize('patch',[{'validated':False},{'applicable':False},{'evidence':''}])
def test_unvalidated_controls_do_not_reduce(patch): assert calc([control(**patch)])['residual']==calc()['inherent']
def test_scenario_gating_and_component_scope():
    assert calc([control()],ctx={**CTX,'web_applicable':False})['residual']==calc()['inherent']
    r=calc([control('Tested backups')])
    assert r['components_before']['likelihood']==r['components_after']['likelihood']
    assert r['components_after']['impact']<r['components_before']['impact']
def test_unknown_not_false():
    r=calc(ctx={}); assert 'exposure' in r['unknowns'] and 'exposure' in r['missing_required']
    assert calc(tech={**TECH,'kev':None})['inherent']>calc(tech={**TECH,'kev':False})['inherent']
def test_reproducibility_trace_and_caps():
    controls=[control(r['name'],effectiveness=1) for r in DEFAULT['controls']];r=calc(controls)
    assert r==calc(list(reversed(controls)))
    for component in ['likelihood','impact']:
        assert isclose(sum(f['contribution'] for f in r['factors'] if f['component']==component),r['components_before'][component])
        assert r['components_after'][component]>=r['components_before'][component]*(1-DEFAULT['max_control_reduction'])-1e-9
    assert isclose(r['inherent']+sum(c['score_delta'] for c in r['controls']),r['residual'])
def test_invalid_policy_and_contradictions():
    p=deepcopy(DEFAULT);p['thresholds'][1]['min']=80
    with pytest.raises(ValidationError): Policy(**p)
    with pytest.raises(ValidationError): Context(environment='Production',production=False)
    with pytest.raises(ValidationError): Context(regulatory=['None','PCI DSS'])

@pytest.mark.parametrize('design,operating,residual,level,decision', [
    (5, 5, 1.25, 'Informational', 'Accept'),
    (3, 3, 9.0, 'Medium', 'Accept'),
    (2, 3, 12.5, 'High', 'Remediate'),
])
def test_grc_spreadsheet_crosswalk(design, operating, residual, level, decision):
    context = {**CTX, 'inherent_likelihood_override': 5, 'inherent_impact_override': 5}
    result = calc([control(design_maturity=design, operating_effectiveness=operating)], ctx=context)['grc_matrix']
    assert result['inherent_risk'] == 25
    assert result['gross_control_strength'] == design + operating
    assert result['residual_risk'] == residual
    assert result['residual_level'] == level
    assert result['recommended_decision'] == decision
    assert result['above_tolerance'] == (decision == 'Remediate')
