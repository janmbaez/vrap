"""Deterministic scoring: inputs + immutable policy + as_of => explainable result."""
from datetime import date
from math import sqrt, ceil
from copy import deepcopy

def classify(score, policy):
    return next(t['name'] for t in reversed(policy['thresholds']) if score >= t['min'])

def calculate(technical: dict, context: dict, controls: list, policy: dict, as_of: date):
    unknown = []
    weighted = [(technical.get(k), w) for k, w in policy['technical_weights'].items() if technical.get(k) is not None and w > 0]
    base = sum(v * 10 * w for v, w in weighted) / sum(w for _, w in weighted) if weighted else policy['severity_map'].get(technical.get('severity'), policy['unknown_score'])
    if not weighted:
        unknown.append('cvss/vpr: severity fallback')
    values = {**context, **{k: technical.get(k) for k in ('exploit_available', 'kev')}}
    try:
        values['age_days'] = max(0, (as_of - date.fromisoformat(str(technical['first_seen'])[:10])).days)
    except (KeyError, TypeError, ValueError):
        values['age_days'] = None
    components = {}
    trace = []
    for component in ('likelihood', 'impact'):
        factors = [f for f in policy['factors'] if f['component'] == component]
        total_weight = sum(f['weight'] for f in factors)
        for factor in factors:
            key, kind = factor['key'], factor['kind']
            value = values.get(key)
            missing = value is None or value == '' or value == []
            if kind == 'technical':
                score, missing = base, False
            elif missing:
                score = policy['unknown_score']
                unknown.append(key)
            elif kind == 'boolean':
                score = factor['true_score'] if value is True else factor['false_score']
            elif kind == 'mapping':
                score = factor['values'].get(str(value), policy['unknown_score'])
                if str(value) not in factor['values']:
                    missing = True
                    unknown.append(key)
            elif kind == 'multi':
                score = max((factor['values'].get(v, policy['unknown_score']) for v in value), default=policy['unknown_score'])
            else:
                score = min(100, max(0, float(value) / factor['scale'] * 100))
            contribution = score * factor['weight'] / total_weight
            components[component] = components.get(component, 0) + contribution
            trace.append({'factor': key, 'component': component, 'value': value if kind != 'technical' else base, 'unknown': missing, 'score': score, 'weight': factor['weight'], 'contribution': contribution})
    inherent = sqrt(components['likelihood'] * components['impact'])
    adjusted = components.copy()
    control_trace = []
    rules = {r['name']: r for r in policy['controls']}
    for control in sorted(controls, key=lambda c: c['name']):
        rule = rules.get(control['name'])
        reason = None
        if not rule:
            reason = 'Not defined in methodology'
        elif not control.get('validated'):
            reason = 'Not validated'
        elif not control.get('evidence', '').strip():
            reason = 'Evidence required'
        elif not control.get('applicable'):
            reason = 'Applicability not confirmed'
        elif rule.get('requires') and context.get(rule['requires']) is not True:
            reason = f"Requires {rule['requires']}"
        before_score = sqrt(adjusted['likelihood'] * adjusted['impact'])
        reduction = 0
        if not reason:
            component = rule['component']
            reduction = min(control['effectiveness'], rule['max_effectiveness'])
            adjusted[component] = max(components[component] * (1 - policy['max_control_reduction']), adjusted[component] * (1 - reduction))
        control_trace.append({'name': control['name'], 'component': rule['component'] if rule else None, 'applied': reason is None, 'reason': reason, 'effectiveness': reduction, 'score_delta': sqrt(adjusted['likelihood'] * adjusted['impact']) - before_score})
    residual = sqrt(adjusted['likelihood'] * adjusted['impact'])
    matrix_policy = policy.get('grc_matrix', {})
    inherent_likelihood = int(context.get('inherent_likelihood_override') or max(1, min(5, ceil(components['likelihood'] / 20))))
    inherent_impact = int(context.get('inherent_impact_override') or max(1, min(5, ceil(components['impact'] / 20))))
    applied_controls = [c for c in sorted(controls, key=lambda item: item['name'])
                        if c.get('validated') and c.get('applicable') and c.get('evidence', '').strip()
                        and c.get('design_maturity') is not None and c.get('operating_effectiveness') is not None]
    if applied_controls:
        weight_total = sum(max(0.01, float(c.get('effectiveness', 0))) for c in applied_controls)
        design = sum(c['design_maturity'] * max(0.01, float(c.get('effectiveness', 0))) for c in applied_controls) / weight_total
        operating = sum(c['operating_effectiveness'] * max(0.01, float(c.get('effectiveness', 0))) for c in applied_controls) / weight_total
    else:
        design = operating = 1.0
    gross_strength = max(2, min(10, round(design + operating)))
    remaining_factor = float(matrix_policy.get('remaining_risk_factors', {}).get(str(gross_strength), 0.95))
    matrix_inherent = inherent_likelihood * inherent_impact
    matrix_residual = matrix_inherent * remaining_factor
    bands = matrix_policy.get('bands', [])
    matrix_level = next((band['name'] for band in bands if band['min'] <= matrix_residual <= band['max']), 'Critical')
    matrix_result = {
        'inherent_likelihood': inherent_likelihood, 'inherent_impact': inherent_impact,
        'inherent_risk': matrix_inherent, 'control_design_maturity': design,
        'control_operating_effectiveness': operating, 'gross_control_strength': gross_strength,
        'remaining_risk_factor': remaining_factor, 'residual_risk': matrix_residual,
        'residual_level': matrix_level, 'authorized_tolerance': matrix_policy.get('authorized_tolerance', 9.999999),
        'above_tolerance': matrix_residual > matrix_policy.get('authorized_tolerance', 9.999999),
        'recommended_decision': 'Remediate' if matrix_residual > matrix_policy.get('authorized_tolerance', 9.999999) else 'Accept',
        'source': 'Jan TVM Risk Analysis.xlsx crosswalk',
    }
    rank = [x['name'] for x in policy['thresholds']]
    residual_level = classify(residual, policy)
    missing_required = [key for key in policy['required_context'] if context.get(key) is None or context.get(key) == '' or context.get(key) == []]
    return {'engine_version': policy['engine_version'], 'as_of': as_of.isoformat(), 'technical': base,
            'inherent': inherent, 'inherent_level': classify(inherent, policy), 'residual': residual,
            'residual_level': residual_level, 'appetite': policy['appetite'],
            'above_appetite': rank.index(residual_level) > rank.index(policy['appetite']),
            'components_before': components, 'components_after': adjusted, 'factors': trace,
            'controls': control_trace, 'unknowns': sorted(set(unknown)), 'missing_required': missing_required,
            'grc_matrix': matrix_result,
            'inputs': {'technical': deepcopy(technical), 'context': deepcopy(context),
                       'controls': deepcopy(sorted(controls, key=lambda control: control['name']))}}
