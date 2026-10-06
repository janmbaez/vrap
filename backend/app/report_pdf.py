"""Shared ReportLab pipeline for executive and campaign evidence reports.

Text is always escaped before Paragraph parsing. Charts are vector drawings and tables
repeat headers and paginate; detail is never clipped to a fixed page count.
"""
from datetime import datetime
from html import escape
from io import BytesIO
import re
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
from reportlab.graphics.shapes import Drawing, Rect, String, Line, Circle

PALETTE = {'Critical': '#c74343', 'High': '#d28b28', 'Medium': '#3d80aa', 'Low': '#519387',
           'Informational': '#8492a2', 'Unknown': '#9a8fa6', 'Reviewed': '#087f79', 'Pending': '#d28b28', 'Skipped': '#8492a2'}
NAVY = colors.HexColor('#173342'); TEAL = colors.HexColor('#087f79'); MUTED = colors.HexColor('#5e7380')
BORDER = colors.HexColor('#d9e3e7'); SOFT = colors.HexColor('#f2f7f8')
WIDTH = 532.8


def text(value):
    value = '' if value is None else str(value)
    value = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', value)
    return escape(value.replace('\u2011', '-').replace('\u2013', '-').replace('\u2014', '-'), quote=True)


def styles():
    sheet = getSampleStyleSheet()
    sheet.add(ParagraphStyle(name='ReportTitle', parent=sheet['Title'], fontName='Helvetica-Bold', fontSize=24, leading=28, textColor=NAVY, alignment=0, spaceAfter=8))
    sheet.add(ParagraphStyle(name='Section', parent=sheet['Heading2'], fontName='Helvetica-Bold', fontSize=13, leading=17, textColor=NAVY, spaceBefore=15, spaceAfter=9, keepWithNext=True))
    sheet.add(ParagraphStyle(name='Muted', parent=sheet['BodyText'], fontSize=9, leading=13, textColor=MUTED, spaceAfter=6))
    sheet.add(ParagraphStyle(name='Compact', parent=sheet['BodyText'], fontSize=8.5, leading=12, textColor=NAVY, splitLongWords=True))
    sheet.add(ParagraphStyle(name='Body', parent=sheet['BodyText'], fontSize=10, leading=15, textColor=NAVY, spaceAfter=7))
    sheet.add(ParagraphStyle(name='CardLabel', parent=sheet['BodyText'], fontSize=8.5, leading=11, textColor=MUTED))
    sheet.add(ParagraphStyle(name='CardValue', parent=sheet['BodyText'], fontName='Helvetica-Bold', fontSize=20, leading=24, textColor=TEAL))
    return sheet


def p(value, sheet, style='Body'):
    return Paragraph(text(value).replace('\n', '<br/>'), sheet[style])


def value(number, unit=None):
    if number is None:
        return 'No data'
    if unit == 'percent':
        return f'{number:.1f}%'
    if isinstance(number, float):
        return f'{number:,.1f}'
    return f'{number:,}' if isinstance(number, int) else str(number)


def section(title, sheet):
    return p(title, sheet, 'Section')


def cards(items, sheet, columns=4):
    rows = []
    for index in range(0, len(items), columns):
        chunk = items[index:index + columns]
        row = [[p(label, sheet, 'CardLabel'), Spacer(1, 6), p(number, sheet, 'CardValue')] for label, number in chunk]
        row += [''] * (columns - len(row)); rows.append(row)
    table = Table(rows, colWidths=[WIDTH / columns] * columns)
    table.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, -1), SOFT), ('BOX', (0, 0), (-1, -1), .6, BORDER),
                              ('INNERGRID', (0, 0), (-1, -1), .5, BORDER), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                              ('LEFTPADDING', (0, 0), (-1, -1), 10), ('RIGHTPADDING', (0, 0), (-1, -1), 10),
                              ('TOPPADDING', (0, 0), (-1, -1), 11), ('BOTTOMPADDING', (0, 0), (-1, -1), 12)]))
    return table


def table(headers, rows, widths, sheet):
    content = [[p(h, sheet, 'Compact') for h in headers]] + [[p(c, sheet, 'Compact') for c in row] for row in rows]
    if not rows:
        content.append([p('No data in this period and scope', sheet, 'Muted')] + [''] * (len(headers) - 1))
    t = Table(content, colWidths=widths, repeatRows=1, splitByRow=1, splitInRow=1)
    t.setStyle(TableStyle([('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dceeed')),
                          ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, SOFT]),
                          ('LINEBELOW', (0, 0), (-1, -1), .4, BORDER), ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                          ('LEFTPADDING', (0, 0), (-1, -1), 8), ('RIGHTPADDING', (0, 0), (-1, -1), 8),
                          ('TOPPADDING', (0, 0), (-1, -1), 7), ('BOTTOMPADDING', (0, 0), (-1, -1), 7)]))
    return t


def bar_chart(rows, field='value', width=WIDTH, max_value=None, percent=False):
    """Compact vector bars with direct labels, zero bars, and graceful no-data state."""
    height = max(68, len(rows) * 31 + 26); drawing = Drawing(width, height)
    numbers = [r.get(field) for r in rows]
    if not rows or all(n is None for n in numbers) or (not percent and not any(n for n in numbers)):
        drawing.add(String(12, height / 2, 'No data in this period and scope', fontSize=10, fillColor=MUTED))
        return drawing
    maximum = max_value or max([n or 0 for n in numbers] + [1])
    left, available = min(155, width * .32), width - min(155, width * .32) - 48
    for index, row in enumerate(rows):
        y = height - 30 - index * 31
        name = str(row.get('name', 'Unknown')); label = name[:25] + '...' if len(name) > 28 else name
        drawing.add(String(0, y + 3, label, fontSize=9, fillColor=NAVY))
        drawing.add(Rect(left, y, available, 16, fillColor=SOFT, strokeColor=None))
        number = row.get(field)
        if number is not None:
            drawing.add(Rect(left, y, available * min(number / maximum, 1), 16, fillColor=colors.HexColor(PALETTE.get(name, '#087f79')), strokeColor=None))
        label_value = 'n/a' if number is None else f'{number:.0f}%' if percent else value(number)
        drawing.add(String(left + available + 7, y + 3, label_value, fontSize=9, fillColor=NAVY))
    return drawing


def line_chart(rows, field='review_coverage', width=WIDTH, height=155):
    d = Drawing(width, height)
    data = [(index, row.get(field)) for index, row in enumerate(rows) if row.get(field) is not None]
    if not data:
        d.add(String(12, 74, 'No historical campaign data', fontSize=10, fillColor=MUTED)); return d
    maximum = max([n for _, n in data] + [100 if field.endswith('coverage') or field=='risk_exposure' else 1])
    x0, y0, w, h = 36, 28, width - 65, height - 52
    d.add(Line(x0, y0, x0 + w, y0, strokeColor=BORDER))
    d.add(String(0, y0, '0', fontSize=8, fillColor=MUTED)); d.add(String(0, y0 + h, f'{maximum:.0f}', fontSize=8, fillColor=MUTED))
    previous = None; previous_index = None
    for index, number in data:
        point = (x0 + index / max(len(rows) - 1, 1) * w, y0 + number / maximum * h)
        if previous and previous_index == index - 1: d.add(Line(*previous, *point, strokeColor=TEAL, strokeWidth=2))
        d.add(Circle(*point, 3, fillColor=TEAL, strokeColor=None)); previous = point; previous_index = index
        d.add(String(point[0] - 8, point[1] + 7, f'{number:.0f}', fontSize=8, fillColor=TEAL))
        if len(rows) <= 8 or index in (0, len(rows) - 1):
            d.add(String(point[0] - 20, 10, str(rows[index].get('period', ''))[:10], fontSize=7, fillColor=MUTED))
    return d


def document(story, title, environment, generated_at):
    output = BytesIO()
    doc = SimpleDocTemplate(output, pagesize=letter, leftMargin=39.6, rightMargin=39.6, topMargin=36,
                            bottomMargin=45, title=title, author='VRAP')
    def footer(canvas, doc):
        canvas.saveState(); canvas.setStrokeColor(BORDER); canvas.line(39.6, 32, 572.4, 32)
        canvas.setFillColor(MUTED); canvas.setFont('Helvetica', 8)
        canvas.drawString(39.6, 18, f'VRAP | {environment} | Confidential')
        canvas.drawRightString(572.4, 18, f'Page {doc.page}'); canvas.restoreState()
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return output.getvalue()


def title_block(title, data, sheet, subtitle=None):
    return [p('VRAP / GOVERNANCE AND RISK', sheet, 'Muted'), p(title, sheet, 'ReportTitle'),
            p(subtitle or f"{data['environment']} | Generated {data['generated_at']}", sheet, 'Muted'), Spacer(1, 12)]


def build_executive_pdf(data):
    s = styles(); summary = data['summary']; gov = data['governance']; g = gov['summary']; posture = data['assessment_posture']
    period = data['period']; story = title_block('Executive vulnerability report', data, s,
        f"{data['environment']} | Review period {period['start']} to {period['end']} | Generated {data['generated_at'][:19]} UTC")
    story.append(cards([('Active findings', value(summary['total_findings'])), ('Critical', value(data['severity']['Critical'])),
                        ('High', value(data['severity']['High'])), ('Affected assets', value(summary['affected_assets'])),
                        ('Average residual risk', value(summary['risk_exposure'])), ('Current assessments', value(summary['assessed'])),
                        ('Review coverage', value(g.get('review_coverage'), 'percent')), ('Reviewed entries', value(g.get('reviewed', 0))),
                        ('Campaign completion', value(g.get('campaign_completion_rate'), 'percent')), ('Overdue campaigns', value(g.get('overdue_campaigns', 0))),
                        ('Pending reviews', value(g.get('pending', 0))), ('Skipped reviews', value(g.get('skipped', 0)))], s))
    story.append(section('Executive position', s)); story.extend(p(sentence, s) for sentence in data['narrative'])
    story += [p(data['statement'], s, 'Muted'), p(f"Risk exceptions: {summary['approved_exceptions']} approved and unexpired. Asset inventory coverage: {value(summary['asset_coverage'], 'percent')}.", s, 'Muted')]
    # A deliberate second page mirrors the dashboard and uses current completed scores.
    story += [PageBreak()] + title_block('Risk and assessment dashboard', data, s)
    story.append(p(f"Organizational risk appetite: {data['methodology'].get('appetite') or 'No methodology'} | Methodology: {data['methodology'].get('version') or 'n/a'}", s, 'Muted'))
    story.append(cards([('Total active findings', value(summary['total_findings']))] + [(name, value(data['severity'][name])) for name in ('Critical', 'High', 'Medium', 'Low')], s, columns=5))
    story += [section('Assessment posture', s), cards([('Above risk appetite', value(posture['above_appetite'])),
                ('Within appetite', value(posture['within_appetite'])), ('Current assessments', value(summary['assessed'])),
                ('Require assessment', value(posture['unassessed']))], s),
              p(f"{value(summary['assessment_coverage'], 'percent')} completed under the current methodology. {posture['draft_assessments']} drafts; {posture['stale_assessments']} stale; {posture['never_assessed']} never assessed. Within appetite does not constitute risk acceptance.", s, 'Muted'),
              section('Residual risk distribution', s),
              bar_chart([{'name': name, 'value': n} for name, n in posture['residual_distribution'].items()]),
              p(f"Population: {summary['assessed']} current completed scored findings. Draft, stale and unassessed findings are excluded.", s, 'Muted')]
    story += [PageBreak()] + title_block('Trends and review governance', data, s)
    story += [section('Review coverage trend', s), line_chart(gov.get('trends', [])), p('Real saved campaign populations by reporting period. No historical estate risk is reconstructed.', s, 'Muted'),
              section('Current versus previous period', s),
              p(f"Current: {period['start']} to {period['end']}. Previous: {period['previous_start']} to {period['previous_end']}. Changes are percentage points for percentages. No previous population is shown as n/a.", s, 'Muted'),
              table(['Metric', 'Current', 'Previous', 'Change / direction'], [[r['label'], value(r['current'], r['unit']),
                    'n/a' if r['previous'] is None else value(r['previous'], r['unit']), 'n/a' if r['change'] is None else f"{r['change']:+.1f} / {r['direction']}"] for r in data['comparisons']], [218, 83, 83, 148.8], s),
              p('Campaign population entries are campaign-specific review obligations. A finding included in two campaigns represents two review obligations.', s, 'Muted')]
    story += [PageBreak()] + title_block('Review governance and historical risk', data, s)
    story += [section('Operational review governance', s),
              cards([('Reviewed', value(g.get('reviewed', 0))), ('Pending', value(g.get('pending', 0))), ('Skipped', value(g.get('skipped', 0))),
                     ('Processed coverage', value(g.get('processed_coverage'), 'percent'))], s),
              p('Frozen campaign population entries: ' + value(g.get('total', 0)) + '. Reviewed only counts as review coverage; processed coverage includes Skipped.', s, 'Muted'),
              section('Coverage by severity', s), bar_chart(gov.get('breakdowns', {}).get('severity', []), field='review_coverage', max_value=100, percent=True),
              section('Campaign snapshot average residual risk', s), line_chart(gov.get('risk_trends', []), field='risk_exposure'),
              p('Saved current completed scores at activation only. These campaign populations do not represent a continuous estate risk trend. Null means no scored snapshot population.', s, 'Muted')]
    story += [PageBreak()] + title_block('Ownership and management attention', data, s)
    for dimension, label in [('business_owner', 'Business owner'), ('it_owner', 'IT remediation owner'), ('application_owner', 'Application owner'), ('asset_group', 'Asset group')]:
        story += [section(label + ' accountability', s), table(['Owner / group', 'Population', 'Reviewed', 'Pending', 'Coverage'],
            [[r['name'], r['total'], r['reviewed'], r['pending'], value(r['review_coverage'], 'percent')]
             for r in gov.get('breakdowns', {}).get(dimension, [])], [248.8, 64, 64, 64, 92], s)]
    story.append(section('Management attention required', s))
    if not data['management_attention']:
        story.append(p('No attention thresholds triggered. No-data populations do not establish compliance.', s))
    for item in data['management_attention']:
        story.append(p(f"{item['severity']}: {item['text']}\nSource: {item['link']}", s))
    story.append(p('Thresholds: overdue > 0; critical pending > 0; campaign coverage < 80%; owner/group coverage < 80% with at least 5 entries; skipped share > 10%; coverage decline >= 10 percentage points.', s, 'Muted'))
    story += [PageBreak()] + title_block('Supporting exposure and campaign detail', data, s)
    story += [section('Most widespread plugins', s), table(['Plugin / vulnerability', 'Findings', 'Critical / High', 'Avg risk', 'Review pending'],
        [[f"{r['name']} (plugin {r['plugin_id'] or 'Manual'})", r['findings'], r['critical_high'], value(r['risk']), r['pending_reviews']] for r in data['top_exposures']], [262.8, 55, 72, 68, 75], s),
        section('Campaign completion trend', s), table(['Period', 'Completed', 'Overdue', 'Incomplete', 'Reviewed entries'],
        [[r['period'], r.get('completed', 0), r.get('overdue', 0), r.get('incomplete', 0), r.get('reviewed', 0)] for r in gov.get('trends', [])], [168.8, 82, 82, 82, 118], s),
        section('Campaign population detail', s), table(['Campaign', 'Period', 'Status', 'Due', 'Review coverage'],
        [[r['name'], f"{r.get('period_start', '')} / {r.get('period_end', '')}", r['status'], r.get('due_date', ''), value((r.get('metrics') or r).get('review_coverage'), 'percent')] for r in gov.get('campaigns', [])], [184.8, 118, 75, 75, 80], s),
        p(data['history_statement'], s, 'Muted')]
    return document(story, data['title'], data['environment'], data['generated_at'])


def build_campaign_pdf(data, findings, evidence, audit):
    s = styles(); m = data['metrics']; story = title_block('Campaign review evidence', data, s)
    story += [section(data['name'], s), p(data.get('description', ''), s),
              p(f"Period {data['period_start']} to {data['period_end']} | Due {data['due_date']} | Status {data['status']} | Campaign {data['id']}", s, 'Muted'),
              cards([('Frozen population', value(m['total'])), ('Reviewed', value(m['reviewed'])), ('Pending', value(m['pending'])), ('Skipped', value(m['skipped'])),
                     ('Review coverage', value(m['review_coverage'], 'percent')), ('Processed coverage', value(m['processed_coverage'], 'percent'))], s, columns=3),
              p('Reviewed / Total is review coverage. Skipped is never counted as reviewed. This evidence records review governance independently of remediation and risk acceptance.', s),
              section('Scope at activation', s), p(data.get('scope_text', '{}'), s, 'Compact'),
              section('Assigned reviewers', s), p(', '.join(data.get('reviewers', [])) or 'No assigned reviewers', s)]
    for dimension, label in [('severity', 'Severity'), ('business_owner', 'Business owner'), ('it_owner', 'IT owner'), ('application_owner', 'Application owner'), ('asset_group', 'Asset group'), ('asset_tag', 'Asset tag'), ('plugin', 'Plugin')]:
        story += [section(label + ' coverage', s), table(['Name', 'Total', 'Reviewed', 'Pending', 'Skipped', 'Coverage'],
             [[r['name'], r['total'], r['reviewed'], r['pending'], r['skipped'], value(r['review_coverage'], 'percent')]
              for r in m.get('breakdowns', {}).get(dimension, [])], [227.8, 50, 60, 60, 55, 80], s)]
    story += [PageBreak()] + title_block('Appendix: frozen population and review evidence', data, s)
    for finding in findings:
        story += [section(f"Finding {finding['finding_id']} | {finding['snapshot_asset']}", s),
            p(f"{finding['snapshot_vulnerability']} | Plugin {finding.get('snapshot_plugin_id') or 'Manual'} | Severity {finding['snapshot_severity']} | Snapshot risk {value(finding.get('snapshot_risk'))}", s),
            p(f"Review: {finding['status']} | Reviewer: {finding.get('reviewer') or 'Pending'} | Time: {finding.get('reviewed_at') or 'n/a'} | Decision: {finding.get('decision') or finding.get('skip_reason') or 'n/a'}", s),
            p(f"Business: {finding.get('snapshot_business_owner') or 'Unassigned'} | IT: {finding.get('snapshot_it_owner') or 'Unassigned'} | Application: {finding.get('snapshot_application_owner') or 'Unassigned'} | Asset group: {finding.get('snapshot_asset_group') or 'Unassigned'}", s, 'Compact'),
            p('Tags: ' + ', '.join(map(str, finding.get('snapshot_tags', []))) + '\nRegulatory: ' + ', '.join(map(str, finding.get('snapshot_regulatory', []))), s, 'Compact'),
            p('Notes: ' + (finding.get('notes') or 'None') + '\nEvidence references: ' + '\n'.join(finding.get('evidence_references', [])), s, 'Compact')]
    story += [PageBreak(), section('Campaign evidence references', s),
              table(['Finding', 'Reference / note', 'Added by / time'], [[r.get('finding_id') or 'Campaign', r.get('reference', '') + '\n' + r.get('notes', ''), r['actor'] + '\n' + r['created_at']] for r in evidence], [70, 302.8, 160], s),
              section('Audit trail', s), table(['When / actor', 'Action', 'Previous / new values and population references'],
                [[r['created_at'] + '\n' + r['actor'], r['action'], r['details_text']] for r in audit], [135, 130, 267.8], s)]
    return document(story, 'VRAP Campaign Evidence', data['environment'], data['generated_at'])
