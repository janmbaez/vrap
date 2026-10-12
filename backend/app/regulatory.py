"""Governed regulatory-scope membership helpers.

The asset JSON context remains a compatibility projection while the membership
records provide the provenance and lifecycle needed for auditability.
"""
from sqlalchemy import select
from .models import AssetRegulatoryScope


def normalize_scopes(values):
    return sorted({str(value).strip() for value in (values or [])
                   if value and str(value).strip() and str(value).strip() != 'None'})


def legacy_scopes(asset):
    return set(normalize_scopes((asset.context or {}).get('regulatory', [])))


def active_scopes(db, asset):
    persisted = set(db.scalars(select(AssetRegulatoryScope.scope).where(
        AssetRegulatoryScope.asset_id == asset.id,
        AssetRegulatoryScope.active.is_(True),
    )).all())
    # During the additive migration, retain legacy JSON scope values even if an
    # old row has not been backfilled yet.
    return persisted | legacy_scopes(asset)


def add_scope_memberships(db, asset, scopes, *, source_system, approval_state='Pending verification', source_record_id=None, verified_by=None, verified_at=None):
    requested = set(normalize_scopes(scopes))
    persisted = set(db.scalars(select(AssetRegulatoryScope.scope).where(
        AssetRegulatoryScope.asset_id == asset.id,
        AssetRegulatoryScope.active.is_(True),
    )).all())
    for scope in requested - persisted:
        existing = db.scalar(select(AssetRegulatoryScope).where(
            AssetRegulatoryScope.asset_id == asset.id,
            AssetRegulatoryScope.scope == scope,
        ))
        if existing:
            # Reactivate the original membership so its identity and historical
            # approval/provenance remain intact; removal history is retained.
            existing.active = True
            existing.removed_at = None
            existing.source_system = source_system
            if source_record_id is not None:
                existing.source_record_id = source_record_id
            existing.approval_state = approval_state
            existing.verified_by = verified_by
            existing.verified_at = verified_at
        else:
            db.add(AssetRegulatoryScope(
                asset_id=asset.id, scope=scope, source_system=source_system,
                source_record_id=source_record_id, approval_state=approval_state,
                verified_by=verified_by, verified_at=verified_at,
            ))
    return active_scopes(db, asset) | requested
