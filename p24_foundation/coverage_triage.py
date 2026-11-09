"""LC2E: conservative review triage for root APIs with unknown Viewer roles.

Triage does NOT classify manual initiation, payment finality, a new
BehaviorOccurrence, or invoke any financial system. It only partitions the
currently indexed, otherwise-unanchored HTTP roots for evidence review.
"""
from __future__ import annotations

from .service_journey import _root_role


REVIEW_TYPES = {
    'known_payment_or_system_step': (
        'Known payment/system stage; inspect typed binding to an existing journey; do not count as a new action.'),
    'known_technical_support_step': (
        'Known catalog/status/support lookup; view as a supporting step, not a confirmed customer gesture.'),
    'public_information_api_unverified': (
        'Public content/information request; source and initiation must be verified before behavioral attribution.'),
    'file_delivery_api_unverified': (
        'File delivery; establish service context and initiator before treating this as customer behavior.'),
    'account_or_app_api_unverified': (
        'Account/app route; determine read vs mutation, initiator and evidence from source before semantic promotion.'),
    'core_misc_api_unverified': (
        'Core route; distinguish setup, background reads and possible customer operations using source/evidence.'),
    'external_channel_api_unverified': (
        'External order/payment flow; do not infer customer debit or independent manual action.'),
    'service_auxiliary_api_unverified': (
        'Service facade without independent anchor; inspect source and owner semantics.'),
    'root_missing_or_unrecognized': (
        'Missing/invalid root; inspect ingestion identity, provenance and multi-root evidence.'),
    'other_unverified': (
        'Other API; requires source/evidence classification.'),
}


def unanchored_review_queue(root: str) -> str:
    """Route an observed root to an evidence-review queue, not a behavior label."""
    if root == '[unrecognized_or_missing_root]':
        return 'root_missing_or_unrecognized'
    role = _root_role(root, None)
    if role in ('payment_execution', 'system_followup'):
        return 'known_payment_or_system_step'
    if role in ('support_status_lookup', 'support_catalog_lookup', 'support'):
        return 'known_technical_support_step'
    if root.startswith('Public.v'):
        return 'public_information_api_unverified'
    if root.startswith('Files.'):
        return 'file_delivery_api_unverified'
    if root.startswith('Core.v') and root.split('/',1)[-1].startswith(('User','Device')):
        return 'account_or_app_api_unverified'
    if root.startswith('Core.v'):
        return 'core_misc_api_unverified'
    if root.startswith('Ewano.'):
        return 'external_channel_api_unverified'
    if root.startswith('Services.v'):
        return 'service_auxiliary_api_unverified'
    return 'other_unverified'
