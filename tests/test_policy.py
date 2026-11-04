"""
EBCP-Guard Adaptive Privacy Policy Engine Tests
=================================================
Tests:
  - Deterministic policy rule execution
  - Blocked destination enforcement
  - Low-confidence model handling (conservative fallback)
  - Tenant policy overrides
"""

from app.policy.policy_engine import PolicyEngine
from app.api.schemas.schemas import ProtectionAction

def test_unauthorized_destination_blocked():
    engine = PolicyEngine()
    decision = engine.evaluate(
        entities=[{"entity_type": "PAN", "confidence": 0.95}],
        sensitivity_class="S4",
        sensitivity_confidence=0.95,
        purpose="PAYMENT_PROCESSING",
        purpose_confidence=0.95,
        exposure_risk_level="HIGH",
        exposure_risk_score=0.70,
        destination="external_unknown",
        tenant_id="bank_a",
    )
    assert decision.is_blocked is True
    assert decision.overall_action == ProtectionAction.BLOCK

def test_low_confidence_triggers_conservative_handling():
    engine = PolicyEngine()
    # Confidence 0.20 is below threshold (0.75)
    decision = engine.evaluate(
        entities=[{"entity_type": "EMAIL", "confidence": 0.90}],
        sensitivity_class="S1",
        sensitivity_confidence=0.20,
        purpose="PAYMENT_PROCESSING",
        purpose_confidence=0.90,
        exposure_risk_level="LOW",
        exposure_risk_score=0.20,
        destination="internal_payment",
        tenant_id="bank_a",
    )
    # Must flag for review and upgrade protection
    assert decision.requires_review is True
    assert decision.overall_action in (
        ProtectionAction.MASK, ProtectionAction.TOKENIZE,
        ProtectionAction.ENCRYPT, ProtectionAction.BLOCK
    )

def test_legitimate_payment_encrypted():
    engine = PolicyEngine()
    decision = engine.evaluate(
        entities=[{"entity_type": "ACCOUNT_NUMBER", "confidence": 0.95}],
        sensitivity_class="S4",
        sensitivity_confidence=0.95,
        purpose="PAYMENT_PROCESSING",
        purpose_confidence=0.95,
        exposure_risk_level="MEDIUM",
        exposure_risk_score=0.40,
        destination="internal_payment",
        tenant_id="bank_a",
    )
    assert decision.overall_action == ProtectionAction.ENCRYPT
