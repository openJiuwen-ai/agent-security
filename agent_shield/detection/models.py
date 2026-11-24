# -*- coding: UTF-8 -*-
# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.

"""
Guardrail Framework Data Models

Defines data structures and dataclasses for guardrail detection and risk assessment.
"""

from dataclasses import dataclass
from typing import (
    Any,
    Dict,
    Optional,
)

from .enums import RiskLevel


@dataclass
class GuardrailResult:
    """Result of guardrail detection.

    Contains the detection outcome, risk level, and optional details.

    Attributes:
        is_safe: Whether the content passed the guardrail check. False means risk
            was detected; it does not mean the call was blocked.
        risk_level: The severity level of detected risk.
        risk_type: Optional identifier for the type of risk detected.
        confidence: Confidence score (0.0 to 1.0) from the backend.
        details: Optional dictionary with detailed detection information.
        modified_data: Optional modified/sanitized version of the data.
        event: Name of the event that triggered this detection.
    """

    is_safe: bool
    risk_level: RiskLevel
    risk_type: Optional[str] = None
    confidence: float = 0.0
    details: Optional[Dict[str, Any]] = None
    modified_data: Optional[Dict[str, Any]] = None
    event: Optional[str] = None

    @classmethod
    def pass_(cls, details: Optional[Dict[str, Any]] = None) -> "GuardrailResult":
        """Create a pass result.

        Args:
            details: Optional detection details.

        Returns:
            GuardrailResult with is_safe=True and risk_level=SAFE.
        """
        return cls(
            is_safe=True,
            risk_level=RiskLevel.SAFE,
            details=details
        )

    @classmethod
    def block(
            cls,
            risk_level: RiskLevel,
            risk_type: str,
            details: Optional[Dict[str, Any]] = None,
            modified_data: Optional[Dict[str, Any]] = None
    ) -> "GuardrailResult":
        """Create an unsafe result.

        This is a result object marking is_safe=False; it does not perform
        execution blocking by itself.

        Args:
            risk_level: The severity level of the risk.
            risk_type: Identifier for the type of risk.
            details: Optional detection details.
            modified_data: Optional sanitized version of data.

        Returns:
            GuardrailResult with is_safe=False.
        """
        return cls(
            is_safe=False,
            risk_level=risk_level,
            risk_type=risk_type,
            details=details,
            modified_data=modified_data
        )


@dataclass
class RiskAssessment:
    """Result of risk analysis from a guardrail backend.

    This is the output format from detection backends, which will be
    converted to GuardrailResult by the guardrail framework.

    Attributes:
        has_risk: Whether risk was detected.
        risk_level: The severity level of detected risk.
        risk_type: Identifier for the type of risk.
        confidence: Confidence score (0.0 to 1.0).
        details: Detailed analysis information.
    """

    has_risk: bool
    risk_level: RiskLevel
    risk_type: Optional[str] = None
    confidence: float = 0.0
    details: Optional[Dict[str, Any]] = None


def to_guardrail_result(assessment: RiskAssessment) -> GuardrailResult:
    """Convert a backend RiskAssessment to a GuardrailResult.

    Preserves the backend's confidence score, unlike the pre-migration
    detect() path which discarded it.

    Args:
        assessment: The RiskAssessment produced by a backend's analyze().

    Returns:
        GuardrailResult carrying the assessment's fields.
    """
    return GuardrailResult(
        is_safe=not assessment.has_risk,
        risk_level=assessment.risk_level,
        risk_type=assessment.risk_type,
        confidence=assessment.confidence,
        details=assessment.details,
    )
