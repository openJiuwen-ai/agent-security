# -*- coding: UTF-8 -*-
# Copyright (c) Huawei Technologies Co., Ltd. 2025. All rights reserved.

"""
Tests for guardrail model output parsers (BERT binary and QwenGuard).
"""

from agent_shield.detection import (
    BertBinaryParser,
    QwenGuardParser,
    RiskLevel,
)


class TestBertBinaryParser:
    """Tests for BertBinaryParser."""

    @staticmethod
    def test_parse_with_predicted_class_attack():
        """Test parsing with predicted_class=1 (attack)."""
        parser = BertBinaryParser()
        result = parser.parse({"predicted_class": 1, "confidence": 0.95})
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.HIGH

    @staticmethod
    def test_parse_with_predicted_class_safe():
        """Test parsing with predicted_class=0 (safe)."""
        parser = BertBinaryParser()
        result = parser.parse({"predicted_class": 0, "confidence": 0.95})
        assert result.has_risk is False
        assert result.risk_level == RiskLevel.SAFE

    @staticmethod
    def test_parse_with_label_attack():
        """Test parsing with label=1 (attack)."""
        parser = BertBinaryParser()
        result = parser.parse({"label": 1, "score": 0.97})
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.HIGH

    @staticmethod
    def test_parse_with_logits_attack():
        """Test parsing with logits predicting attack."""
        parser = BertBinaryParser()
        result = parser.parse({"logits": [-2.0, 5.0]})
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.HIGH

    @staticmethod
    def test_parse_with_logits_safe():
        """Test parsing with logits predicting safe."""
        parser = BertBinaryParser()
        result = parser.parse({"logits": [2.0, 0.5]})
        assert result.has_risk is False
        assert result.risk_level == RiskLevel.SAFE

    @staticmethod
    def test_parse_with_probabilities_attack():
        """Test parsing with probabilities predicting attack."""
        parser = BertBinaryParser()
        result = parser.parse({"probabilities": [0.02, 0.98]})
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.HIGH

    @staticmethod
    def test_parse_with_probabilities_safe():
        """Test parsing with probabilities predicting safe."""
        parser = BertBinaryParser()
        result = parser.parse({"probabilities": [0.9, 0.1]})
        assert result.has_risk is False
        assert result.risk_level == RiskLevel.SAFE

    @staticmethod
    def test_parse_with_list_attack():
        """Test parsing with list output predicting attack."""
        parser = BertBinaryParser()
        result = parser.parse([0.2, 0.8])
        assert result.has_risk is True
        assert result.confidence == 0.8

    @staticmethod
    def test_parse_with_list_safe():
        """Test parsing with list output predicting safe."""
        parser = BertBinaryParser()
        result = parser.parse([0.8, 0.2])
        assert result.has_risk is False
        assert result.risk_level == RiskLevel.SAFE

    @staticmethod
    def test_low_confidence_attack_returns_safe():
        """Test low confidence attack returns SAFE (reduce false positive)."""
        parser = BertBinaryParser()
        result = parser.parse({"predicted_class": 1, "confidence": 0.6})
        assert result.has_risk is False
        assert result.risk_level == RiskLevel.SAFE

    @staticmethod
    def test_confidence_threshold_low():
        """Test confidence in low range."""
        parser = BertBinaryParser()
        result = parser.parse({"predicted_class": 1, "confidence": 0.75})
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.LOW

    @staticmethod
    def test_confidence_threshold_medium():
        """Test confidence in medium range."""
        parser = BertBinaryParser()
        result = parser.parse({"predicted_class": 1, "confidence": 0.9})
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.MEDIUM

    @staticmethod
    def test_confidence_threshold_high():
        """Test confidence in high range."""
        parser = BertBinaryParser()
        result = parser.parse({"predicted_class": 1, "confidence": 0.97})
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.HIGH

    @staticmethod
    def test_custom_thresholds():
        """Test custom confidence thresholds."""
        parser = BertBinaryParser(
            confidence_thresholds={"low": 0.8, "medium": 0.9, "high": 0.98}
        )
        result = parser.parse({"predicted_class": 1, "confidence": 0.85})
        assert result.risk_level == RiskLevel.LOW

    @staticmethod
    def test_custom_risk_type():
        """Test custom risk type."""
        parser = BertBinaryParser(risk_type="prompt_injection")
        result = parser.parse({"predicted_class": 1, "confidence": 0.95})
        assert result.risk_type == "prompt_injection"

    @staticmethod
    def test_parse_empty_output():
        """Test parsing empty output."""
        parser = BertBinaryParser()
        result = parser.parse({})
        assert result.has_risk is False
        assert result.risk_level == RiskLevel.SAFE

    @staticmethod
    def test_custom_attack_class_id():
        """Test custom attack class id."""
        parser = BertBinaryParser(attack_class_id=0)
        result = parser.parse({"predicted_class": 0, "confidence": 0.95})
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.HIGH


class TestQwenGuardParser:
    """Tests for QwenGuardParser."""

    @staticmethod
    def test_parse_standard_format_unsafe():
        """Test parsing standard format with Unsafe safety."""
        parser = QwenGuardParser()
        result = parser.parse("""Safety: Unsafe
Categories: Violent""")
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.HIGH
        assert result.risk_type == "Violent"
        assert result.details["safety"] == "Unsafe"
        assert "Violent" in result.details["categories"]

    @staticmethod
    def test_parse_standard_format_safe():
        """Test parsing standard format with Safe safety."""
        parser = QwenGuardParser()
        result = parser.parse("""Safety: Safe
Categories:""")
        assert result.has_risk is False
        assert result.risk_level == RiskLevel.SAFE
        assert result.details["safety"] == "Safe"

    @staticmethod
    def test_parse_standard_format_controversial():
        """Test parsing standard format with Controversial safety."""
        parser = QwenGuardParser()
        result = parser.parse("""Safety: Controversial
Categories: Political""")
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.MEDIUM
        assert result.risk_type == "Political"

    @staticmethod
    def test_parse_standard_format_multiple_categories():
        """Test parsing standard format with multiple categories."""
        parser = QwenGuardParser()
        result = parser.parse("""Safety: Unsafe
Categories: Violent, Sexual, Hate""")
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.HIGH
        assert result.risk_type == "Violent"
        assert len(result.details["categories"]) == 3

    @staticmethod
    def test_parse_dict_standard_format():
        """Test parsing dict with safety/categories fields."""
        parser = QwenGuardParser()
        result = parser.parse({
            "safety": "Unsafe",
            "categories": ["Violent", "Hate"]
        })
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.HIGH
        assert result.risk_type == "Violent"

    @staticmethod
    def test_parse_dict_standard_format_string_categories():
        """Test parsing dict with categories as string."""
        parser = QwenGuardParser()
        result = parser.parse({
            "safety": "Unsafe",
            "categories": "Violent, Sexual"
        })
        assert result.has_risk is True
        assert result.risk_type == "Violent"
        assert len(result.details["categories"]) == 2

    @staticmethod
    def test_parse_standard_format_case_insensitive():
        """Test parsing standard format is case insensitive."""
        parser = QwenGuardParser()
        result = parser.parse("""safety: unsafe
categories: violent""")
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.HIGH

    @staticmethod
    def test_parse_legacy_full_format():
        """Test parsing legacy full format."""
        parser = QwenGuardParser()
        result = parser.parse({
            "analysis": {
                "risk_level": "unsafe",
                "risk_categories": ["hate_speech"],
                "evidence": "Test evidence",
                "language": "zh"
            },
            "decision": "block",
            "version": "qwen3guard-gen-8b-v1.0"
        })
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.HIGH
        assert result.risk_type == "hate_speech"

    @staticmethod
    def test_parse_legacy_simple_format():
        """Test parsing legacy simple format."""
        parser = QwenGuardParser()
        result = parser.parse({
            "judgment": "Unsafe",
            "reason": "Test reason",
            "language": "zh"
        })
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.HIGH

    @staticmethod
    def test_parse_legacy_api_format():
        """Test parsing legacy API format."""
        parser = QwenGuardParser()
        result = parser.parse({
            "severity_level": "unsafe",
            "reason": "Test reason",
            "language": "zh"
        })
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.HIGH

    @staticmethod
    def test_parse_text_with_keywords():
        """Test parsing text with safety keywords."""
        parser = QwenGuardParser()
        result = parser.parse("This content is unsafe and should be blocked")
        assert result.has_risk is True
        assert result.risk_level == RiskLevel.HIGH

    @staticmethod
    def test_parse_fallback():
        """Test parsing with unknown format falls back to safe."""
        parser = QwenGuardParser()
        result = parser.parse("Unknown format without keywords")
        assert result.has_risk is False
        assert result.risk_level == RiskLevel.SAFE

    @staticmethod
    def test_custom_risk_type():
        """Test custom risk type."""
        parser = QwenGuardParser(risk_type="content_moderation")
        result = parser.parse({"safety": "Unsafe", "categories": []})
        assert result.risk_type == "content_moderation"