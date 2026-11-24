# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""F3 内容检测：对进入模型的内容做注入等检测，输出概率性软信号。"""

# Enumerations
from .enums import (
    RiskLevel,
    GuardrailContentType,
)

# Data Models
from .models import (
    GuardrailResult,
    RiskAssessment,
    to_guardrail_result,
)

# Context and Parsers
from .context import (
    GuardrailContext,
    ModelOutputParser,
    BertBinaryParser,
    QwenGuardParser,
)

# Backends
from .backends import (
    GuardrailBackend,
    RuleBasedPromptInjectionBackend,
    RuleBasedBackendConfig,
    LLMPromptInjectionBackend,
    LLMPromptInjectionBackendConfig,
    APIModelBackend,
    APIModelBackendConfig,
    LocalModelBackend,
    LocalModelBackendConfig,
)

__all__ = [
    # Enumerations
    "RiskLevel",
    "GuardrailContentType",
    # Data Models
    "GuardrailResult",
    "RiskAssessment",
    "to_guardrail_result",
    # Context and Parsers
    "GuardrailContext",
    "ModelOutputParser",
    "BertBinaryParser",
    "QwenGuardParser",
    # Backends
    "GuardrailBackend",
    "RuleBasedPromptInjectionBackend",
    "RuleBasedBackendConfig",
    "LLMPromptInjectionBackend",
    "LLMPromptInjectionBackendConfig",
    "APIModelBackend",
    "APIModelBackendConfig",
    "LocalModelBackend",
    "LocalModelBackendConfig",
]