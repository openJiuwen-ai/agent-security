# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.
"""Host callback contracts for the Windows DLL guard."""

from collections.abc import Awaitable
from typing import Any, Literal, NotRequired, Protocol, Required, TypedDict

from agent_shield.tool_permission.runtime.models import PermissionConfirmResponse, PermissionResult


class RuntimeApprovalEvent(TypedDict):
    request_id: str
    tool_call_id: str
    execution_id: str
    session_id: str
    resource: dict
    reason: str | None
    matched_rule: str | None


class RuntimePersistenceEvent(TypedDict):
    tool_call_id: str
    execution_id: str
    session_id: str
    persisted: bool
    scope: Literal["permanent", "session"]


class ApprovalGrant(TypedDict):
    id: str
    tools: list[str]
    match_type: str
    pattern: str
    action: Literal["allow"]


class ConfirmationFields(TypedDict, total=False):
    approved: Required[bool]
    feedback: str
    auto_confirm: bool
    persist_allow: bool | None
    authorization_mode: str | None
    authorization_scope: str | None


class ApprovalReceipt(TypedDict):
    operation: dict[str, Any]
    accesses: NotRequired[list[tuple[str, str]]]
    grants: NotRequired[list[ApprovalGrant]]
    confirmation: NotRequired[PermissionConfirmResponse | ConfirmationFields | None]


class ProgramSubject(TypedDict):
    kind: Literal["program"]
    exe: str
    argv: list[str]
    cwd: str
    source_tool: str
    source_shell: str | None
    root_command_approved: NotRequired[bool]


class TakeApproval(Protocol):
    def __call__(
        self, tool_call_id: str, tool_name: str, inputs: dict[str, Any], /
    ) -> ApprovalReceipt | None:
        ...


class ProgramDecision(Protocol):
    def __call__(
        self,
        subject: ProgramSubject,
        result: PermissionResult,
        /,
        *,
        session: Any,
        tool_call_id: str,
        execution_id: str,
    ) -> Awaitable[PermissionResult | None]:
        ...


class PersistApproval(Protocol):
    def __call__(
        self, session_id: str, config: dict, grant: ApprovalGrant, /, *, permanent: bool
    ) -> bool:
        ...


class PolicyRevision(Protocol):
    def __call__(self) -> str | int:
        ...
