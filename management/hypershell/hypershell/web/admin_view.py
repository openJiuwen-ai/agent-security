"""Read-only presentation helpers for the administrator demo UI.

These views reuse the configuration compiler and explanation; they do not grant
permissions, change instances, or certify a live sandbox's complete policy.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping

from ..config import AdminConfig, load_document
from ..policy import AccessMode, InvalidRequest, LaunchRequest, PolicyError
from ..runner.jiuwenbox_policy import policy_digest, to_jiuwenbox_policy

_MODE_LABELS = {"none": "无权限", "read": "只读", "read_write": "读写"}
_PREVIEW_SCOPE = (
    "仅预览工作负载资源投影，不创建沙箱；不包含运行时附加挂载、环境和网络配置，" "不代表运行中实例的实际策略。"
)


def startup_request_path(config_path: str | Path, user_id: str) -> Path:
    """Use exactly the request-file selection performed by the Web start route."""
    directory = Path(config_path).parent
    candidate = directory / f"request-{user_id}.yaml"
    return candidate if candidate.exists() else directory / "request.yaml"


def _load_startup_request(config_path: str | Path, user_id: str) -> LaunchRequest:
    return LaunchRequest.from_dict(load_document(startup_request_path(config_path, user_id)))


def _error(exc: Exception) -> dict[str, str]:
    return {"code": getattr(exc, "code", "PREVIEW_UNAVAILABLE"), "message": str(exc)}


def _mode_label(mode: Any) -> str:
    if isinstance(mode, AccessMode):
        mode = mode.name.lower()
    return _MODE_LABELS.get(mode, "无法确认")


def _permission_rows(config: AdminConfig, explanation: dict, request, plan) -> list[dict]:
    mounts = {mount.resource_id: mount for mount in plan.mounts} if plan else {}
    resources = explanation["resources"]
    requested = request.resources if request is not None else None
    rows = []
    for resource_id, resource in sorted(config.catalog.items()):
        detail = resources.get(resource_id, {})
        source_labels = []
        for source in detail.get("sources", []):
            name = source["source"]
            name = "用户追加授权" if name == "user.grants" else "角色 " + name.removeprefix("role:")
            source_labels.append(f"{name}（{_mode_label(source['mode'])}）")
        mount = mounts.get(resource_id)
        rows.append(
            {
                "id": resource_id,
                "host_path": resource.backend_ref,
                "sandbox_path": resource.sandbox_target,
                "source_text": "；".join(source_labels) or "无授权来源",
                "granted": _mode_label(detail.get("granted", "none")),
                "limit": _mode_label(detail["limit"]) if detail.get("limit") is not None else "未设置",
                "effective": _mode_label(detail.get("effective", "none")),
                "requested": (
                    "无法确认"
                    if requested is None
                    else _mode_label(requested[resource_id]) if resource_id in requested else "未申请"
                ),
                "mount_mode": (
                    (("只读" if mount.read_only else "读写") if mount else "不挂载")
                    if plan is not None
                    else "未生成计划"
                ),
            }
        )
    return rows


def build_preview(config: AdminConfig, config_path: str | Path, user_id: str, mode: str = "request") -> dict:
    """Preview the real startup request unless explicitly inspecting all grants.

    Failed requests are never replaced with all authorized resources. Permission
    explanation rows remain visible when reading or compiling the request fails.
    """
    result = {
        "chosen": user_id,
        "mode": mode,
        "request_name": None,
        "rows": [],
        "plan": None,
        "policy": None,
        "digest": None,
        "error": None,
        "scope": _PREVIEW_SCOPE,
    }
    request = plan = None
    try:
        explanation = config.explain(user_id)
    except (PolicyError, KeyError, ValueError, TypeError) as exc:
        result["error"] = _error(exc)
        return result
    try:
        if mode == "request":
            result["request_name"] = startup_request_path(config_path, user_id).name
            request = _load_startup_request(config_path, user_id)
        elif mode == "authorized":
            result["request_name"] = "全部配置授权（非启动请求）"
            request = LaunchRequest(resources=config.users[user_id].grants)
        else:
            raise InvalidRequest("未知预览模式，请选择启动请求或全部配置授权")
        plan = config.compile(user_id, request)
        user = config.users[user_id]
        policy = to_jiuwenbox_policy(
            plan, run_as_user=user.run_as_user, run_as_group=user.run_as_group, allowed_roots=config.allowed_roots
        )
        result.update(
            plan=json.dumps({**plan.canonical(), "digest": plan.digest}, ensure_ascii=False, indent=2),
            policy=json.dumps(policy, ensure_ascii=False, indent=2),
            digest=policy_digest(policy),
        )
    except (PolicyError, OSError, KeyError, ValueError, TypeError) as exc:
        result["error"] = _error(exc)
        plan = None
    result["rows"] = _permission_rows(config, explanation, request, plan)
    return result


def _digest(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _build_drift(config: AdminConfig, user_id: str, status: Mapping[str, Any], config_path: str | Path) -> dict:
    drift = {
        "state": "unknown",
        "label": "无法确认",
        "description": "缺少实例记录，无法确认配置是否已应用。",
        "current_authorization_digest": None,
        "recorded_authorization_digest": _digest(status.get("authorization_digest")),
        "current_plan_digest": None,
        "recorded_plan_digest": _digest(status.get("plan_digest")),
    }
    error = None
    try:
        drift["current_authorization_digest"] = config.explain(user_id)["authorization_digest"]
        request = _load_startup_request(config_path, user_id)
        drift["current_plan_digest"] = config.compile(user_id, request).digest
    except (PolicyError, OSError, KeyError, ValueError, TypeError) as exc:
        error = _error(exc)
    phase = status.get("phase")
    if phase == "STOPPED":
        drift.update(
            state="stopped", label="下次启动应用", description="当前无运行实例；保存的配置将在下次成功启动时应用。"
        )
        if error:
            drift["description"] += f"当前启动请求尚不可用：{error['message']}"
        return drift
    if phase != "RUNNING":
        drift.update(
            label="异常待处理" if phase in ("LOST", "ERROR", "ERROR_CLEANUP_REQUIRED") else "无法确认",
            description="实例当前未确认正常运行，请先检查状态与诊断；不能认定当前配置已应用。",
        )
        return drift
    authorization_changed = (
        drift["recorded_authorization_digest"] is not None
        and drift["current_authorization_digest"] is not None
        and drift["current_authorization_digest"] != drift["recorded_authorization_digest"]
    )
    plan_changed = (
        drift["recorded_plan_digest"] is not None
        and drift["current_plan_digest"] is not None
        and drift["current_plan_digest"] != drift["recorded_plan_digest"]
    )
    recorded_roles = status.get("roles")
    roles_known = isinstance(recorded_roles, (list, tuple)) and all(isinstance(role, str) for role in recorded_roles)
    roles_changed = (
        roles_known and user_id in config.users and sorted(recorded_roles) != sorted(config.users[user_id].roles)
    )
    if authorization_changed or plan_changed or roles_changed:
        drift.update(
            state="pending",
            label="待重建",
            description="当前配置授权、角色或启动请求计划与实例启动记录不同；需停止并重新启动后应用。",
        )
        if error:
            drift["description"] = (
                "配置授权或角色已变更；当前启动请求无效，请先修正请求，再停止并重新启动应用。"
                f"核对错误（{error['code']}）：{error['message']}"
            )
        return drift
    if error:
        drift["description"] = f"无法核对当前启动请求（{error['code']}）：{error['message']}"
        return drift
    if not drift["recorded_authorization_digest"] or not drift["recorded_plan_digest"]:
        return drift
    if recorded_roles is not None and not roles_known:
        drift["description"] = "实例角色记录格式异常，无法完整核对配置是否已应用。"
        return drift
    drift.update(
        state="aligned",
        label="一致",
        description="配置授权与启动请求计划和启动记录一致；不代表运行身份、运行时配置或完整隔离边界已核验。",
    )
    return drift


def build_instance_view(config: AdminConfig, user_id: str, status: Mapping[str, Any], config_path: str | Path) -> dict:
    """Describe observed state and safe next steps without executing an action."""
    raw = dict(status)
    phase = str(raw.get("phase") or "UNKNOWN")
    states = {
        "RUNNING": (
            "运行中",
            "success",
            "已观察到沙箱与应用正在运行。",
            "修改配置后需停止并重新启动，才能应用到此实例。",
        ),
        "STOPPED": (
            "已停止",
            "muted",
            "当前没有运行中的实例。",
            "确认配置与启动请求后启动，用户才能使用 Web 对话或 TUI。",
        ),
        "LOST": (
            "运行记录失效",
            "danger",
            "无法确认记录中的引擎身份，保留原始记录等待处理。",
            "先查看诊断；恢复仅适用于有跨开机证据且无相关残留的记录，不是通用重启。",
        ),
        "ERROR": (
            "实例异常",
            "danger",
            "无法确认沙箱与应用处于正常运行状态。",
            "先展开诊断详情检查引擎、沙箱和应用状态；可尝试停止，成功后再启动，不要反复启动或盲目恢复。",
        ),
        "ERROR_CLEANUP_REQUIRED": (
            "需要清理",
            "danger",
            "启动失败后的清理尚未完成。",
            "先查看诊断并核实残留资源；可尝试停止，若无法确认清理完成则保留记录，由管理员继续处理。",
        ),
        "STARTING": (
            "启动中",
            "warning",
            "已有启动记录，尚未确认应用就绪。",
            "等待当前操作完成后刷新状态；暂勿重复提交。",
        ),
        "STOPPING": ("停止中", "warning", "实例正在停止。", "等待清理完成后刷新状态；暂勿重复提交。"),
    }
    label, tone, description, hint = states.get(
        phase, ("状态未知", "warning", "尚未获取到可识别的实例状态。", "刷新并查看诊断详情，确认状态后再操作。")
    )
    reasons = {
        "ENGINE_IDENTITY_MISSING": "引擎身份与启动记录不匹配，可能已重启或退出。",
        "ENGINE_QUERY_FAILED": "查询引擎失败，尚不能确定沙箱或应用的实际状态。",
    }
    if isinstance(raw.get("reason"), str) and raw["reason"] in reasons:
        description = reasons[raw["reason"]]
    actions = []
    if phase == "RUNNING":
        actions = [
            {
                "action": "stop",
                "label": "停止",
                "tone": "danger",
                "confirm": "停止将中断此用户当前的对话和 TUI，个人持久数据保留。确认停止？",
            }
        ]
    elif phase == "STOPPED":
        actions = [{"action": "start", "label": "启动", "tone": "success", "confirm": ""}]
    elif phase == "LOST":
        actions = [
            {
                "action": "recover",
                "label": "检查并恢复",
                "tone": "warning",
                "confirm": "仅在存在跨开机证据且无相关残留时恢复失效记录；检查失败将保持原状态，恢复后仍需手动启动。继续检查？",
            }
        ]
    elif phase in {"ERROR", "ERROR_CLEANUP_REQUIRED"}:
        actions = [
            {
                "action": "stop",
                "label": "尝试停止",
                "tone": "danger",
                "confirm": "请先查看诊断。尝试停止会中断此用户的对话和 TUI，并由既有停止流程检查引擎身份与清理结果；无法确认时会报错，不会自动恢复或启动。确认尝试停止？",
            }
        ]
    return {
        "raw": raw,
        "phase": phase,
        "label": label,
        "tone": tone,
        "description": description,
        "hint": hint,
        "actions": actions,
        "drift": _build_drift(config, user_id, raw, config_path),
    }
