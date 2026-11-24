"""Map a jiuwenswarm tool result onto text for detection."""


def tool_result_text(result: object) -> str:
    if isinstance(result, str):
        return result
    if isinstance(result, dict):
        for key in ("content", "output", "text", "result"):
            value = result.get(key)
            if isinstance(value, str):
                return value
    return ""
