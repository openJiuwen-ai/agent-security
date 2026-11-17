# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

"""流式敏感内容替换。

待匹配段初始为空。push 吃进一个 chunk：若其中没有分割字符，整段留在
待匹配段并输出空串；若有，取最后一个分割字符，把它和它前面的内容
（含旧的待匹配段）送去做正则替换，分割字符后面的尾巴成为新的待匹配段。
没有后续 chunk 时调用 finish，把待匹配段自己送去替换。

重叠命中只留最长的一段。每段留前 3 后 4，中间固定四个全角星号；
原文不足 11 个字符时缩小两端，保证至少藏住 4 个字符。
不用半角 *：网页按 markdown 渲染，半角星号会和模型自己写的加粗撞在一起。
"""

from __future__ import annotations

import re

# 这些字符可以出现在密钥、手机号、身份证、邮箱里。其余字符都是分割字符。
_TOKEN_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-+/=@%"
)


def _is_delimiter(ch: str) -> bool:
    return ch not in _TOKEN_CHARS


def _last_delimiter(chunk: str) -> int | None:
    for index in range(len(chunk) - 1, -1, -1):
        if _is_delimiter(chunk[index]):
            return index
    return None


_HEAD = 3
_TAIL = 4
_MIN_HIDDEN = 4
# 全角星号。半角 * 在 markdown 里是加粗，贴着模型写的 **密钥** 会被吃掉。
_STARS = "＊＊＊＊"


def _display_secret(secret: str) -> str:
    """留前 3 后 4，中间固定四个全角星号。至少藏住 4 个原文字符。"""
    length = len(secret)
    if length <= _MIN_HIDDEN:
        return _STARS
    if length >= _HEAD + _TAIL + _MIN_HIDDEN:
        head, tail = _HEAD, _TAIL
    else:
        shown = length - _MIN_HIDDEN
        head = min(_HEAD, shown)
        tail = shown - head
    if tail:
        return secret[:head] + _STARS + secret[-tail:]
    return secret[:head] + _STARS


def _mask(text: str, patterns: list[re.Pattern[str]]) -> str:
    """重叠的命中留最长的一段，互不重叠的都按展示规则替换。"""
    spans: list[tuple[int, int]] = []
    for pattern in patterns:
        for match in pattern.finditer(text):
            if match.start() < match.end():
                spans.append((match.start(), match.end()))
    if not spans:
        return text

    spans.sort(key=lambda span: (-(span[1] - span[0]), span[0]))
    chosen: list[tuple[int, int]] = []
    for start, end in spans:
        overlapped = False
        for chosen_start, chosen_end in chosen:
            if not (end <= chosen_start or start >= chosen_end):
                overlapped = True
                break
        if not overlapped:
            chosen.append((start, end))
    chosen.sort()

    pieces: list[str] = []
    cursor = 0
    for start, end in chosen:
        pieces.append(text[cursor:start])
        pieces.append(_display_secret(text[start:end]))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


class StreamSensitiveMask:
    """待匹配段初始为空。push 吃进一个 chunk，finish 在没有后续 chunk 时收尾。"""

    def __init__(self, patterns: list[str]) -> None:
        self._patterns = [re.compile(pattern) for pattern in patterns]
        self._pending = ""

    def push(self, chunk: str) -> str:
        if not chunk:
            return ""
        cut = _last_delimiter(chunk)
        if cut is None:
            self._pending += chunk
            return ""
        ready = self._pending + chunk[: cut + 1]
        self._pending = chunk[cut + 1:]
        return _mask(ready, self._patterns)

    def finish(self) -> str:
        ready = self._pending
        self._pending = ""
        return _mask(ready, self._patterns)


def mask_complete(text: str, patterns: list[str]) -> str:
    """整段文本已经到齐时使用，等价于 push 后再 finish。"""
    if not text:
        return text
    masker = StreamSensitiveMask(patterns)
    return masker.push(text) + masker.finish()
