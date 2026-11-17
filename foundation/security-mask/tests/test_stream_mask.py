# Copyright (c) Huawei Technologies Co., Ltd. 2026. All rights reserved.

from security_mask.stream_mask import StreamSensitiveMask, mask_complete

_KEY = r"(?:sk|rk|pk|ak)-[A-Za-z0-9]{8,}"


def test_hold_until_delimiter_then_mask_key() -> None:
    masker = StreamSensitiveMask([_KEY])
    assert masker.push("密钥是sk-abc") == "密钥是"
    assert masker.push("def999，请查收") == "sk-＊＊＊＊f999，请查收"
    assert masker.finish() == ""


def test_finish_masks_pending_without_delimiter() -> None:
    masker = StreamSensitiveMask([_KEY])
    assert masker.push("密钥是sk-abc") == "密钥是"
    assert masker.push("def999") == ""
    assert masker.finish() == "sk-＊＊＊＊f999"


def test_no_delimiter_emits_nothing() -> None:
    masker = StreamSensitiveMask([_KEY])
    assert masker.push("sk-abc") == ""
    assert masker.push("def99") == ""
    assert masker.finish() == "sk-＊＊＊＊ef99"


def test_empty_chunk() -> None:
    masker = StreamSensitiveMask([_KEY])
    assert masker.push("") == ""
    assert masker.finish() == ""


def test_longest_overlap_wins() -> None:
    text = "sk-abcdef999"
    masked = mask_complete(text, [r"sk-[A-Za-z0-9]+", r"abcdef"])
    assert masked == "sk-＊＊＊＊f999"


def test_non_overlapping_both_replaced() -> None:
    text = "a@b.co 和 sk-abcdef999。"
    masked = mask_complete(
        text,
        [r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", _KEY],
    )
    assert masked == "a@＊＊＊＊ 和 sk-＊＊＊＊f999。"


def test_short_match_hides_at_least_four() -> None:
    assert mask_complete("abcdefgh", [r"abcdefgh"]) == "abc＊＊＊＊h"
    assert mask_complete("abcd", [r"abcd"]) == "＊＊＊＊"


def test_markdown_bold_keeps_mask_stars() -> None:
    """模型用 **密钥** 加粗时，打码星号不能再是半角 *，否则网页会把星号吃掉。"""
    masked = mask_complete("**sk-hppn87Eb9EY**", [_KEY])
    assert masked == "**sk-＊＊＊＊b9EY**"
    assert "****" not in masked


def test_switch_off_is_empty_pattern_list() -> None:
    assert mask_complete("sk-abcdef999", []) == "sk-abcdef999"
