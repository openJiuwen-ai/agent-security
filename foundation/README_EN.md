# security-mask

English | [简体中文](./README.md)

The caller passes a list of regexes, and the utility replaces matched spans in a stream of text with stars. A match of 11 or more characters keeps its first 3 and last 4 characters; a match of 5–10 characters shrinks the head and tail so at least 4 characters stay hidden; a match of 4 characters or fewer is replaced entirely. The middle is always four full-width stars (`＊＊＊＊`), which keeps web Markdown from treating the mask as bold.

A delimiter is any character outside `A-Za-z0-9._-+/=@%`. On each `push`, the masker sends everything up to and including the last delimiter through replacement and keeps the remainder pending; it does not keep only a candidate prefix. Overlapping matches resolve to the longest one. The utility does not own the rules or the switch; the caller decides which text needs masking.

```python
from security_mask import StreamSensitiveMask, mask_complete

patterns = [r"sk-[A-Za-z0-9]{16,}"]

masked = mask_complete("token=sk-abcdefghijklmnop", patterns)
# "token=sk-＊＊＊＊mnop"; unmatched text is returned unchanged

masker = StreamSensitiveMask(patterns)
out = masker.push("token=sk-abc") + masker.push("defghijklmnop") + masker.finish()
# "token=sk-＊＊＊＊mnop"
```

Neither chunk in this split contains a delimiter, so the two `push` calls return empty strings and `finish` produces the masked text.

`jiuwenswarm/gateway/channel_manager/web/sensitive_mask.py` lazily loads this package for outbound web-channel text; when it is missing, the channel logs a warning and passes text through. agent-shield and JiuwenBox do not depend on it.

It can be installed as a `jiuwenswarm` dependency from the repository subdirectory:

```text
security-mask @ git+https://gitcode.com/openJiuwen/agent-security.git@develop#subdirectory=foundation
```

There are no third-party runtime dependencies. Tests are in `tests/test_stream_mask.py`.
