# Security Mask

Security Mask (distribution name `security-mask`, import name `security_mask`) is a streaming text masking utility. The caller supplies regexes, and the tool replaces matched spans with stars as characters flow through. It does not decide what counts as sensitive and does not own the rules or the switch.

The code lives under `foundation/`.

---

## 1. What problem it solves

Web chat and log echo render output incrementally: the model generates a chunk and the frontend displays it. If masking waits until the whole text is complete, a key may already have appeared in an earlier frame.

Security Mask is built for that streaming case. It receives chunks and decides which parts are safe to emit now and which might still become a match and must be held back. Once a match is found, it keeps the head and tail and replaces the middle with stars, so the user can see that a value was there without seeing the full value.

## 2. Core concepts

| Concept | Meaning |
| --- | --- |
| Token characters | Characters that can appear in keys, phone numbers, ID numbers, and emails: letters, digits, and `._-+/=@%` |
| Delimiter | Any character outside the token set, such as a space, colon, or newline |
| Pending tail | A tail that has not met a delimiter yet and could still become part of a match |
| Overlapping match | When several regexes match the same span, only the longest one is kept |

`push(chunk)` consumes one chunk. If the chunk contains a delimiter, the delimiter and everything before it (including the old pending tail) go through replacement, and the part after the delimiter becomes the new pending tail. If there is no delimiter, the whole chunk is held and an empty string is returned. Call `finish()` when no more chunks are coming.

## 3. Usage

```python
from security_mask import StreamSensitiveMask, mask_complete

patterns = [r"sk-[A-Za-z0-9]{16,}", r"\b\d{17}[\dXx]\b"]

# Complete text
masked = mask_complete("token=sk-abcdefghijklmnop", patterns)

# Streaming text: push returns the part that can be emitted now; finish flushes
masker = StreamSensitiveMask(patterns)
out = masker.push("token=sk-abc")
out += masker.push("defghijklmnop")
out += masker.finish()
```

## 4. Replacement rules and examples

- A match of 11 or more characters keeps its first 3 and last 4 characters; the middle becomes four full-width stars `＊＊＊＊`.
- A match of 5–10 characters shrinks the head and tail so at least 4 characters stay hidden; a match of 4 characters or fewer is fully starred.
- Full-width stars are not interpreted as Markdown bold in a web page, so the output can go straight into a chat renderer.
- Overlapping matches resolve to the longest one; non-overlapping matches are replaced independently.

Complete-text example:

```python
mask_complete("token=sk-abcdefghijklmnop", [r"sk-[A-Za-z0-9]{16,}"])
# "token=sk-＊＊＊＊mnop"
```

Streaming example:

```python
masker = StreamSensitiveMask([r"sk-[A-Za-z0-9]{16,}"])
masker.push("token=sk-abc")      # ""
masker.push("defghijklmnop")     # ""
masker.finish()                  # "token=sk-＊＊＊＊mnop"
```

Neither chunk contains a delimiter (`=` is a token character), so both `push` calls return an empty string and `finish` produces the masked text.

## 5. Who uses it

`jiuwenswarm/gateway/channel_manager/web/sensitive_mask.py` lazily loads this package to mask outbound text on the web channel; when the package is missing it logs a warning and passes text through. agent-shield and JiuwenBox do not depend on it.

## 6. Install and test

```bash
cd foundation
pip install -e ".[dev]"
pytest
```

It can also be installed as a `jiuwenswarm` dependency from the repository subdirectory:

```text
security-mask @ git+https://gitcode.com/openJiuwen/agent-security.git@develop#subdirectory=foundation
```

There are no third-party runtime dependencies. Python 3.11 or newer is required. Tests are in `foundation/tests/test_stream_mask.py`.
