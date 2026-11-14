# Security Mask

Security Mask（发行名 `security-mask`，导入名 `security_mask`）是一个流式文本脱敏工具。调用方传入正则列表，工具在字符流经过时把命中片段替换成星号。它不判断什么是敏感数据，也不持有规则和开关。

代码位于仓库的 `foundation/` 目录。

---

## 1. 它解决什么问题

网页聊天、日志回显这类输出是逐段渲染的：模型生成一段，前端就显示一段。如果等整段文本结束再脱敏，密钥可能已经在中间某一帧露出去了。

Security Mask 面向这种流式场景。它一边接收 chunk，一边判断哪些片段已经可以安全输出、哪些可能是命中前缀需要先留住。命中后保留首尾字符，中间替换成星号，既能让用户看出这里原本有一个值，又不会暴露完整内容。

## 2. 核心概念

| 概念 | 含义 |
| --- | --- |
| token 字符 | 可能出现在密钥、手机号、身份证、邮箱里的字符：字母、数字和 `._-+/=@%` |
| 分隔符 | token 字符之外的字符，例如空格、冒号、换行 |
| 待匹配段 | 还没有遇到分隔符、可能继续构成命中的尾部 |
| 重叠命中 | 多个正则命中同一段文本时，只保留最长的一段 |

`push(chunk)` 会吃掉一个 chunk：如果里面有分隔符，就把分隔符及之前的内容（含旧待匹配段）送去替换，分隔符之后的部分留作新的待匹配段；如果没有分隔符，就整段留住并返回空串。没有后续 chunk 时调用 `finish()` 收尾。

## 3. 用法

```python
from security_mask import StreamSensitiveMask, mask_complete

patterns = [r"sk-[A-Za-z0-9]{16,}", r"\b\d{17}[\dXx]\b"]

# 完整文本
masked = mask_complete("token=sk-abcdefghijklmnop", patterns)

# 流式文本：push 返回本次可安全输出的部分，finish 收尾
masker = StreamSensitiveMask(patterns)
out = masker.push("token=sk-abc")
out += masker.push("defghijklmnop")
out += masker.finish()
```

## 4. 替换规则与示例

- 命中段 11 个字符及以上时保留前 3 个字符和后 4 个字符，中间固定替换为四个全角星号 `＊＊＊＊`。
- 5–10 个字符时缩小首尾展示长度，至少藏住 4 个字符；4 个字符及以下时整段替换为星号。
- 全角星号不会在网页 Markdown 中被当成加粗，适合直接进入聊天渲染。
- 重叠命中取最长的一段；互不重叠的命中分别替换。

完整文本示例：

```python
mask_complete("token=sk-abcdefghijklmnop", [r"sk-[A-Za-z0-9]{16,}"])
# "token=sk-＊＊＊＊mnop"
```

流式示例：

```python
masker = StreamSensitiveMask([r"sk-[A-Za-z0-9]{16,}"])
masker.push("token=sk-abc")      # ""
masker.push("defghijklmnop")     # ""
masker.finish()                  # "token=sk-＊＊＊＊mnop"
```

两段输入都不含分隔符（`=` 属于 token 字符），所以两次 `push` 都返回空串，结果由 `finish` 一次给出。

## 5. 谁在用

`jiuwenswarm/gateway/channel_manager/web/sensitive_mask.py` 懒加载这个包，对网页通道的出站文本做脱敏；未安装时只记录告警并原样输出。agent-shield 与 JiuwenBox 不依赖它。

## 6. 安装与测试

```bash
cd foundation
pip install -e ".[dev]"
pytest
```

也可以作为 `jiuwenswarm` 的依赖从仓库子目录安装：

```text
security-mask @ git+https://gitcode.com/openJiuwen/agent-security.git@develop#subdirectory=foundation
```

运行时没有第三方依赖，要求 Python 3.11 及以上。测试见 `foundation/tests/test_stream_mask.py`。
