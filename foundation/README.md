# security-mask

[English](./README_EN.md) | 简体中文

调用方传入正则列表，对流式文本做部分星号替换。命中段 11 个字符及以上时保留前 3 个字符和后 4 个字符；5–10 个字符时缩小首尾展示长度，至少藏住 4 个字符；4 个字符及以下时整段替换为星号。中间固定为四个全角星号 `＊＊＊＊`，全角星号不会被网页 Markdown 当成加粗。

分隔符是 `A-Za-z0-9._-+/=@%` 之外的任意字符。每次 `push` 会把最后一个分隔符及其之前的全部内容（含之前挂起的内容）送去替换，剩下的部分继续挂起；它不会只保留可能是命中前缀的尾巴。重叠命中取最长的一段。规则和开关由调用方持有，工具本身不判断什么是敏感数据。

```python
from security_mask import StreamSensitiveMask, mask_complete

patterns = [r"sk-[A-Za-z0-9]{16,}"]

masked = mask_complete("token=sk-abcdefghijklmnop", patterns)
# "token=sk-＊＊＊＊mnop"；未命中的文本原样返回

masker = StreamSensitiveMask(patterns)
out = masker.push("token=sk-abc") + masker.push("defghijklmnop") + masker.finish()
# "token=sk-＊＊＊＊mnop"
```

上例的两段输入都不含分隔符，所以前两次 `push` 返回空串，结果由 `finish` 一次给出。

`jiuwenswarm/gateway/channel_manager/web/sensitive_mask.py` 懒加载这个包，对网页通道的出站文本做脱敏；未安装时只记录告警并原样输出。agent-shield 与 JiuwenBox 不依赖它。

也可以作为 `jiuwenswarm` 的依赖从仓库子目录安装：

```text
security-mask @ git+https://gitcode.com/openJiuwen/agent-security.git@develop#subdirectory=foundation
```

运行时没有第三方依赖。测试见 `tests/test_stream_mask.py`。
