# Security Gateway

Security Gateway（发行名 `security-gateway`，导入名 `security_gateway`）是一个加密字段存储库。它按 id 存取记录，字段是否加密由 schema 决定。它是库，不是独立服务。

---

## 1. 它解决什么问题

Agent 和工具经常需要保存 API Key、访问令牌、私钥等敏感字段。如果直接写进配置文件或数据库，磁盘上就是明文：备份、日志、误提交都可能把它们带出去。

Security Gateway 把“哪些字段需要加密”写进 schema，写入时自动加密，读取时自动解密。加密用的数据密钥不会明文落盘，而是由密钥加密密钥包裹；密钥加密密钥又由文件、SQLite 和内置常量三份分片异或后经 PBKDF2 派生。内置常量随包发布，应视为公开值；安全边界是只拿到文件分片或只拿到 SQLite 分片都无法还原密钥。这防的是离线数据窃取，不是能同时读取文件与数据库的本地提权。

## 2. 核心概念

| 概念 | 含义 |
| --- | --- |
| `Record` | 一条记录，含一个 id 和若干字段值 |
| `Schema` | 记录的形状：有哪些字段、每个字段是什么类型、是否加密 |
| `FieldDef` | schema 里的一个字段定义，含名字、类型和 `encrypted` 标记 |
| `Value` | 一个字段值，支持 string、bytes、int64 和 bool |
| DEK | 数据加密密钥，用来加密字段值 |
| KEK | 密钥加密密钥，用来包裹 DEK；由文件、SQLite 和内置常量三份分片异或后再经 PBKDF2 派生 |
| `VREC` | 记录字段的二进制容器，存进 SQLite 的 `vault_record.data` |
| 轮换 | 更换 DEK，并逐步把旧记录重新加密到新密钥 |

schema 是权威来源：字段是否加密只看 schema，落盘字节上的标记只用于读取时交叉校验。schema 可以向后加字段：已有字段的类型和加密状态必须保持不变；重命名、删除、改类型或改加密状态会被拒绝，需要显式迁移。存储会保留旧的 schema 版本，旧记录仍可读取。

## 3. 一次读写经过哪些步骤

写入：

1. 调用 `Vault.open(config, schema)` 打开存储。打开时校验 schema：新 schema 必须是已存 schema 的加性扩展，否则拒绝。
2. 构造 `Record`，用 `Value.new_string()`、`Value.new_bytes()` 等方法填入字段。
3. 调用 `vault.put(record)`。引擎按 schema 判断哪些字段要加密；需要加密的字段用当前 DEK 加密，然后整体编码成 `VREC` 容器写入 SQLite。

读取：

1. 调用 `vault.get(record_id)`，按 id 取出记录行。
2. 按记录里的 schema 版本找到对应 schema。
3. 按 schema 解密需要解密的字段，返回 `Record`。
4. 用 `record.get_string()`、`record.get_bytes()` 等方法取值。

轮换：

1. 调用 `rotate_dek()` 生成新的 DEK，并用 KEK 包裹。
2. 轮换先切换新 DEK，再按批次把仍使用旧 DEK 的记录重新加密；尚未迁移的记录在读取时回退到旧 DEK。
3. 自动轮换可以用 `start_auto_rotate()`；中断的轮换可以在下次打开时继续，也可以用 `takeover_pending()` 接管。

## 4. 代码怎么分

| 目录 | 职责 |
| --- | --- |
| `security_gateway/src/crypto/` | AEAD 加解密、密钥派生、wire format 与模式常量 |
| `security_gateway/src/platform/` | 配置加载、错误码与 HTTP 状态映射、内存锁定、单实例锁 |
| `security_gateway/src/vault/` | 加密字段存储：schema、记录编解码、SQLite 存储、密钥管理与轮换 |

`src` 直接映射为包根，因此导入路径是 `security_gateway.vault`、`security_gateway.crypto`、`security_gateway.platform`。

## 5. 用法示例

```python
from security_gateway.vault import (
    Config as VaultConfig,
    FieldDef,
    Record,
    Schema,
    Type,
    Value,
    Vault,
)

schema = Schema(version=1, fields=[
    FieldDef(name="kind", type=Type.STRING),
    FieldDef(name="secret", type=Type.BYTES, encrypted=True),
])
vault = Vault.open(VaultConfig(data_dir="/var/lib/security-gateway/vault"), schema)

record = Record(id="service/token")
record.set("kind", Value.new_string("api_key"))
record.set("secret", Value.new_bytes(b"..."))
vault.put(record)

entry = vault.get("service/token")
print(entry.get_string("kind"))
print(entry.get_bytes("secret"))
```

## 6. 边界与限制

- 本包不监听端口，也不提供 UDS 服务；HTTP 接口、凭据路由和 LLM 网关集成由调用方实现。
- 记录只按 id 访问，不提供按字段查询，也没有二级索引。
- 落盘格式、SQLite DDL、密钥派生参数与 UDS 帧格式属于兼容性契约；改动需要两侧一起迁移。
- etcd 与集群同步目前只是移植骨架，还无法导入：它们引用包内未随附的 `security_gateway.credmgr` 子包；当前可直接使用的是单机 vault。
- 现有测试集中在 `tests/unit/`，覆盖 crypto、platform 与 vault。

## 7. 安装与测试

```bash
cd security_gateway
pip install -e .
pip install -e ".[dev]"
pytest tests -q
```

运行时只依赖 `cryptography` 与 `PyYAML`，要求 Python 3.11 及以上。

## 8. 继续阅读

更完整的接口说明、兼容性规则与迁移注意事项见 `security_gateway/README.md`。
