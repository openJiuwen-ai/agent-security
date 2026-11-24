# security_gateway

[English](./README.md) | 简体中文

`credential_router` 存储层的 Python 实现：一个基于代码内 schema 的加密字段存储库。它移植 Go 服务的 `crypto`、`platform` 与 `vault` 三个包；Go 服务本身是外部参考实现，不在本仓库中。

客户端和 LLM 网关集成由调用方实现；本包只提供密码学原语、平台层和 vault。

## 目录

```
src/                  security_gateway 包（package-dir 把 src 映射为 security_gateway）
  crypto/             密码学原语与落盘格式
  platform/           错误封装、配置与进程级保护
  vault/              通用加密字段存储（schema、记录、密钥、轮换）
tests/
  unit/               每个包一个目录
```

每个子包与一个 Go 包一一对应。上游 Go 实现只作为行为参考，不在本仓库中；每个 Python 模块的 docstring 记录了它移植的规则和原因，因此以 docstring 和本 README 作为主要参考。

## 能力

- 记录按 id 存取，字段由宿主在代码里声明的 `Schema` 描述。
- 字段可以原样存储，也可以用数据加密密钥（DEK）加密。schema 是权威来源；落盘字节上的标记只用于读取时交叉校验。
- DEK 由密钥加密密钥（KEK）包裹。KEK 由三份分片（文件、SQLite、内置常量）异或后再经 PBKDF2 派生。内置常量分片随包发布，应视为公开值。安全边界是：只拿到文件分片或只拿到 SQLite 分片的攻击者都无法还原 KEK；这防的是离线数据窃取，不是能同时读取文件与数据库的本地提权。
- 记录字段编码为 `VREC` 容器后存进 `vault_record.data`；schema、密钥元数据和同步状态分别放在 `vault_schema`、`vault_key_metadata` 与 `vault_sync_state`。
- 支持 DEK 轮换、自动轮换和接管未完成的轮换。新 schema 只在加性变更时被接受：已有字段必须保留原类型和加密状态；重命名、删除、改类型或改加密状态会被拒绝，需要显式迁移。存储会保留已经见过的旧 schema 版本，旧记录仍可读取。
- 记录以 id 为键。唯一的批量读取是 `Vault.list(prefix)`，它列出 id 以该前缀开头的记录；没有按字段查询的接口，也没有二级索引。

## 安装

```sh
pip install -e .
pip install -e '.[dev]'
```

核心包只依赖 `cryptography` 与 `PyYAML`。

## 测试

```sh
pip install -e '.[dev]'
pytest tests -q
```

当前测试位于 `tests/unit/`，覆盖 `crypto`、`platform` 与 `vault`。尚未移植的行为以 Go 服务的测试为参考。

## 读写记录

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
vault = Vault.open(VaultConfig(data_dir="/var/lib/credential-router/vault"), schema)

record = Record(id="some/record/id")
record.set("kind", Value.new_string("api_key"))
record.set("secret", Value.new_bytes(b"..."))
vault.put(record)
secret = vault.get("some/record/id").get_bytes("secret")
```

## 当前范围

- 本包不监听端口，也不实现 UDS 服务。HTTP 接口、凭据路由和 LLM 网关集成由调用方实现。
- etcd 与集群同步目前只是移植骨架，还无法导入：它们引用包内未随附的 `security_gateway.credmgr` 子包。这些模块尚不可用；当前只有单机 vault 可用。
- `VREC` 容器、包裹后的 DEK、密钥快照文件、SQLite DDL 与密钥派生参数都属于兼容性契约；改动需要两侧一起迁移。

## 兼容性规则

这些不是风格偏好。破坏任意一条，都会让读取另一方写入数据的部署失效。

1. **落盘格式不变。** `VREC` 容器、包裹后的 DEK 和密钥快照文件都由格式固定；改动需要两侧迁移。
2. **SQLite DDL 不变。** 表、列、索引和默认值保持一致。
3. **密钥派生不变。** 同样的三份分片、异或、盐、迭代次数和每种模式的 PRF。
4. **etcd keyspace 不变。** 前缀、值编码和 generation fence 保持一致。
5. **UDS 帧格式不变。** 长度前缀、JSON 形状和错误码保持一致。本包既不实现 UDS 监听器，也不实现帧编解码；帧格式属于外部服务封装与上游实现，本仓库没有对应的编解码代码。
