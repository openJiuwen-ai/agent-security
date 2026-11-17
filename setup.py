"""openjiuwen-security 聚合包的动态打包配置。

为什么有这个文件：pyproject.toml 的静态 packages 列表无法表达五个异构目录的
自动发现（agent_shield 是扁平布局，packages.find 拼不出 agent_shield.* 前缀），
此前显式列 65 个包，新增子包忘了同步会静默缺包。这里改为构建时自动发现：

- 新增子包（任意组件内部）：无需任何改动，自动进包；
- 新增 foundation 组件：COMPONENTS 加一行映射，数据文件按需配 package_data；
- 成员若新增入口点（[project.scripts]）或数据文件声明（package-data），
  必须同步到根 pyproject 的 [project.scripts] / 本文件的 package_data，
  构建时 check_member_declarations_synced 会强制校验，漏同步直接构建失败。

[project] 元数据、依赖、入口点仍在 pyproject.toml；本文件只负责包的发现与映射。
"""
import tomllib
from pathlib import Path

from setuptools import find_packages, setup

ROOT_DIR = Path(__file__).parent

# 顶层包名 -> 包根目录（相对本文件所在仓库根）
COMPONENTS = {
    "agent_shield": "agent_shield",               # 扁平布局：目录即包
    "agent_ssas": "agent_ssas/src/agent_ssas",   # src 布局
    "security_mask": "foundation/security-mask/src/security_mask",
    "jiuwenbox": "jiuwenbox/src/jiuwenbox",      # src 布局
    "security_gateway": "security_gateway/src",  # src 目录即包（同其成员 pyproject 的 package-dir）
}

# 与各成员 pyproject 的声明保持一致（只覆盖被聚合进 wheel 的组件；
# agent-security-dll 是独立分发的可选依赖，不在聚合 wheel 内，无需在此声明）
package_data = {
    "agent_shield": ["py.typed"],
    "agent_shield.tool_permission.runtime": ["defaults.yaml"],
    "agent_ssas": ["**/*.yaml"],
    "jiuwenbox": ["configs/*.yaml"],
}

# 过滤包根里的非发布内容（按发现的包名 fnmatch），如 agent_shield/ 下的 tests、native
EXCLUDE = ["build*", "tests*", "native*"]


def check_member_declarations_synced():
    """校验聚合侧已同步成员 pyproject 的入口点与 package-data 键。

    防止"成员新增声明、聚合侧漏同步"导致的静默缺内容（入口点缺失、
    运行时 FileNotFoundError）。只检查 COMPONENTS 里的被聚合组件。
    """
    root_scripts = tomllib.loads(
        (ROOT_DIR / "pyproject.toml").read_text(encoding="utf-8")
    )["project"].get("scripts", {})
    problems = []
    for pkg, pkg_dir in COMPONENTS.items():
        # 成员工程目录 = 包路径截掉 "/src" 及其后（扁平布局则是组件目录本身）
        member_py = ROOT_DIR / pkg_dir.split("/src")[0] / "pyproject.toml"
        if not member_py.exists():
            problems.append(f"{pkg}: 找不到成员 pyproject（{member_py}），检查 COMPONENTS 路径")
            continue
        member = tomllib.loads(member_py.read_text(encoding="utf-8"))
        for name, target in member.get("project", {}).get("scripts", {}).items():
            if root_scripts.get(name) != target:
                problems.append(f"{pkg}: 入口点未同步 -> {name} = {target}")
        for data_key in member.get("tool", {}).get("setuptools", {}).get("package-data", {}):
            if data_key not in package_data:
                problems.append(f"{pkg}: package-data 键未同步 -> {data_key}")
    if problems:
        raise SystemExit(
            "openjiuwen-security 与成员 pyproject 声明不一致，请同步后重新构建：\n  "
            + "\n  ".join(problems)
        )


check_member_declarations_synced()

packages = []
package_dir = {}
for name, path in COMPONENTS.items():
    package_dir[name] = path
    packages.append(name)
    packages.extend(f"{name}.{sub}" for sub in find_packages(path, exclude=EXCLUDE))

setup(
    packages=packages,
    package_dir=package_dir,
    license_files=["LICENSE"],
    package_data=package_data,
)
