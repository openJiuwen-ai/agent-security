"""openjiuwen-security 聚合包的动态打包配置。

为什么有这个文件：pyproject.toml 的静态 packages 列表无法表达四个异构目录的
自动发现（agent_shield 是扁平布局，packages.find 拼不出 agent_shield.* 前缀），
此前显式列 65 个包，新增子包忘了同步会静默缺包。这里改为构建时自动发现：

- 新增子包（任意组件内部）：无需任何改动，自动进包；
- 新增 foundation 组件：COMPONENTS 加一行映射，数据文件按需配 package_data。

[project] 元数据、依赖、入口点仍在 pyproject.toml；本文件只负责包的发现与映射。
"""
from setuptools import find_packages, setup

# 顶层包名 -> 包根目录（相对本文件所在仓库根）
COMPONENTS = {
    "agent_shield": "agent_shield",               # 扁平布局：目录即包
    "agent_ssas": "agent_ssas/src/agent_ssas",   # src 布局
    "security_mask": "foundation/security_mask",
    "jiuwenbox": "jiuwenbox/src/jiuwenbox",      # src 布局
}

# 过滤包根里的非发布内容（按发现的包名 fnmatch），如 agent_shield/ 下的 tests、native
EXCLUDE = ["build*", "tests*", "native*"]

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
    package_data={
        # 与各子包 pyproject 的声明保持一致
        "agent_shield": ["py.typed"],
        "agent_shield.tool_permission.runtime": ["defaults.yaml"],
        "agent_ssas": ["**/*.yaml"],
        "jiuwenbox": ["configs/*.yaml", "native/*.dll", "native/softdelete/*"],
    },
)
