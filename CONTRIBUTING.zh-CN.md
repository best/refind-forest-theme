# 贡献指南

[English](CONTRIBUTING.md)

欢迎贡献，但贡献必须保持项目的可复现性和可审查性，并且能够在不以特权访问
真实固件或磁盘的情况下安全测试。

## 开发环境

请在源代码检出目录中工作。构建命令所需的补丁和图稿输入不会作为 wheel 包数据
安装。项目要求 Python 3.12 或更高版本，并且需要 `venv` 支持；Debian 和
Ubuntu 用户可能需要安装匹配的 `python3-venv` 包。

```bash
make setup
make test
make check
```

Make 会自行选择项目 `.venv` 中的解释器，因此无需在 shell 中激活虚拟环境。
运行 `make help` 可以查看可用目标。

每项更改都必须新增或更新针对性测试。提交 pull request 之前，先运行受影响的
测试，再运行完整测试套件，并将警告视为错误。测试必须使用临时目录、合成标识符
和模拟的固件接口；不得要求 root 权限，也不得接触真实 EFI 系统分区（ESP）、
块设备或 NVRAM。

`make ci` 运行与持续集成相同的聚合检查。需要单独排查公开源码树或可复现性问题
时，可分别运行 `make audit` 和 `make deterministic`。

## 敏感数据

不要提交凭据、私钥、证书、令牌、机器快照、EFI 变量转储、磁盘或分区标识符、
私有启动配置、绝对主目录路径，或真实机器的日志。在 issue、测试、提交或 pull
request 中加入诊断材料之前，必须先将其脱敏。

## 许可与视觉素材

对项目代码和文档的贡献以 GPL-3.0-or-later 许可接受。修改 rEFInd 补丁或记录
下载的构建输入时，请保留上游针对各文件的声明。

贡献者必须拥有所提交视觉素材的相应权利，并提供其源文件、著作权归属和许可。
由 Yaru 图稿衍生的视觉素材必须继续与 CC-BY-SA-4.0 兼容，并保留
`THIRD_PARTY_NOTICES.md` 中记录的署名信息。不要仅为装饰而提交第三方标记；
请遵循 `TRADEMARKS.md`。

## 开发者原创声明

所有提交都必须包含
[Developer Certificate of Origin 1.1](https://developercertificate.org/)
要求的 sign-off。使用 `git commit -s` 添加；生成的提交信息中必须包含如下格式
的一行：

```text
Signed-off-by: Your Name <your-address@example.invalid>
```

添加 sign-off 即表示你确认 Developer Certificate of Origin 1.1，并确认自己
有权依据项目和素材所适用的许可提交该贡献。
