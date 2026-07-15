# rEFInd Forest 主题

[English](README.md)

这是为 ASUS ROG Flow Z13 上的 rEFInd 配置协调设计的两套
2560x1600 主题：

- A 方案是默认方案，采用现代 Ubuntu 橙色和 Windows 蓝色。
- B 方案在半透明深绿色徽章上使用冰白色标记。

两种方案都包含相互匹配的恢复、固件、重启、关机、Ventoy 和通用
UEFI 介质图标。rEFInd 会继续自动发现 Ubuntu 内核、Windows 和可移动
启动介质。

## 安全警告

部分命令需要 root 权限，并且可能写入 EFI 系统分区（ESP）或修改 NVRAM
启动变量。目标选错、写入中断或未经审查的签名输入都可能导致系统无法
启动。部署到真实硬件之前，请先在无特权环境中完成构建和测试，核实已挂载
ESP 及其物理身份，将经过验证的备份保存在 ESP 之外，并准备一条已经测试
可用的固件或操作系统恢复路径。

主题安装会将 Forest 文件和配置写入所选 ESP。loader 的 `stage`、
`boot-next`、`promote` 和 `rollback` 工作流还会管理备用 loader 文件和
NVRAM 条目。绝不要让这些操作与 `efibootmgr` 或其他固件变量写入工具并发
运行。在审查命令路径及其对目标机器的影响之前，不要运行本文中的特权命令。

需要特权的 Make 目标会自行调用 `sudo`，不要使用 `sudo make`。要求
`CONFIRM=YES` 的目标只把它作为明确的操作确认，并不会替你验证 ESP、备份、
签名材料或恢复方案是否正确。

只读的 `theme-verify` 和 `loader-status` 目标也会调用 `sudo`，但不要求传入
`CONFIRM`。

## 仅源代码发布与 Python 支持

本项目仅以源代码形式发布。请在源码检出目录中运行下列命令；构建工作流
需要的补丁和素材资源尚未作为 wheel 包数据安装，因此不支持从已安装的 wheel
中运行这些命令。

项目要求 Python 3.12 或更高版本，并且需要 `venv` 支持；在 Debian 和 Ubuntu
上，必要时请安装与 Python 版本匹配的 `python3-venv` 包。测试矩阵覆盖
Python 3.12 和 Python 3.14。在测试或构建之前，让 Make 创建项目专用的
`.venv`，并以 editable 模式安装项目：

```bash
make setup
```

后续目标会自行选择 `.venv` 解释器，无需在 shell 中激活虚拟环境。运行
`make help` 可以查看可用目标。

## 构建与检查

运行测试并构建两种主题方案，不会写入 EFI 系统分区：

```bash
make test
make build
```

排查失败时，可以分别运行确定性构建检查和公开源码树审计，也可以运行本地
聚合检查：

```bash
make deterministic
make audit
make check
```

`make ci` 运行 CI 使用的聚合检查。`make clean` 删除生成输出，但保留虚拟环境、
下载缓存和备份；`make distclean` 还会删除虚拟环境和下载缓存，但始终保留备份。

生成的主题包位于 `build/refind-theme/`。其中生成的 `theme-active.conf` 默认
选择 A 方案。请让这个目录与 loader 构建输出保持分离。loader 下载默认缓存
在 `.cache/refind-loader/` 下。

## 补丁 loader 工作流

替换 loader 是一套单独且必须显式执行的工作流，不会在安装主题时自动发生。
先构建并验证可复现的未签名镜像，再用本机管理、仅 root 可访问的密钥和证书
进行签名：

```bash
make loader-build
make loader-verify
make loader-sign CONFIRM=YES
make loader-verify \
  LOADER_IMAGE=build/refind-loader/refind_x64.signed.efi
```

签名默认读取 `/etc/refind.d/keys/refind_local.key` 和
`/etc/refind.d/keys/refind_local.crt`。在依赖已签名 loader 之前，请准备
相互匹配的私钥和证书，并通过平台的 Secure Boot 流程建立对该证书的信任。
密钥必须是 root 所有的普通文件，且不得授予组或其他用户任何权限；证书必须
归 root 所有，且组和其他用户均不得写入。本项目不会生成、注册或分发签名密钥或证书。
安全打开的本地证书是验证时的信任来源。

签名还会在已签名镜像旁发布 `refind_x64.signed.crt`。这两个发布文件都是
公开的 `0644` 构件，因此离线验证不需要 root 权限；私钥始终留在仅 root
可访问的密钥目录中，绝不会被复制。

如果在创建任一输出后发布失败，错误信息会列出保留在
`.refind-loader-retained-*` 目录下的每个公开构件。调用用户可以在重试前检查
并删除这些报告的路径；其中只会包含已签名 EFI 镜像或公开证书，绝不会包含
私钥。删除报告的文件后，再删除空的 `.refind-loader-retained-*` 容器目录。

在向物理 ESP 写入候选 loader 之前，先运行隔离的 OVMF/QEMU 冒烟测试：

```bash
make loader-smoke
```

该检查的输出目录必须尚不存在。第一次暂存之前，准备仅 root 可访问的事务备份
目录：

```bash
make loader-backup-init CONFIRM=YES
```

通过上述门禁后，将已签名镜像暂存到备用槽位，并记录 `stage` 输出的事务路径：

```bash
make loader-stage CONFIRM=YES
BACKUP_PATH=/var/lib/refind-forest/loader-backups/loader-TRANSACTION
make loader-status BACKUP_PATH="$BACKUP_PATH"
make loader-boot-next BACKUP_PATH="$BACKUP_PATH" CONFIRM=YES
```

暂存不会修改 `refind_x64.efi` 和正常的 `BootOrder`。随后可以在维护窗口中
重启，并从候选菜单启动 Ubuntu。返回系统后，只有当状态报告确认
`BootCurrent` 就是记录的候选条目时，才允许提升候选 loader：

```bash
make loader-status BACKUP_PATH="$BACKUP_PATH"
make loader-promote BACKUP_PATH="$BACKUP_PATH" CONFIRM=YES
make loader-status BACKUP_PATH="$BACKUP_PATH"
```

如果候选验证失败，请从未修改的正常 rEFInd 或 Ubuntu 条目启动，然后恢复已记录
的事务：

```bash
make loader-rollback BACKUP_PATH="$BACKUP_PATH" CONFIRM=YES
```

任何 Make 目标都不会自动重启机器。请保留备用的旧 loader 条目和外部事务备份，
直到之后通过正常条目成功启动 Ubuntu 和 Windows。不要让 `efibootmgr` 或其他
特权固件变量管理器与 `stage`、`boot-next`、`promote` 或 `rollback` 并发
运行：Linux efivarfs 不支持按内容进行条件删除，因此事务锁可以协调相互配合的
loader 管理进程，却无法串行化独立的 root 或固件写入者。

## 安装

安装默认写入 `/boot/efi`，并需要 `sudo`。Make 目标会自行申请特权；不要运行
`sudo make`。首先记录当前启动状态和 rEFInd 配置校验和：

```bash
efibootmgr -v > /tmp/efibootmgr-before-forest.txt
sha256sum /boot/efi/EFI/refind/refind.conf > /tmp/refind-conf-before-forest.sha256
make theme-install CONFIRM=YES | tee /tmp/refind-forest-install.txt
make theme-verify
```

`theme-install` 输出的最后一行是绝对备份目录。重启前必须捕获并验证它：

```bash
BACKUP_PATH="$(tail -n 1 /tmp/refind-forest-install.txt)"
test -f "$BACKUP_PATH/backup.json"
```

备份默认保存在仓库的 `backups/` 目录下。在两个已安装操作系统和可移动介质都
通过运行验收之前，请保留所选备份。

Make 目标默认使用 `ESP=/boot/efi`。只有在核实替代挂载点及其物理身份后，
才应显式传入其他 `ESP` 值。

## 切换主题

在 Ubuntu 中激活一个方案，重启后即可看到效果：

```bash
make theme-switch VARIANT=a CONFIRM=YES
make theme-switch VARIANT=b CONFIRM=YES
```

排查意外结果时，请在切换后执行验证：

```bash
make theme-verify
```

## 回滚

使用安装时捕获的准确备份路径：

```bash
make theme-rollback BACKUP_PATH="$BACKUP_PATH" CONFIRM=YES
sha256sum -c /tmp/refind-conf-before-forest.sha256
efibootmgr -v > /tmp/efibootmgr-after-rollback.txt
diff -u /tmp/efibootmgr-before-forest.txt /tmp/efibootmgr-after-rollback.txt
make theme-verify
```

回滚会恢复原始 `refind.conf` 的逐字节内容，以及安装前已经存在的所有 Forest
文件，不会触碰无关的 EFI 文件。如果安装前不存在 Forest 主题，最后的
`theme-verify` 应以状态码 1 退出，并报告缺少 Forest manifest；这个结果确认
Forest 安装已经移除。

## 固件恢复

如果 rEFInd 无法正确显示，请打开固件启动菜单并选择已有的 Ubuntu NVRAM 条目。
Ubuntu 启动后，执行上面的回滚命令。

安装器不会修改 EFI `BootOrder`、`refind_x64.efi`、GRUB、Shim、Windows
Boot Manager、Linux 内核或 initrd。

## 运行验收

安装后完成以下检查：

1. 在未连接 USB 介质时启动。第一行应包含一个折叠后的 Ubuntu 条目和一个
   Windows 条目，默认选中 Ubuntu，并显示八秒倒计时。
2. 确认 rEFInd 发现或支持 Windows 恢复、固件、重启和关机工具时，会显示对应
   的主题图标。
3. 分别明确启动一次 Ubuntu 和 Windows。
4. 激活 B 方案，确认布局保持不变，而标记变为冰白玻璃效果。
5. 连接一个 Ventoy U 盘，以及一个直接写入 Ubuntu 或 Windows 安装镜像的
   U 盘。确认它们分别出现，移除后又消失。检查期间不要启动操作系统安装程序。

外部启动条目只会在对应介质连接时出现。可识别的 Ubuntu、Windows 和 Ventoy
介质使用相匹配的主题图标；无法识别的介质使用主题化的通用 UEFI 图标。

## 许可与第三方名称

项目原创代码和文档采用 GPL-3.0-or-later 许可。Yaru 源图稿及生成的衍生作品
采用 CC-BY-SA-4.0。下载的 rEFInd 和 GNU-EFI 输入仍适用其上游针对各文件的
许可条款。完整声明见 `LICENSE`、`LICENSES/CC-BY-SA-4.0.txt` 和
`THIRD_PARTY_NOTICES.md`。

本项目独立且非官方。rEFInd、Ubuntu、Windows、Ventoy、Linux、UEFI、ASUS、
ROG 或其他为兼容与识别目的使用的名称和标记，其权利人均未认可或背书本项目。
详见 `TRADEMARKS.md`。

涉及启动链或特权操作漏洞的安全报告必须遵循 `SECURITY.md`，不得作为公开 issue
提交。
