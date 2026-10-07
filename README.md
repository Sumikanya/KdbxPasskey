# KDBX Passkey

[下载](https://github.com/Sumikanya/KdbxPasskey/releases/latest) · [安装](#安装) · [使用](#使用) · [源码构建](BUILDING.md)

将 KDBX 数据库中的通行密钥用于 Windows 登录。基于 [KeePassPasskey](https://github.com/yusei36/KeePassPasskey) 开发，直接读取本地数据库，无需安装 KeePass 2 插件。

可以继续用 KeePassXC 管理数据库，KDBX Passkey 负责向 Windows 提供其中已有的通行密钥。目前只支持认证，不支持创建通行密钥。

## 系统要求

- Windows 11 24H2 或更新版本，x64；系统需支持第三方通行密钥提供程序。
- 已配置 Windows Hello（PIN、指纹或人脸）。
- 包含 KeePassXC 兼容通行密钥的 KDBX 数据库。

## 安装

1. 从 [Releases](https://github.com/Sumikanya/KdbxPasskey/releases/latest) 下载 `.msix` 安装包和 `KdbxPasskey.cer`。
2. 右键证书 → **安装证书** → **本地计算机** → **将所有证书放入下列存储** → **受信任的人（Trusted People）**。
3. 双击 `.msix` 安装，从开始菜单打开 **KDBX Passkey**。
4. 在应用的 **设置 → Windows 通行密钥 → 打开设置** 中，启用 KDBX Passkey。

当前安装包使用自签名证书，首次安装需要手动信任。证书指纹和文件校验和随版本提供；请勿将证书导入“受信任的根证书颁发机构”。

## 使用

选择 `.kdbx` 文件，输入主密码，按需选择密钥文件，然后解锁。应用会读取通行密钥并同步到 Windows。

在网站或应用中选择通行密钥登录，再选择 KDBX Passkey，完成 Windows Hello 验证。如果同一站点有多个账户，会提示选择账户。

### 后台运行与锁定

关闭窗口或最小化后，程序保留在系统托盘。点击托盘图标可以恢复窗口，右键菜单可锁定数据库或退出程序。

数据库路径会保存。主密码仅在本次运行期间加密暂存，锁定后可在主窗口通过 Windows Hello 重新解锁。退出程序或选择“忘记本次密码”后，需要重新输入主密码。

设置中可调整闲置锁定时间、锁屏时锁定，以及登录时是否额外手动确认。网站认证仍需要 Windows Hello。

### 数据库更新

程序读取的是解锁时的数据库内容。在 KeePassXC 中新增、删除或修改通行密钥后，需要锁定并重新解锁，才能加载最新内容。

## 支持范围

- 主密码、密钥文件，或两者组合解锁。
- KeePassXC 的 `KPEX_PASSKEY_*` 通行密钥格式。
- ES256（P-256）、Ed25519 和 RS256。
- 站点分组、账户搜索、深浅主题。

只读访问数据库，不写回文件。不支持硬件 challenge-response 解锁。网站或应用必须支持 Windows 通行密钥接口；仅有普通密码条目的数据库不会显示通行密钥。

## 常见问题

**Windows 中找不到提供程序？**

确认已安装 MSIX、从开始菜单启动过应用，并在 Windows 通行密钥设置中启用 KDBX Passkey。直接运行源码目录中的 EXE 不具备安装包身份。

**数据库解锁了，但没有凭据？**

检查数据库是否包含兼容的通行密钥。回收站、历史记录和禁用搜索分组中的条目不会被使用；解析问题可在“诊断”页查看。

**锁定后无法登录？**

程序常驻时，登录请求会自动显示解锁界面，解锁后继续这次认证，无需回到网站重试。可以取消本次登录；等待超过两分钟会结束请求。恢复数据库会话和网站登录仍是两次独立的身份验证。

**如何卸载？**

在 Windows 设置中卸载应用。手动导入的证书需另行管理，不会随 MSIX 自动删除。卸载清理尚未完成测试，详见 [分发说明](docs/DISTRIBUTION.md)。

## 开发

构建环境：Windows、Python 3.11、.NET 10 SDK 和 Windows SDK。步骤见 [BUILDING.md](BUILDING.md)。问题和改进建议可提交到 [Issues](https://github.com/Sumikanya/KdbxPasskey/issues)，也欢迎 Pull Request。

本项目使用 Codex / ChatGPT 辅助编写代码和文档。

## 许可与致谢

[GPL-3.0-or-later](LICENSE)。Windows 提供程序基于 [KeePassPasskey](https://github.com/yusei36/KeePassPasskey)，界面使用 WPF UI，数据库读取使用 PyKeePass。上游署名与第三方许可见 [NOTICE.md](NOTICE.md)。
