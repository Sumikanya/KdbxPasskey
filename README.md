# KDBX Passkey

Windows 通行密钥提供程序：从本地 KDBX 数据库读取已有通行密钥，通过 Windows Hello 在支持的应用和网站中认证。

**当前版本：0.2.7 · Windows x64 · GPL-3.0-or-later**

这是独立的实验性项目，基于 [KeePassPasskey](https://github.com/yusei36/KeePassPasskey) 的提供程序源码开发，不是 KeePassXC 或微软官方产品。尚未经过独立安全审计。

## 功能

- 只读打开 KDBX，支持主密码及密钥文件，不创建或写回数据库。
- 读取 KeePassXC 的 `KPEX_PASSKEY_*` 通行密钥字段，支持 ES256/P-256、Ed25519、RS256。
- Windows Hello 验证、可选手动确认、多账户选择、闲置及锁屏锁定。
- WPF 深浅主题、站点分组、搜索及紧凑列表；仅凭据区域滚动。
- 关闭或最小化到托盘；本次运行加密暂存主密码，退出后清除。
- 保存数据库路径；锁定后可在主窗口通过 Hello 恢复会话。

KDBX 是 KeePass 系列共享的数据库格式，不是 KeePassXC 独有。能否解析数据库取决于加密方式及解锁机制；能打开数据库也不代表其中有兼容的通行密钥。

## 系统要求

Windows 11 x64，具备第三方通行密钥提供程序接口（包最低版本为 24H2 / build 26100；接口是否可用还取决于系统更新）。需要配置 Windows Hello。当前不支持硬件 challenge-response 解锁。

目标应用必须调用支持第三方提供程序的 Windows 认证接口。软件不能让原本不支持通行密钥的登录窗口自动支持通行密钥。

## 安装与使用

从本仓库的 **Releases** 页面获取同一版本的 MSIX、公开证书和校验和。

当前是自签名测试版本：确认来源和证书指纹后，手动将公开的 `KdbxPasskey.cer` 导入 **本地计算机 → 受信任的人（Trusted People）**，再安装 `KdbxPasskey-0.2.7-x64.msix`。此步骤可能需要管理员权限；不要导入到根证书存储。签名私钥不会发布。参见 [分发及卸载说明](docs/DISTRIBUTION.md)。

1. 从开始菜单打开 KDBX Passkey，在 Windows 通行密钥设置中启用提供程序。
2. 选择数据库，输入主密码及可选密钥文件，解锁并同步。
3. 在支持的应用中使用通行密钥，完成 Windows Hello 和所需账户确认。
4. 关闭窗口后程序留在通知区域；真正退出请使用托盘菜单的“退出”。

数据库锁定后，先在主窗口恢复会话，再重试网站登录。会话恢复和网站登录分别验证 Hello。主密码只在进程内加密暂存；退出、重启或“忘记本次密码”后需要重新输入。托管内存中仍可能短暂存在明文副本。

本程序读取解锁时的数据库快照。使用 KeePassXC 修改数据库后，请重新解锁以刷新。KDBX 和密钥文件始终由用户管理，卸载不会删除它们。

## 构建与贡献

- [构建说明](BUILDING.md)：Windows、Python 3.11、.NET 10 和 Windows SDK；支持不签名构建。
- [贡献指南](CONTRIBUTING.md)与[安全说明](SECURITY.md)。
- [验证记录](VALIDATION.md)与[优化记录](OPTIMIZATION.md)。

0.2.7 通过 30 项后端测试、4 项管道测试、11 个界面场景及签名完整性校验；用户已于 2026-10-05 反馈：安装后可成功进行通行密钥认证。该结果限于用户已测试的场景，不代表所有网站或所有 Windows Hello 验证方式均已完成回归；干净卸载尚未验证。请勿将这些检查理解为全面安全保证。

## 许可与致谢

遵循 **GPL-3.0-or-later**，见 [LICENSE](LICENSE) 和 [NOTICE.md](NOTICE.md)。感谢 KeePassPasskey、KeePassXC、PyKeePass 和 WPF UI 的开发者。保留的上游源码、署名与第三方许可随项目提供。
