# DSH Redactor

[English](#english) | 中文

一个 DeepSeek Harness（DSH）插件：在 **Agent Loop** 与 **模型适配器** 之间插入一层可逆脱敏。

模型只看到“同类型、可推理”的假值；会话日志、界面、工具参数和落盘文件始终是真实数据。

---

## 为什么需要它

把敏感数据交给云端模型时，通常只有两种选择：要么把原文发出去，要么整段删掉导致模型无法推理。

DSH Redactor 走第三条路：**只改网络边界上的字节**。

- 发给模型的 `GenerateOptions` 里，真值被替换为同类型的假值（假 IP、假邮箱、假手机号、假账号密码）；
- 模型返回的流式 chunk 里，假值被还原成真值；
- 会话日志、UI、工具执行、文件写入全部保持真值，因此工具调用、`resume`、`fork`、压缩摘要都不受影响。

## 特性

- **双向可逆**：请求侧脱敏，响应侧还原，跨 chunk 安全（占位符被流式切分也能还原）。
- **同类型仿值**：IP → 合法格式的假 IP；邮箱 → 结构相同的假邮箱；身份证/银行卡 → 校验位合法的假号码；密码 → 同长度同字符集的假密码。
- **稳定绑定**：同一个真值在一次会话内永远映射到同一个假值（HMAC 确定性派生）。
- **自动发现 + 手动词表**：
  - 内置规则：邮箱、手机号、身份证（校验位）、银行卡（Luhn）、IPv4、JWT、带前缀的 API Key、连接串凭据；
  - 结构化上下文：行首 `KEY=value`、JSON `"key": "value"`、`--flag value`、`scheme://user:pass@host`；
  - 手动添加支持精确值、通配符、正则。
- **加密落盘**：词表写入 profile 目录，AES-256-GCM 密文；密钥由内置 pepper + profile 标识通过 HKDF-SHA256 现场派生，磁盘上没有密钥文件。
- **本机地址豁免**：`localhost`、`127.0.0.1`、`0.0.0.0`、`::1` 永远不脱敏，也不会被当成假值生成。
- **会话级统计**：会话头部显示本会话命中的不同敏感项数量；面板里可以查看真值/假值对照、触发点和命中次数。

## 安装

### 方式一：作为 DSH bundle 安装（推荐）

```bash
# 把仓库克隆到本地
git clone https://github.com/1315577677/dsh-redactor.git
```

然后在 DSH 里安装本地目录：

- **桌面端**：`Plugins` → `Add plugin` → 选择克隆下来的目录；
- 或使用 `plugin_manager` 工具：`install_bundle`，target 为该目录的绝对路径。

安装后插件对所有 provider 生效（可通过 `providers` 配置限制）。

### 方式二：在插件页面填地址安装（推荐）

打开 DSH 的 **Plugins** → **Add plugin**，填入 Release 附件的地址：

```
https://github.com/1315577677/dsh-redactor/releases/download/v0.1.0/local-dsh-redactor-0.1.0.tgz
```

确认后 DSH 会下载、安装并注册这个 bundle，无需先克隆仓库。

### 方式三：从本地打包文件安装

在仓库根目录执行：

```bash
npm pack
```

会生成 `local-dsh-redactor-0.1.0.tgz`，再把该文件路径作为安装地址填入插件管理器（或使用 `plugin_manager` 的 `install_bundle`，target 指向该 tgz 文件）。

## 配置

配置写在 profile 的 `cordis.patch.yml` 中，或由插件管理器写入：

```yaml
- id: redactor
  name: '@local/dsh-redactor'
  config:
    enabled: true
    providers: ['*']          # 只对这些 provider 生效，'*' 表示全部
    strategy: surrogate       # surrogate：同类型仿值
    ipPool: documentation     # documentation：使用 RFC 5737 保留段；public：随机公网段
    emailDomain: mask         # mask：域名替换为 example.com；keep：保留原域名
    autoDiscover: true        # 请求侧命中即自动入库
    maxEntries: 5000          # 词表上限
```

## 工作原理

```
session log（真值）
      │  deriveMessages()
      ▼
GenerateOptions（真值，深冻结）
      │
      ├─ SanitizingAdapter.sanitize()   真值 → 假值
      ▼
真实适配器（pi-ai / deepseek / 任意 provider）
      │  HTTP
      ▼
    模型（只看到假值）
      │
      ├─ SanitizingAdapter.restore()    假值 → 真值（流式、跨 chunk 安全）
      ▼
agent loop → session log / UI / 工具 / 文件（真值）
```

插件在 `llm/adapters-updated` 时扫描 `LlmRuntime` 的适配器表，把每个 provider 的适配器包一层 `SanitizingAdapter`；卸载时还原。所有请求（对话、压缩摘要、标题生成、子代理、workflow）都会经过这一层。

## 加密存储

```
$DSH_PROFILE_DIR/plugins/dsh-redactor/vault.bin
```

文件结构：

```json
{
  "v": 2,
  "kdf": "hkdf-sha256",
  "salt": "<base64>",
  "nonce": "<base64>",
  "tag": "<base64>",
  "ct": "<base64 AES-256-GCM 密文>"
}
```

`salt` 明文是设计使然（它不是秘密）；真值、假值、类型、命中次数全部在 `ct` 里。直接读取或用 `grep` 搜索都只能得到密文。

## 已知限制

- **会话日志仍是明文**：session log 由宿主写入，模型若主动用 `bash` 读取 `sessions/*.jsonl` 仍能看到真值。本插件解决的是“被动进入模型上下文”，不是“模型主动翻本地文件”。
- **图片不脱敏**：图像内的文字不经过文本通道。
- **外部工具**：还原后的真值会发送给 MCP 服务器、被执行的命令和网络请求。
- **密钥不是秘密**：无口令模式下密钥可重建，定向复现算法即可解密词库；它防的是全局搜索和随手一读，不是定向攻击。
- **依赖内部字段**：适配器包装读取 `LlmRuntime.adapters`（TypeScript `private`，运行时是普通属性）。DSH 升级后需回归测试。

## 开发

插件是纯 JavaScript，无构建步骤：

```bash
node --check index.js
node --check client.js
```

目录结构：

```
dsh-redactor/
├── index.js          # Host half：适配器包装、脱敏/还原、加密词表、HTTP 桥
├── client.js         # Client half：会话视图 tab、命中计数、词表管理面板
├── cordis.patch.yml  # bundle patch
├── package.json
├── locale/           # 显示元数据
├── docs/DETAIL.md    # 插件详情页
└── icon.svg
```

## License

MIT

---

<a id="english"></a>
## English

A DeepSeek Harness plugin that inserts a **reversible redaction layer** between the agent loop and the model adapter.

The model only sees surrogate values of the same kind; the session log, UI, tool arguments and files on disk keep the real data.

- Requests are sanitized on the way out, responses are restored on the way in (stream-safe across chunk boundaries).
- Surrogates are type-faithful: fake IPs, fake emails, fake phone numbers, fake ID/card numbers with valid checksums, same-length passwords.
- Same real value always maps to the same surrogate within a session.
- The word list is stored encrypted (AES-256-GCM) under the profile directory; the key is derived with HKDF-SHA256 and never written to disk.
- `localhost`, `127.0.0.1`, `0.0.0.0` and `::1` are never redacted.

See the Chinese sections above for installation, configuration and known limitations.
