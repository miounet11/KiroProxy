<p align="center">
  <img src="assets/icon.svg" width="80" height="96" alt="Kiro Proxy">
</p>

<h1 align="center">Kiro API Proxy</h1>

<p align="center">
  Kiro IDE API 反向代理服务器，支持多账号轮询、Token 自动刷新、配额管理、代理会话固定
</p>

<p align="center">
  <a href="#功能特性">功能</a> •
  <a href="#快速开始">快速开始</a> •
  <a href="#cli-配置">CLI 配置</a> •
  <a href="#api-端点">API</a> •
  <a href="#许可证">许可证</a>
</p>

---

> **⚠️ 测试说明**
>
> 本项目支持 **Claude Code**、**Codex CLI**、**Gemini CLI** 三种客户端，工具调用功能已全面支持。

## 功能特性

### 核心功能
- **多协议支持** - OpenAI / Anthropic / Gemini 三种协议兼容
- **完整工具调用** - 三种协议的工具调用功能全面支持
- **图片理解** - 支持 Claude Code / Codex CLI 图片输入
- **网络搜索** - 支持 Claude Code / Codex CLI 网络搜索工具
- **多账号轮询** - 支持添加多个 Kiro 账号，自动负载均衡
- **会话粘性** - 同一会话 60 秒内使用同一账号，保持上下文
- **Web UI** - 简洁的管理界面，支持监控、日志、设置

### v1.8.0 新功能（借鉴 Tokens 平台）

- **代理会话固定 IP** - 通过 `%s` 占位符为每个账号生成唯一会话 ID
  - 确保同一账号始终使用同一 IP
  - 大幅降低封号风险
  - 支持各类代理服务商的会话固定功能

- **自定义限速/异常规则** - 根据错误响应关键字自动处理
  - 限速规则：`rate limit|LIMIT|1h` - 匹配关键字后冷却指定时间
  - 禁用规则：`account suspended|DEACTIVE` - 匹配关键字后禁用账号
  - 内置常见错误规则，支持自定义扩展

- **Token 优先级配置** - 高优先级账号优先被选中
  - 支持设置账号优先级（数字越大优先级越高）
  - 按优先级降序 + 请求数升序排序

- **轮询数量配置** - 控制每次轮询使用的账号数量
  - 设置为 0 表示不限制
  - 适合大量账号场景

- **批量导入** - 支持批量导入 Token
  - 每行一个 accessToken
  - 自动命名：前缀-001, 前缀-002, ...

### v1.6.3 功能
- **命令行工具 (CLI)** - 无 GUI 服务器也能轻松管理
  - `python run.py accounts list` - 列出账号
  - `python run.py accounts export/import` - 导出/导入账号
  - `python run.py accounts add` - 交互式添加 Token
  - `python run.py accounts scan` - 扫描本地 Token
  - `python run.py login google/github` - 命令行登录
  - `python run.py login remote` - 生成远程登录链接
- **远程登录链接** - 在有浏览器的机器上完成授权，Token 自动同步
- **账号导入导出** - 跨机器迁移账号配置
- **手动添加 Token** - 直接粘贴 accessToken/refreshToken

### v1.6.2 功能
- **Codex CLI 完整支持** - 使用 OpenAI Responses API (`/v1/responses`)
  - 完整工具调用支持（shell、file 等所有工具）
  - 图片输入支持（`input_image` 类型）
  - 网络搜索支持（`web_search` 工具）
  - 错误代码映射（rate_limit、context_length 等）
- **Claude Code 增强** - 图片理解和网络搜索完整支持

### v1.6.0 功能
- **历史消息管理** - 4 种策略处理对话长度限制，可自由组合
  - 自动截断：发送前优先保留最新上下文
  - 智能摘要：用 AI 生成早期对话摘要
  - 摘要缓存：历史变化不大时复用最近摘要
  - 错误重试：遇到长度错误时自动截断重试（默认启用）

## 工具调用支持

| 功能 | Anthropic (Claude Code) | OpenAI (Codex CLI) | Gemini |
|------|------------------------|-------------------|--------|
| 工具定义 | ✅ `tools` | ✅ `tools.function` | ✅ `functionDeclarations` |
| 工具调用响应 | ✅ `tool_use` | ✅ `tool_calls` | ✅ `functionCall` |
| 工具结果 | ✅ `tool_result` | ✅ `tool` 角色消息 | ✅ `functionResponse` |
| 强制工具调用 | ✅ `tool_choice` | ✅ `tool_choice` | ✅ `toolConfig.mode` |
| 图片理解 | ✅ | ✅ | ❌ |
| 网络搜索 | ✅ | ✅ | ❌ |

## 快速开始

### 方式一：下载预编译版本

从 [Releases](../../releases) 下载对应平台的安装包，解压后直接运行。

### 方式二：从源码运行

```bash
# 克隆项目
git clone https://github.com/miounet11/KiroProxy.git
cd KiroProxy

# 创建虚拟环境
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 安装依赖
pip install -r requirements.txt

# 运行
python run.py

# 或指定端口
python run.py 8081
```

启动后访问 http://localhost:8080

### 登录获取 Token

**方式一：在线登录（推荐）**
1. 打开 Web UI，点击「在线登录」
2. 选择登录方式：Google / GitHub / AWS Builder ID
3. 在浏览器中完成授权
4. 账号自动添加

**方式二：批量导入**
1. 点击「批量导入」
2. 每行粘贴一个 accessToken
3. 设置名称前缀
4. 点击「开始导入」

**方式三：扫描 Token**
1. 打开 Kiro IDE，使用 Google/GitHub 账号登录
2. 登录成功后 token 自动保存到 `~/.aws/sso/cache/`
3. 在 Web UI 点击「扫描 Token」添加账号

## CLI 配置

### Claude Code 配置

```bash
# 临时生效
export ANTHROPIC_BASE_URL="http://localhost:8080"
export ANTHROPIC_AUTH_TOKEN="sk-any"
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

# 或写入配置文件
mkdir -p ~/.claude
cat > ~/.claude/settings.json << 'EOF'
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://localhost:8080",
    "ANTHROPIC_AUTH_TOKEN": "sk-any",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"
  }
}
EOF
```

### Codex CLI 配置

```bash
export OPENAI_API_KEY=any
export OPENAI_BASE_URL=http://localhost:8080/v1
codex
```

## API 端点

| 协议 | 端点 | 用途 |
|------|------|------|
| OpenAI | `POST /v1/chat/completions` | Chat Completions API |
| OpenAI | `POST /v1/responses` | Responses API (Codex CLI) |
| OpenAI | `GET /v1/models` | 模型列表 |
| Anthropic | `POST /v1/messages` | Claude Code |
| Gemini | `POST /v1/models/{model}:generateContent` | Gemini CLI |

### 设置 API（v1.8.0 新增）

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/settings/proxy` | GET/POST | 代理配置（%s 占位符支持） |
| `/api/settings/rules` | GET/POST | 自定义限速/异常规则 |
| `/api/settings/rate-limit` | GET/POST | 限速配置（含轮询数量） |
| `/api/accounts/{id}/priority` | POST | 设置账号优先级 |

## 代理配置示例

```
# 普通代理
http://user:pass@proxy.com:7890

# 会话固定代理（推荐）
http://user:pass@proxy.com:7890?session=%s

# %s 会被替换为账号的唯一会话 ID
# 确保同一账号始终使用同一 IP
```

## 自定义规则示例

```
# 限速规则：关键字|LIMIT|时间
rate limit|LIMIT|1h
too many requests|LIMIT|30m
quota exceeded|LIMIT|1h

# 禁用规则：关键字|DEACTIVE
account suspended|DEACTIVE
invalid token|DEACTIVE
unauthorized|DEACTIVE
```

## 免责声明

本项目仅供学习研究，禁止商用。使用本项目产生的任何后果由使用者自行承担，与作者无关。

本项目与 Kiro / AWS / Anthropic 官方无关。
