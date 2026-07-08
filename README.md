# 🔐 Flask 用户管理系统 — OWASP Top 10 安全加固实战

一个基于 Python Flask 的用户信息管理平台，**从"漏洞百出"到"生产安全"**的完整安全开发流程演示项目。

## 📋 项目说明

本项目原为教学演示用途，故意引入了多项常见 Web 安全漏洞。随后按照 **OWASP Top 10 (2021)** 框架进行全面安全审计与修复，完整展示了 **"漏洞发现 → Burp 验证 → 代码修复 → 复测确认"** 的安全开发闭环。

## 🔍 修复的漏洞（15 项）

| # | 漏洞类型 | 严重程度 | OWASP 映射 |
|---|---------|---------|-----------|
| 1 | 明文密码存储 | 🔴 严重 | A02:2021 |
| 2 | HTML 注释泄露凭据 | 🔴 严重 | A05:2021 |
| 3 | Secret Key 硬编码 | 🔴 严重 | A05:2021 |
| 4 | CSRF 防护缺失 | 🔴 严重 | A01:2021 |
| 5 | 暴力破解无防护 | 🟠 高危 | A07:2021 |
| 6 | 用户枚举 | 🟠 高危 | A07:2021 |
| 7 | Session 配置不足 | 🟠 高危 | A05:2021 |
| 8 | Session Fixation | 🟡 中危 | A07:2021 |
| 9 | 敏感信息返回前端 | 🟡 中危 | A04:2021 |
| 10 | 登出不彻底 | 🟡 中危 | A05:2021 |
| 11 | 安全响应头缺失 | 🟡 中危 | A05:2021 |
| 12 | 输入验证不足 | 🟡 中危 | A03:2021 |
| 13 | IDOR 越权 | 🟡 中危 | A01:2021 |
| 14 | Debug 模式开启 | 🟢 低危 | A05:2021 |
| 15 | HTTPS 未配置 | 🟢 低危 | A05:2021 |

## 🛠 技术栈

| 组件 | 技术 |
|------|------|
| 后端框架 | Flask 3.1 (Python 3.13) |
| 模板引擎 | Jinja2 |
| Session 管理 | Flask Signed Cookie Session |
| 密码存储 | PBKDF2-SHA256（修复后） |
| 渗透测试 | Burp Suite |
| 前端样式 | 自定义 CSS |

## 🚀 快速启动

```bash
# 1. 安装依赖
pip install flask werkzeug

# 2. 启动（开发环境）
python app.py

# 3. 启动（生产环境推荐）
SECRET_KEY="your-strong-64-char-random-key" \
FLASK_DEBUG=0 \
HTTPS_ENABLED=1 \
python app.py
```

### 默认账号

| 用户名 | 密码 | 角色 |
|--------|------|------|
| admin | admin123 | 管理员 |
| alice | alice2025 | 普通用户 |

## 📁 项目结构

```
flask_user_platform/
├── app.py                 # 主应用（安全加固版 v2.0）
├── requirements.txt       # 依赖清单
├── .gitignore
├── README.md
├── templates/
│   ├── base.html          # 基础模板
│   ├── login.html         # 登录页（CSRF token + 输入校验）
│   └── index.html         # 首页（安全状态展示）
└── static/css/
    └── style.css          # 样式表
```

## 🔒 安全加固清单

- ✅ 密码 PBKDF2-SHA256 加盐哈希存储
- ✅ CSRF Token 双重防护（Token + SameSite）
- ✅ 同一 IP 60 秒限 5 次登录尝试
- ✅ Session 30 分钟无操作自动过期
- ✅ Session 登录后重置（防 Fixation）
- ✅ 11 项安全响应头（CSP / HSTS / XFO / ...）
- ✅ 输入三层校验（长度 / 字符集 / 格式）
- ✅ 角色权限访问控制（防 IDOR）
- ✅ 统一登录错误提示（防用户枚举）
- ✅ 随机 Secret Key + 环境变量覆盖
- ✅ Debug 模式环境变量控制
- ✅ 安全登出（session.clear + cookie 过期）

## 📄 安全报告

详细的安全审计与修复报告请见项目根目录的 `Flask_安全加固报告_OWASP_Top10_v2.pdf`。

## 📝 课程作业建议

本项目的安全报告可按以下结构组织：

1. **漏洞分析** — 白盒审计 + Burp Suite 抓包验证
2. **修复实施** — 代码变更对照（🔴 Before → ✅ After）
3. **复测确认** — Burp Suite 再次验证 + 自动化测试
4. **结论** — 安全评分对比 + OWASP Top 10 映射表
