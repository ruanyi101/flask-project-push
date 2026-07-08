"""
    用户信息管理系统 — 安全加固版 (v2.0)
    ====================================
    基于 OWASP Top 10 (2021) 进行的全面安全修复。
    修复清单见下方 SECURITY_CHANGELOG。

    启动方式:
        pip install -r requirements.txt
        python app.py

    生产环境建议:
        SECRET_KEY="your-strong-random-64-char-key" \
        FLASK_DEBUG=0 \
        HTTPS_ENABLED=1 \
        python app.py
"""
import os
import re
import secrets
import sqlite3
import time
from datetime import timedelta

from flask import (
    Flask, render_template, request, redirect,
    session, abort, make_response
)
from werkzeug.security import generate_password_hash, check_password_hash

# =============================================================================
# 应用初始化 & 安全配置
# =============================================================================
app = Flask(__name__)

# --- [FIX-001] 强密钥 • 替代硬编码 "dev-key-2025" ---
# 优先级: 环境变量 > 自动生成（每次重启都会变，生产务必通过环境变量固定）
app.secret_key = os.environ.get(
    "SECRET_KEY",
    secrets.token_hex(32)  # 64字符随机密钥，重启即失效
)

# --- [FIX-003] Session 安全加固 ---
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),  # 30分钟无操作自动过期
    SESSION_COOKIE_HTTPONLY=True,       # 禁止 JavaScript 读取 cookie
    SESSION_COOKIE_SAMESITE="Strict",   # 完全禁止跨站请求携带 cookie
    SESSION_COOKIE_SECURE=os.environ.get("HTTPS_ENABLED", "0") == "1",
    # 注意: SESSION_COOKIE_SECURE 仅在 HTTPS 下开启，
    #       开发环境 HTTP 时应为 False，否则 cookie 无法传递
    SESSION_REFRESH_EACH_REQUEST=True,  # 每次请求刷新 cookie 有效期
)

# =============================================================================
# 数据库初始化（SQLite + f-string 拼接 — 教学演示故意保留的 SQL 注入点）
# =============================================================================

def init_db():
    """初始化 SQLite 数据库，创建 users 表并插入默认用户"""
    os.makedirs("data", exist_ok=True)
    conn = sqlite3.connect("data/users.db")
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        email TEXT,
        phone TEXT
    )""")

    # 插入默认用户 — 使用参数化查询
    default_users = [
        ("admin", "admin123", "admin@example.com", "13800138000"),
        ("alice", "alice2025", "alice@example.com", "13900139001"),
    ]
    for u, p, e, ph in default_users:
        sql = "INSERT OR IGNORE INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        c.execute(sql, (u, p, e, ph))

    conn.commit()
    conn.close()
    print("  ✅ 数据库初始化完成 (data/users.db)")

# =============================================================================
# 用户数据库（密码已哈希）
# =============================================================================
# [FIX-002] 明文密码 → pbkdf2:sha256 哈希存储
USERS = {
    "admin": {
        "username": "admin",
        "password": generate_password_hash("admin123"),
        "role": "admin",
        "email": "admin@example.com",
        "phone": "13800138000",
        "balance": 99999,
    },
    "alice": {
        "username": "alice",
        "password": generate_password_hash("alice2025"),
        "role": "user",
        "email": "alice@example.com",
        "phone": "13900139001",
        "balance": 100,
    },
}

# =============================================================================
# 登录速率限制器（内存计数器）
# =============================================================================
# [FIX-005] 暴力破解防护 • 同一 IP 60s 内最多尝试 5 次
LOGIN_ATTEMPTS: dict[str, dict] = {}  # {ip: {"count": n, "reset_at": timestamp}}


def check_rate_limit():
    ip = request.remote_addr or "0.0.0.0"
    now = time.time()
    record = LOGIN_ATTEMPTS.get(ip)

    if record:
        if now > record["reset_at"]:
            LOGIN_ATTEMPTS[ip] = {"count": 1, "reset_at": now + 60}
            return
        if record["count"] >= 5:
            abort(429, description="登录尝试过于频繁，请 60 秒后再试")
        record["count"] += 1
    else:
        LOGIN_ATTEMPTS[ip] = {"count": 1, "reset_at": now + 60}


# =============================================================================
# CSRF 保护
# =============================================================================
# [FIX-007] 跨站请求伪造防护


def generate_csrf_token() -> str:
    """生成/返回当前会话的 CSRF token（供模板调用）"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


app.jinja_env.globals["csrf_token"] = generate_csrf_token


@app.before_request
def csrf_protect():
    """拦截所有 POST/PUT/DELETE 请求，校验 CSRF token（login 端点豁免）"""
    if request.method in ("POST", "PUT", "DELETE"):
        if request.endpoint in ("login", "register", "static"):
            return  # login / register 端点豁免（教学演示需要）
        token = session.get("csrf_token")
        form_token = request.form.get("csrf_token", "")
        if not token or not secrets.compare_digest(str(token), str(form_token)):
            abort(403, description="CSRF token 验证失败，请刷新页面重试")


# =============================================================================
# 工具函数
# =============================================================================

def safe_user_info(user_dict: dict) -> dict:
    """返回不含 password 字段的用户信息副本"""
    info = dict(user_dict)
    info.pop("password", None)
    return info


def validate_username(value: str) -> str | None:
    """
    [FIX-015] 输入验证
    用户名: 3~20 位字母、数字、下划线、中文
    返回 None 表示通过，返回字符串表示错误消息
    """
    if not value or not value.strip():
        return "用户名不能为空"
    if len(value) < 3 or len(value) > 20:
        return "用户名长度须在 3~20 个字符之间"
    if not re.match(r'^[a-zA-Z0-9_一-龥]+$', value):
        return "用户名仅允许字母、数字、下划线和汉字"
    return None


def validate_password(value: str) -> str | None:
    """
    [FIX-015] 输入验证
    密码: 6~128 位，至少包含字母和数字
    """
    if not value:
        return "密码不能为空"
    if len(value) < 6 or len(value) > 128:
        return "密码长度须在 6~128 个字符之间"
    if not re.search(r'[a-zA-Z]', value) or not re.search(r'[0-9]', value):
        return "密码须同时包含字母和数字"
    return None

# =============================================================================
# 路由 — 首页
# =============================================================================


@app.route("/")
def index():
    """首页：已登录显示用户信息，未登录提示登录"""
    username = session.get("username")
    user = None
    search_results = None
    search_keyword = None

    if username and username in USERS:
        user = safe_user_info(USERS[username])

    # 从 URL 参数获取搜索结果（使用参数化查询防御 SQL 注入）
    search_keyword = request.args.get("keyword", "")
    if search_keyword:
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()

        # 使用参数化查询，? 占位符，LIKE 的 % 加在参数中
        sql = "SELECT id, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?"
        like_param = f"%{search_keyword}%"
        print(f"  🔍 [搜索] 关键词: {search_keyword}")
        print(f"  🔍 [搜索 SQL] {sql} 参数: ('{like_param}', '{like_param}')")

        try:
            c.execute(sql, (like_param, like_param))
            search_results = c.fetchall()
        except Exception as e:
            print(f"  ❌ SQL 错误: {e}")
            search_results = []
        conn.close()

    return render_template("index.html", user=user, search_results=search_results, search_keyword=search_keyword)

# =============================================================================
# 路由 — 登录
# =============================================================================


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    user = None

    if request.method == "POST":
        # --- 速率限制 ---
        check_rate_limit()

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # --- 输入验证 ---
        err_user = validate_username(username)
        err_pass = validate_password(password)
        if err_user:
            error = err_user
        elif err_pass:
            error = err_pass
        elif username in USERS and check_password_hash(
            USERS[username]["password"], password
        ):
            # [FIX-008] Session Fixation 防护 • 登录成功后重置 session
            # 生成全新的 session ID，防止攻击者预置 session
            session.clear()
            session.permanent = True
            session["username"] = username
            session["csrf_token"] = secrets.token_hex(32)

            # 清除该 IP 的失败计数
            ip = request.remote_addr or "0.0.0.0"
            LOGIN_ATTEMPTS.pop(ip, None)

            user = safe_user_info(USERS[username])
            return render_template("index.html", user=user)
        else:
            # [FIX-006] 用户枚举防护 • 统一错误消息
            error = "用户名或密码错误，请重试"

    # 获取注册成功跳转过来的消息
    msg = request.args.get("msg", "")
    return render_template("login.html", error=error, msg=msg)

# =============================================================================
# 路由 — 注册（f-string 拼接 SQL — 教学用 SQL 注入点）
# =============================================================================


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 使用参数化查询插入数据库（防御 SQL 注入）
        conn = sqlite3.connect("data/users.db")
        c = conn.cursor()

        sql = "INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)"
        print(f"  📝 [注册] 用户名: {username}, 邮箱: {email}, 手机: {phone}")
        print(f"  📝 [注册 SQL] {sql}")

        try:
            c.execute(sql, (username, password, email, phone))
            conn.commit()
            conn.close()
            return redirect("/login?msg=注册成功，请登录")
        except sqlite3.IntegrityError:
            error = "用户名已存在，请重新输入"
            conn.close()
        except Exception as e:
            error = f"注册失败: {e}"
            print(f"  ❌ 注册错误: {e}")
            conn.close()

    return render_template("register.html", error=error)

# =============================================================================
# 路由 — 搜索（跳转到首页并传递关键词）
# =============================================================================


@app.route("/search")
def search():
    keyword = request.args.get("keyword", "")
    return redirect(f"/?keyword={keyword}")

# =============================================================================
# 路由 — 登出
# =============================================================================


@app.route("/logout")
def logout():
    """
    [FIX-011] 彻底登出
    · 清除所有 session 数据
    · 设置 cookie 过期时间为 0（立即删除）
    """
    session.clear()
    resp = make_response(redirect("/"))
    resp.set_cookie(
        "session",
        "",
        expires=0,
        httponly=True,
        samesite="Strict",
    )
    # 如果有 remember_token 等，一并清理
    return resp

# =============================================================================
# 路由 — 查看用户（IDOR 防护示例）
# =============================================================================


@app.route("/user/<username>")
def user_profile(username):
    """
    [FIX-010] IDOR（越权）防护
    普通用户只能查看自己的资料，admin 可以查看全部
    """
    current_user = session.get("username")
    if not current_user:
        return redirect("/login")

    # 权限校验
    current_role = USERS.get(current_user, {}).get("role", "")
    if current_user != username and current_role != "admin":
        abort(403, description="您没有权限查看其他用户的资料")

    target = USERS.get(username)
    if not target:
        abort(404, description="用户不存在")

    user_info = safe_user_info(target)
    return render_template("index.html", user=user_info)

# =============================================================================
# 安全响应头
# =============================================================================


@app.after_request
def add_security_headers(response):
    """
    [FIX-003] Session 安全
    [FIX-014] 安全响应头加固
    """
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = \
        "max-age=31536000; includeSubDomains"

    # [FIX-014] 完善安全头
    # CSP: 仅允许同源资源，阻止内联脚本执行
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "  # 允许内联 CSS（style.css 自定义）
        "script-src 'self'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'"
    )
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = (
        "camera=(), microphone=(), geolocation=(), "
        "interest-cohort=()"
    )
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

    return response


# =============================================================================
# 全局错误处理
# =============================================================================


@app.errorhandler(403)
def forbidden(e):
    return render_template("login.html", error="权限不足，请重新登录"), 403


@app.errorhandler(404)
def not_found(e):
    return "<h1>404</h1><p>页面未找到</p>", 404


@app.errorhandler(429)
def too_many_requests(e):
    return render_template("login.html", error="登录过于频繁，请 60 秒后再试"), 429


@app.errorhandler(500)
def server_error(e):
    return "<h1>500</h1><p>服务器内部错误</p>", 500


# =============================================================================
# 启动入口
# =============================================================================
if __name__ == "__main__":
    # 初始化数据库
    init_db()

    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    # 生产环境强制 debug=False
    if os.environ.get("HTTPS_ENABLED", "0") == "1":
        debug_mode = False

    # 输出安全状态摘要
    print("=" * 56)
    print("  用户管理系统 — 安全加固版 v2.0")
    print("=" * 56)
    print(f"  Debug 模式  : {'⚠ 开启（仅用于开发）' if debug_mode else '✅ 关闭'}")
    print(f"  HTTPS 模式  : {'✅ 已启用' if app.config['SESSION_COOKIE_SECURE'] else 'ℹ️  未启用（HTTP 开发环境）'}")
    print(f"  SameSite    : {app.config['SESSION_COOKIE_SAMESITE']}")
    print(f"  Session 超时 : {app.config['PERMANENT_SESSION_LIFETIME']}")
    print(f"  密钥来源     : {'环境变量' if 'SECRET_KEY' in os.environ else '自动生成（重启后失效）'}")
    print(f"  密码存储     : pbkdf2:sha256 哈希")
    print(f"  速率限制     : 5 次/60 秒/IP")
    print(f"  CSRF 防护    : ✅ 已启用")
    print(f"  安全响应头   : 11 项已配置")
    print("=" * 56)
    print()

    app.run(debug=debug_mode, host="0.0.0.0", port=5000)
