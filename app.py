import os
import sqlite3
import subprocess
import urllib.parse

from flask import (Flask, jsonify, make_response, redirect, render_template,
                   request, send_file, url_for)

app = Flask(__name__)
app.secret_key = "super_secret_key_1234"

DB_PATH = "/app/data/test.db"
UPLOAD_DIR = "/app/uploads"
SECRET_FILE = "/app/data/secret.txt"

# ── DB 초기화 ──────────────────────────────────────────────────────────────────
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    conn = get_db()
    c = conn.cursor()
    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY,
            username TEXT UNIQUE,
            password TEXT,
            email    TEXT,
            phone    TEXT,
            role     TEXT DEFAULT 'user'
        );
        INSERT OR IGNORE INTO users VALUES
            (1,'admin_PB','PBKOR!@','admin-pb@corp.internal','02-1588-0001','admin'),
            (2,'alice','alice_pw!','alice.kim@corp.internal','010-1234-5678','user'),
            (3,'bob',  'bob_pw!',  'bob.lee@corp.internal',  '010-9876-5432','user'),
            (4,'carol','carol_pw!','carol.park@corp.internal','010-5555-1234','user');

        CREATE TABLE IF NOT EXISTS secrets (
            id    INTEGER PRIMARY KEY,
            label TEXT,
            value TEXT
        );
        INSERT OR IGNORE INTO secrets VALUES
            (1,'FLAG','FLAG{sql_inj3ction_1s_d4ng3r0us}'),
            (2,'DB_PASS','s3cr3t_db_p4ssw0rd'),
            (3,'API_KEY','api-key-abc123xyz');
    """)
    conn.commit()
    conn.close()

    # secret.txt 생성 (Path Traversal / Command Injection 목표 파일)
    os.makedirs(os.path.dirname(SECRET_FILE), exist_ok=True)
    if not os.path.exists(SECRET_FILE):
        with open(SECRET_FILE, "w") as f:
            f.write("=== 관리자 크리덴셜 ===\nID: admin_PB\nPW: PBKOR!@\n")

    # 다운로드 취약점 테스트용 샘플 파일
    sample = os.path.join(UPLOAD_DIR, "readme.txt")
    if not os.path.exists(sample):
        with open(sample, "w") as f:
            f.write("이 파일은 테스트용 샘플입니다.\n업로드된 파일 목록에서 다운로드할 수 있습니다.\n")


# ── 메인 / 로그인 ──────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")


# [취약점 1] 인증 우회 - 클라이언트가 JSON status 값으로 인증 결정
@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "")
    password = data.get("password", "")

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE username=? AND password=?", (username, password)
    ).fetchone()
    conn.close()

    if user:
        # admin_PB 계정만 응답에 role + 더미 필드 포함 (쿠키 조작 챌린지용 힌트)
        if user["username"] == "admin_PB":
            return jsonify({
                "status": "success",
                "user_id": user["id"],
                "username": user["username"],
                "role": "admin",
                "session_token": "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW5fUEIifQ.",
                "permissions": ["read", "write", "admin"]
            })
        return jsonify({"status": "success", "user_id": user["id"], "username": user["username"]})
    return jsonify({"status": "fail", "message": "아이디 또는 비밀번호가 틀렸습니다."})


@app.route("/dashboard")
def dashboard():
    role = request.cookies.get("role", "user")
    username = request.cookies.get("username", "guest")
    return render_template("dashboard.html", role=role, username=username)


# ── [취약점 2] SQL Injection ──────────────────────────────────────────────────
@app.route("/search")
def search():
    # 원시 쿼리스트링에서 q 추출 (Flask URL 디코딩 전)
    raw_qs = request.environ.get('QUERY_STRING', '')
    raw_q = next((p[2:] for p in raw_qs.split('&') if p.startswith('q=')), '')
    query = urllib.parse.unquote_plus(raw_q)  # 화면 표시용

    results = []
    columns = []
    error = None

    conn = get_db()
    default_users = conn.execute(
        "SELECT id, username, email FROM users WHERE role='user'"
    ).fetchall()

    # 필터: 리터럴 공백(' ')과 폼 인코딩 공백('+')만 제거
    # /**/와 %20은 통과 → SQL 실행 전 공백으로 변환
    if raw_q:
        blocked = raw_q.replace('+', '').replace(' ', '')
        # 우회 허용: /**/ → 공백, %20 → 공백
        sql_input = blocked.replace('/**/', ' ').replace('%20', ' ')
        sql_input = urllib.parse.unquote(sql_input)  # 나머지 인코딩 해제

        try:
            # ★ role='user' 조건 — UNION으로 우회 시 admin + password 노출
            sql = f"SELECT id, username, email FROM users WHERE username='{sql_input}' AND role='user'"
            rows = conn.execute(sql).fetchall()
            results = rows
            if rows:
                columns = list(rows[0].keys())
        except Exception as e:
            error = str(e)
    conn.close()

    return render_template("search.html", query=query, results=results,
                           columns=columns, error=error, default_users=default_users)


# ── [취약점 3] Command Injection (; & 필터) ──────────────────────────────────
@app.route("/ping", methods=["GET", "POST"])
def ping():
    output = None
    target = ""
    if request.method == "POST":
        target = request.form.get("target", "")
        # ; 와 & 만 제거 → | 로 우회 가능
        filtered = target.replace(";", "").replace("&", "")
        try:
            output = subprocess.check_output(
                f"ping -c 2 {filtered}",
                shell=True, stderr=subprocess.STDOUT, timeout=5, text=True
            )
        except subprocess.TimeoutExpired:
            output = "[timeout]"
        except subprocess.CalledProcessError as e:
            output = e.output or "[error]"
    return render_template("ping.html", output=output, target=target)


# ── [취약점 4-A] 파일 업로드 (블랙리스트 우회) ───────────────────────────────
BLACKLIST_EXT = {"php", "jsp", "asp", "aspx", "sh", "py", "rb", "pl"}

@app.route("/upload", methods=["GET", "POST"])
def upload():
    message = None
    uploaded_files = os.listdir(UPLOAD_DIR)
    if request.method == "POST":
        f = request.files.get("file")
        if f and f.filename:
            filename = f.filename
            # 소문자 변환 없이 확장자 그대로 체크 → .PHP, .PhP, .phtml 등으로 우회 가능
            ext = filename.rsplit(".", 1)[-1] if "." in filename else ""
            if ext in BLACKLIST_EXT:
                message = f"❌ 차단된 확장자: .{ext}"
            else:
                save_path = os.path.join(UPLOAD_DIR, filename)
                f.save(save_path)
                message = f"✅ 업로드 성공: {filename}"
                uploaded_files = os.listdir(UPLOAD_DIR)
    return render_template("upload.html", message=message, files=uploaded_files)


# ── [취약점 4-B] 파일 다운로드 (Path Traversal) ──────────────────────────────
@app.route("/download")
def download():
    filename = request.args.get("file", "")
    content = None
    error = None

    # ../ 를 한 번만 제거 → ....// 으로 우회 가능
    filtered = filename.replace("../", "")
    file_path = os.path.join(UPLOAD_DIR, filtered)

    try:
        with open(file_path, "r", errors="replace") as fh:
            content = fh.read()
    except Exception as e:
        error = str(e)

    return render_template("download.html", filename=filename, filtered=filtered,
                           content=content, error=error,
                           files=os.listdir(UPLOAD_DIR))


# ── [취약점 5] IDOR ───────────────────────────────────────────────────────────
@app.route("/mypage")
def mypage():
    username = request.cookies.get("username", "")
    conn = get_db()
    # 로그인한 사용자 ID 조회
    logged_in = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    my_id = str(logged_in["id"]) if logged_in else "2"

    # ★ IDOR: user_id 파라미터로 덮어쓸 수 있음 — 본인 확인 없음
    user_id = request.args.get("user_id", my_id)

    user = conn.execute(
        "SELECT id, username, email, phone FROM users WHERE id=?", (user_id,)
    ).fetchone()
    conn.close()
    return render_template("mypage.html", user=user, user_id=str(user_id), my_id=my_id)


# ── [취약점 6] 권한 상승 (쿠키 조작) ─────────────────────────────────────────
@app.route("/admin")
def admin():
    # role 쿠키를 서버 세션 없이 그대로 신뢰
    role = request.cookies.get("role", "user")
    if role != "admin":
        return render_template("forbidden.html", role=role), 403
    conn = get_db()
    users = conn.execute("SELECT id, username, email, role FROM users").fetchall()
    conn.close()
    return render_template("admin.html", users=users)


# ── 정답지 (admin 전용) ────────────────────────────────────────────────────────
@app.route("/solutions")
def solutions():
    return render_template("solutions.html")


@app.route("/set_cookie")
def set_cookie():
    """로그인 후 쿠키 설정 (role=user 로 고정)"""
    username = request.args.get("username", "guest")
    resp = make_response(redirect(url_for("dashboard")))
    resp.set_cookie("username", username)
    resp.set_cookie("role", "user")   # ★ 브라우저에서 admin 으로 바꾸면 관리자 접근
    return resp


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("index")))
    resp.delete_cookie("username")
    resp.delete_cookie("role")
    return resp


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
