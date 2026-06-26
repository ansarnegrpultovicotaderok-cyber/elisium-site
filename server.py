from http import cookies
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from urllib.parse import unquote, urlsplit


ROOT = Path(__file__).resolve().parent
DB_PATH = ROOT / "elisium.db"
SECRET_PATH = ROOT / ".elisium_secret"
HOST = os.environ.get("ELISIUM_HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT") or os.environ.get("ELISIUM_PORT", "4173"))
MAX_JSON = 950_000
RATE_LIMIT = {}
RATE_WINDOW = 60
RATE_MAX = 18
DEVELOPER_NAMES = {"destra777", "loseyourself"}
STATUSES = {"Media", "Developer", "Member", "Assistent"}
REVIEWER_STATUSES = {"Developer", "Assistent"}
LIFETIME_TS = 4102444800


def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    con.execute("PRAGMA journal_mode = WAL")
    return con


def project_secret():
    env_secret = os.environ.get("ELISIUM_SECRET", "").strip()
    if env_secret:
        return env_secret
    if not SECRET_PATH.exists():
        SECRET_PATH.write_text(secrets.token_hex(48), encoding="utf-8")
    return SECRET_PATH.read_text(encoding="utf-8").strip()


def promo_hash(code):
    clean = "".join(str(code).upper().split())
    digest = hashlib.pbkdf2_hmac("sha256", clean.encode("utf-8"), project_secret().encode("utf-8"), 180000)
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def subscription_label(until):
    if not until:
        return "Нет активной подписки"
    if until >= LIFETIME_TS:
        return "Lifetime"
    left = max(0, int(until) - int(time.time()))
    days = left // 86400
    hours = (left % 86400) // 3600
    return f"{days} дн. {hours} ч."


def init_db():
    with db() as con:
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                uid INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                avatar TEXT,
                medal TEXT NOT NULL DEFAULT '',
                created_at INTEGER NOT NULL
            )
            """
        )
        con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username_lower ON users(lower(username))")
        existing_cols = {row["name"] for row in con.execute("PRAGMA table_info(users)").fetchall()}
        if "media_deadline" not in existing_cols:
            con.execute("ALTER TABLE users ADD COLUMN media_deadline INTEGER")
        if "subscription_until" not in existing_cols:
            con.execute("ALTER TABLE users ADD COLUMN subscription_until INTEGER")
        if "subscription_plan" not in existing_cols:
            con.execute("ALTER TABLE users ADD COLUMN subscription_plan TEXT")
        for user in con.execute("SELECT uid, medal FROM users").fetchall():
            normalized = normalize_status(user["medal"] or "")
            if normalized != (user["medal"] or ""):
                con.execute("UPDATE users SET medal = ? WHERE uid = ?", (normalized, user["uid"]))
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS media_submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid INTEGER NOT NULL,
                links TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                norm_done INTEGER,
                comment TEXT,
                reviewer_uid INTEGER,
                created_at INTEGER NOT NULL,
                reviewed_at INTEGER,
                FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE,
                FOREIGN KEY(reviewer_uid) REFERENCES users(uid) ON DELETE SET NULL
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid INTEGER NOT NULL,
                text TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS promo_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                code_hash TEXT NOT NULL UNIQUE,
                code_preview TEXT NOT NULL,
                plan TEXT NOT NULL,
                duration_days INTEGER NOT NULL,
                max_activations INTEGER NOT NULL,
                activations INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                created_by TEXT,
                disabled INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS promo_activations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                promo_id INTEGER NOT NULL,
                uid INTEGER NOT NULL,
                activated_at INTEGER NOT NULL,
                FOREIGN KEY(promo_id) REFERENCES promo_codes(id) ON DELETE CASCADE,
                FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE,
                UNIQUE(promo_id, uid)
            )
            """
        )
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS support_tickets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                uid INTEGER NOT NULL,
                subject TEXT NOT NULL,
                body TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                answer TEXT,
                reviewer_uid INTEGER,
                created_at INTEGER NOT NULL,
                resolved_at INTEGER,
                FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE,
                FOREIGN KEY(reviewer_uid) REFERENCES users(uid) ON DELETE SET NULL
            )
            """
        )
        con.execute("DELETE FROM messages WHERE uid NOT IN (SELECT uid FROM users)")
        con.execute("DELETE FROM media_submissions WHERE uid NOT IN (SELECT uid FROM users)")
        con.execute("DELETE FROM support_tickets WHERE uid NOT IN (SELECT uid FROM users)")
        con.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                uid INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(uid) REFERENCES users(uid) ON DELETE CASCADE
            )
            """
        )
        con.execute("DELETE FROM sessions WHERE uid NOT IN (SELECT uid FROM users)")


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 120000)
    return f"{salt}${base64.b64encode(digest).decode('ascii')}"


def verify_password(password, stored):
    try:
        salt, expected = stored.split("$", 1)
    except ValueError:
        return False
    return secrets.compare_digest(hash_password(password, salt), stored)


def public_user(row):
    if not row:
        return None
    status = normalize_status(row["medal"] or "")
    developer = row["username"].lower() in DEVELOPER_NAMES
    subscription_until = row["subscription_until"] if "subscription_until" in row.keys() else None
    subscription_plan = row["subscription_plan"] if "subscription_plan" in row.keys() else None
    if developer:
        subscription_until = LIFETIME_TS
        subscription_plan = "Developer Max"
    return {
        "uid": row["uid"],
        "username": row["username"],
        "avatar": row["avatar"],
        "medal": status,
        "status": status,
        "developer": developer,
        "mediaDeadline": row["media_deadline"] if "media_deadline" in row.keys() else None,
        "subscriptionUntil": subscription_until,
        "subscriptionPlan": subscription_plan,
        "subscriptionLabel": subscription_label(subscription_until),
        "createdAt": row["created_at"],
    }


def normalize_status(value):
    lookup = {status.lower(): status for status in STATUSES}
    if value and value.lower() in lookup:
        return lookup[value.lower()]
    if value == "founder":
        return "Developer"
    if value == "developer":
        return "Developer"
    return "Member"


def is_reviewer(row):
    if not row:
        return False
    return row["username"].lower() in DEVELOPER_NAMES or normalize_status(row["medal"]) in REVIEWER_STATUSES


def add_message(con, uid, text):
    con.execute("INSERT INTO messages(uid, text, created_at) VALUES (?, ?, ?)", (uid, text, int(time.time())))


def enforce_media_deadline(row):
    if not row:
        return row
    status = normalize_status(row["medal"])
    deadline = row["media_deadline"] if "media_deadline" in row.keys() else None
    now = int(time.time())
    if status == "Media":
        with db() as con:
            if not deadline:
                deadline = now + 7 * 24 * 60 * 60
                con.execute("UPDATE users SET media_deadline = ? WHERE uid = ?", (deadline, row["uid"]))
                row = con.execute("SELECT * FROM users WHERE uid = ?", (row["uid"],)).fetchone()
            elif deadline < now:
                con.execute("UPDATE users SET medal = 'Member', media_deadline = NULL WHERE uid = ?", (row["uid"],))
                add_message(con, row["uid"], "Media norm was not submitted in time. Your status changed to Member.")
                row = con.execute("SELECT * FROM users WHERE uid = ?", (row["uid"],)).fetchone()
    return row


def create_session(uid):
    token = secrets.token_urlsafe(32)
    with db() as con:
        con.execute("INSERT INTO sessions(token, uid, created_at) VALUES (?, ?, ?)", (token, uid, int(time.time())))
    return token


def auth_cookie(token):
    return f"elisium_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000"


def auth_headers_for_wsgi(uid):
    return [("Set-Cookie", auth_cookie(create_session(uid)))]


class ElisiumHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def is_forbidden_static(self):
        path = unquote(urlsplit(self.path).path).replace("\\", "/").lower()
        name = path.rsplit("/", 1)[-1]
        forbidden_ext = (".db", ".sqlite", ".py", ".pyc", ".env", ".db-wal", ".db-shm", ".secret", ".key")
        forbidden_names = {"server.py", "admin_panel.py", "pythonanywhere_wsgi.py", "elisium.db", "elisium.db-wal", "elisium.db-shm", ".elisium_secret"}
        return name in forbidden_names or any(name.endswith(ext) for ext in forbidden_ext) or "/__pycache__/" in path or "/." in path

    def send_head(self):
        if self.is_forbidden_static():
            self.send_json({"error": "forbidden"}, 403)
            return None
        return super().send_head()

    def api_json(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > MAX_JSON:
            raise ValueError("Слишком большой запрос")
        if not length:
            return {}
        raw = self.rfile.read(length)
        return json.loads(raw.decode("utf-8"))

    def end_headers(self):
        if self.headers.get("Origin") == "null":
            self.send_header("Access-Control-Allow-Origin", "null")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Elisium-Session")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "same-origin")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Cache-Control", "no-store" if self.path.startswith("/api/") else "no-cache")
        super().end_headers()

    def send_json(self, payload, status=200, extra_headers=None):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def cookie_token(self):
        header_token = self.headers.get("X-Elisium-Session", "").strip()
        if header_token:
            return header_token
        header = self.headers.get("Cookie", "")
        jar = cookies.SimpleCookie()
        jar.load(header)
        item = jar.get("elisium_session")
        return item.value if item else None

    def same_origin_post(self):
        origin = self.headers.get("Origin")
        if origin == "null":
            return True
        host = self.headers.get("Host")
        allowed = {f"http://{host}", f"https://{host}"}
        return not origin or origin in allowed

    def rate_key(self):
        forwarded = self.headers.get("X-Forwarded-For", "")
        return forwarded.split(",", 1)[0].strip() or self.client_address[0]

    def check_rate_limit(self):
        key = self.rate_key()
        now = time.time()
        bucket = [stamp for stamp in RATE_LIMIT.get(key, []) if now - stamp < RATE_WINDOW]
        if len(bucket) >= RATE_MAX:
          raise ValueError("Слишком много попыток, попробуй позже")
        bucket.append(now)
        RATE_LIMIT[key] = bucket

    def current_user(self):
        token = self.cookie_token()
        if not token:
            return None
        with db() as con:
            user = con.execute(
                """
                SELECT users.* FROM users
                JOIN sessions ON sessions.uid = users.uid
                WHERE sessions.token = ?
                """,
                (token,),
            ).fetchone()
        return enforce_media_deadline(user)

    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/api/me":
            self.send_json({"user": public_user(self.current_user())})
            return
        if path == "/api/messages":
            self.messages()
            return
        if path == "/api/review/list":
            self.review_list()
            return
        if self.is_forbidden_static():
            self.send_json({"error": "forbidden"}, 403)
            return
        super().do_GET()

    def do_POST(self):
        try:
            if not self.same_origin_post():
                self.send_json({"error": "bad_origin"}, 403)
                return
            if self.path.startswith("/api/register"):
                self.check_rate_limit()
                self.register()
            elif self.path.startswith("/api/login"):
                self.check_rate_limit()
                self.login()
            elif self.path.startswith("/api/logout"):
                self.logout()
            elif self.path.startswith("/api/profile"):
                self.update_profile()
            elif self.path.startswith("/api/promo/activate"):
                self.promo_activate()
            elif self.path.startswith("/api/media/submit"):
                self.media_submit()
            elif self.path.startswith("/api/support/submit"):
                self.support_submit()
            elif self.path.startswith("/api/support/resolve"):
                self.support_resolve()
            elif self.path.startswith("/api/review/decision"):
                self.review_decision()
            elif self.path.startswith("/api/messages/read"):
                self.messages_read()
            else:
                self.send_json({"error": "not_found"}, 404)
        except sqlite3.IntegrityError:
            self.send_json({"error": "Такой ник уже занят"}, 409)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, 400)
        except Exception:
            self.send_json({"error": "server_error"}, 500)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()

    def make_session(self, uid):
        return create_session(uid)

    def auth_headers(self, token):
        return {"Set-Cookie": auth_cookie(token)}

    def register(self):
        data = self.api_json()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        if len(username) < 3 or len(username) > 18:
            raise ValueError("Ник должен быть от 3 до 18 символов")
        if not username.replace("_", "").isalnum():
            raise ValueError("В нике можно использовать буквы, цифры и _")
        if len(password) < 5:
            raise ValueError("Пароль должен быть минимум 5 символов")
        with db() as con:
            exists = con.execute("SELECT 1 FROM users WHERE lower(username) = lower(?)", (username,)).fetchone()
            if exists:
                raise ValueError("Такой ник уже занят")
            count = con.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
            medal = "Developer" if username.lower() in DEVELOPER_NAMES else ("Developer" if count == 0 else "Member")
            cur = con.execute(
                "INSERT INTO users(username, password_hash, medal, created_at) VALUES (?, ?, ?, ?)",
                (username, hash_password(password), medal, int(time.time())),
            )
            uid = cur.lastrowid
            user = con.execute("SELECT * FROM users WHERE uid = ?", (uid,)).fetchone()
        token = self.make_session(uid)
        self.send_json({"user": public_user(user), "sessionToken": token}, 201, self.auth_headers(token))

    def login(self):
        data = self.api_json()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE lower(username) = lower(?)", (username,)).fetchone()
        if not user or not verify_password(password, user["password_hash"]):
            raise ValueError("Неверный ник или пароль")
        token = self.make_session(user["uid"])
        self.send_json({"user": public_user(user), "sessionToken": token}, 200, self.auth_headers(token))

    def logout(self):
        token = self.cookie_token()
        if token:
            with db() as con:
                con.execute("DELETE FROM sessions WHERE token = ?", (token,))
        self.send_json({"ok": True}, 200, {"Set-Cookie": "elisium_session=; Path=/; Max-Age=0; SameSite=Lax"})

    def update_profile(self):
        user = self.current_user()
        if not user:
            self.send_json({"error": "Нужно войти в аккаунт"}, 401)
            return
        data = self.api_json()
        avatar = str(data.get("avatar", "") or "")
        if avatar and (not avatar.startswith("data:image/") or len(avatar) > 900000):
            raise ValueError("Аватар должен быть картинкой до 900 KB")
        with db() as con:
            con.execute("UPDATE users SET avatar = ? WHERE uid = ?", (avatar, user["uid"]))
            updated = con.execute("SELECT * FROM users WHERE uid = ?", (user["uid"],)).fetchone()
        self.send_json({"user": public_user(updated)})

    def promo_activate(self):
        user = self.current_user()
        if not user:
            self.send_json({"error": "Нужно войти в аккаунт"}, 401)
            return
        data = self.api_json()
        code = "".join(str(data.get("code", "")).upper().split())
        if len(code) < 8 or len(code) > 64:
            raise ValueError("Проверь ключ: он слишком короткий или неверный")
        hashed = promo_hash(code)
        now = int(time.time())
        with db() as con:
            promo = con.execute(
                """
                SELECT * FROM promo_codes
                WHERE code_hash = ? AND disabled = 0
                """,
                (hashed,),
            ).fetchone()
            if not promo:
                raise ValueError("Промокод не найден или уже отключен")
            if promo["activations"] >= promo["max_activations"]:
                raise ValueError("У этого промокода закончились активации")
            used = con.execute(
                "SELECT 1 FROM promo_activations WHERE promo_id = ? AND uid = ?",
                (promo["id"], user["uid"]),
            ).fetchone()
            if used:
                raise ValueError("Ты уже активировал этот промокод")
            current_until = user["subscription_until"] if "subscription_until" in user.keys() and user["subscription_until"] else 0
            if promo["duration_days"] >= 99999:
                new_until = LIFETIME_TS
            else:
                base = max(now, int(current_until or 0))
                new_until = base + promo["duration_days"] * 86400
            con.execute(
                "UPDATE users SET subscription_until = ?, subscription_plan = ? WHERE uid = ?",
                (new_until, promo["plan"], user["uid"]),
            )
            con.execute("UPDATE promo_codes SET activations = activations + 1 WHERE id = ?", (promo["id"],))
            con.execute(
                "INSERT INTO promo_activations(promo_id, uid, activated_at) VALUES (?, ?, ?)",
                (promo["id"], user["uid"], now),
            )
            add_message(con, user["uid"], f"Промокод активирован: {promo['plan']}.")
            updated = con.execute("SELECT * FROM users WHERE uid = ?", (user["uid"],)).fetchone()
        self.send_json({"ok": True, "user": public_user(updated), "message": "Промокод успешно активирован"})

    def media_submit(self):
        user = self.current_user()
        if not user:
            self.send_json({"error": "Нужно войти в аккаунт"}, 401)
            return
        if normalize_status(user["medal"]) != "Media":
            self.send_json({"error": "Заявки доступны только Media статусу"}, 403)
            return
        data = self.api_json()
        links = [str(link).strip() for link in data.get("links", []) if str(link).strip()]
        low = [link.lower() for link in links]
        if len(links) < 2 or not any("tiktok.com" in link for link in low) or not any(("youtube.com" in link or "youtu.be" in link) for link in low):
            raise ValueError("Нужно минимум две ссылки: TikTok и YouTube")
        with db() as con:
            con.execute(
                "INSERT INTO media_submissions(uid, links, created_at) VALUES (?, ?, ?)",
                (user["uid"], json.dumps(links, ensure_ascii=False), int(time.time())),
            )
            add_message(con, user["uid"], "Media norm request sent to reviewers.")
        self.send_json({"ok": True})

    def support_submit(self):
        user = self.current_user()
        if not user:
            self.send_json({"error": "Нужно войти в аккаунт"}, 401)
            return
        data = self.api_json()
        subject = str(data.get("subject", "")).strip()
        body = str(data.get("body", "")).strip()
        if len(subject) < 3 or len(subject) > 80:
            raise ValueError("Тема должна быть от 3 до 80 символов")
        if len(body) < 8 or len(body) > 1200:
            raise ValueError("Сообщение должно быть от 8 до 1200 символов")
        now = int(time.time())
        with db() as con:
            existing = con.execute(
                "SELECT COUNT(*) AS c FROM support_tickets WHERE uid = ? AND status = 'open'",
                (user["uid"],),
            ).fetchone()["c"]
            if existing >= 3:
                raise ValueError("У тебя уже есть 3 открытых обращения. Дождись ответа команды")
            con.execute(
                "INSERT INTO support_tickets(uid, subject, body, created_at) VALUES (?, ?, ?, ?)",
                (user["uid"], subject, body, now),
            )
            add_message(con, user["uid"], "Обращение отправлено команде поддержки.")
        self.send_json({"ok": True})

    def review_list(self):
        user = self.current_user()
        if not is_reviewer(user):
            self.send_json({"error": "Нет доступа"}, 403)
            return
        with db() as con:
            rows = con.execute(
                """
                SELECT media_submissions.*, users.username, users.medal
                FROM media_submissions
                JOIN users ON users.uid = media_submissions.uid
                WHERE media_submissions.status = 'pending'
                ORDER BY media_submissions.created_at DESC
                """
            ).fetchall()
            tickets = con.execute(
                """
                SELECT support_tickets.*, users.username, users.medal
                FROM support_tickets
                JOIN users ON users.uid = support_tickets.uid
                WHERE support_tickets.status = 'open'
                ORDER BY support_tickets.created_at DESC
                """
            ).fetchall()
        items = []
        for row in rows:
            items.append({
                "type": "media",
                "id": row["id"],
                "uid": row["uid"],
                "username": row["username"],
                "status": normalize_status(row["medal"]),
                "links": json.loads(row["links"]),
                "createdAt": row["created_at"],
            })
        for row in tickets:
            items.append({
                "type": "support",
                "id": row["id"],
                "uid": row["uid"],
                "username": row["username"],
                "status": normalize_status(row["medal"]),
                "subject": row["subject"],
                "body": row["body"],
                "createdAt": row["created_at"],
            })
        items.sort(key=lambda item: item["createdAt"], reverse=True)
        self.send_json({"items": items})

    def support_resolve(self):
        reviewer = self.current_user()
        if not is_reviewer(reviewer):
            self.send_json({"error": "Нет доступа"}, 403)
            return
        data = self.api_json()
        ticket_id = int(data.get("id", 0))
        answer = str(data.get("answer", "")).strip()
        if len(answer) < 2 or len(answer) > 1200:
            raise ValueError("Ответ должен быть от 2 до 1200 символов")
        now = int(time.time())
        with db() as con:
            ticket = con.execute("SELECT * FROM support_tickets WHERE id = ? AND status = 'open'", (ticket_id,)).fetchone()
            if not ticket:
                raise ValueError("Обращение не найдено")
            con.execute(
                """
                UPDATE support_tickets
                SET status = 'resolved', answer = ?, reviewer_uid = ?, resolved_at = ?
                WHERE id = ?
                """,
                (answer, reviewer["uid"], now, ticket_id),
            )
            add_message(con, ticket["uid"], f"Поддержка ответила: {answer}")
        self.send_json({"ok": True})

    def review_decision(self):
        reviewer = self.current_user()
        if not is_reviewer(reviewer):
            self.send_json({"error": "Нет доступа"}, 403)
            return
        data = self.api_json()
        submission_id = int(data.get("id", 0))
        norm_done = bool(data.get("normDone"))
        comment = str(data.get("comment", "")).strip()
        with db() as con:
            submission = con.execute("SELECT * FROM media_submissions WHERE id = ? AND status = 'pending'", (submission_id,)).fetchone()
            if not submission:
                raise ValueError("Заявка не найдена")
            con.execute(
                """
                UPDATE media_submissions
                SET status = 'reviewed', norm_done = ?, comment = ?, reviewer_uid = ?, reviewed_at = ?
                WHERE id = ?
                """,
                (1 if norm_done else 0, comment, reviewer["uid"], int(time.time()), submission_id),
            )
            if norm_done:
                deadline = int(time.time()) + 7 * 24 * 60 * 60
                con.execute("UPDATE users SET medal = 'Media', media_deadline = ? WHERE uid = ?", (deadline, submission["uid"]))
                add_message(con, submission["uid"], "Your media norm was accepted. New 7-day timer started.")
            else:
                text = f"{reviewer['username']} ({normalize_status(reviewer['medal'])}) added a comment: {comment or 'Norm was not completed.'}"
                add_message(con, submission["uid"], text)
        self.send_json({"ok": True})

    def messages(self):
        user = self.current_user()
        if not user:
            self.send_json({"items": []})
            return
        with db() as con:
            rows = con.execute("SELECT * FROM messages WHERE uid = ? ORDER BY created_at DESC LIMIT 30", (user["uid"],)).fetchall()
        self.send_json({"items": [dict(row) for row in rows]})

    def messages_read(self):
        user = self.current_user()
        if not user:
            self.send_json({"ok": True})
            return
        with db() as con:
            con.execute("UPDATE messages SET is_read = 1 WHERE uid = ?", (user["uid"],))
        self.send_json({"ok": True})


if __name__ == "__main__":
    init_db()
    print(f"Elisium server: http://{HOST}:{PORT}/index.html")
    ThreadingHTTPServer((HOST, PORT), ElisiumHandler).serve_forever()
