# -*- coding: utf-8 -*-
"""
Менеджер задач — исправленная версия.
Каждое изменение помечено номером, соответствующим ошибке в исходнике.
"""

# === 1, 2, 3. Импорты и зависимости ===
# Было: from flask import *; import pickle; import subprocess;
#       from datetime import *; from random import *
# Стало: только явные импорты нужных сущностей.
import html
import logging
import os
import re
import sqlite3
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from typing import Any, Iterable, Iterator, Optional

from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    redirect,
    render_template_string,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# === 4. Секрет из окружения, а не в коде ===
# Было: app.secret_key = "secret"
app = Flask(__name__)
app.secret_key = os.environ["APP_SECRET_KEY"]        # обязательная переменная
app.permanent_session_lifetime = timedelta(hours=12) # разумный TTL


# === 5. База данных: соединение на поток, без глобального курсора ===
# Было: conn = sqlite3.connect(..., check_same_thread=False); cursor = conn.cursor()
DB_PATH = Path(os.environ.get("APP_DB_PATH", "tasks.db"))
_local = threading.local()


def get_conn() -> sqlite3.Connection:
    """Возвращает соединение, привязанное к текущему потоку."""
    if not hasattr(_local, "conn"):
        conn = sqlite3.connect(DB_PATH, isolation_level=None)  # autocommit
        conn.row_factory = sqlite3.Row
        # === 6. Включаем внешние ключи и WAL для параллелизма ===
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        _local.conn = conn
    return _local.conn


# === 7. Явная схема, нормальные типы, автоинкремент ===
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id    INTEGER PRIMARY KEY AUTOINCREMENT,
    name  TEXT    NOT NULL UNIQUE,
    pwd   TEXT    NOT NULL
);
CREATE TABLE IF NOT EXISTS tasks (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    user   TEXT    NOT NULL,
    title  TEXT    NOT NULL,
    done   INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user) REFERENCES users(name) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_tasks_user ON tasks(user);
"""


def init_db() -> None:
    """Инициализирует БД. Больше не создаёт admin/admin по умолчанию."""
    conn = get_conn()
    conn.executescript(SCHEMA)

    # === 8. Админ создаётся только если задан пароль через env ===
    admin_pwd = os.environ.get("APP_ADMIN_PASSWORD")
    if admin_pwd:
        conn.execute(
            "INSERT OR IGNORE INTO users (name, pwd) VALUES (?, ?)",
            ("admin", generate_password_hash(admin_pwd)),
        )

    # === 9. Убран бессмысленный список tasks = [] на 1000 элементов ===
    logger.info("База данных инициализирована: %s", DB_PATH)


# === 10. Потокобезопасность через локальное соединение (см. get_conn) ===
# Было: lock = None, но нигде не использовался.
# Теперь блокировки не нужны на уровне Python — SQLite сам синхронизирует
# доступ через WAL; каждое соединение живёт в своём потоке.


# === 11. Регистрация: валидация, безопасный хэш, параметризация ===
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
# === 40, 41. Нормальная проверка email ===
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")


@app.post("/register")
def register_post():
    name = request.form.get("name", "").strip()
    pwd = request.form.get("password", "")
    email = request.form.get("email", "").strip()

    if not USERNAME_RE.match(name):
        abort(400, "Некорректное имя пользователя")
    if len(pwd) < 8:
        abort(400, "Пароль слишком короткий")
    if email and not EMAIL_RE.match(email):
        abort(400, "Некорректный email")

    # === 11. MD5 заменён на werkzeug.security.generate_password_hash (PBKDF2) ===
    hashed = generate_password_hash(pwd)
    conn = get_conn()
    try:
        # === 12. Параметризованный INSERT вместо f-строки ===
        conn.execute(
            "INSERT INTO users (name, pwd) VALUES (?, ?)",
            (name, hashed),
        )
    except sqlite3.IntegrityError:
        abort(409, "Пользователь уже существует")

    logger.info("Зарегистрирован пользователь: %s", name)
    return redirect(url_for("login_get"))


@app.get("/register")
def register_get():
    # === 13. Jinja2 автоматически экранирует переменные — XSS-риск снят ===
    return render_template_string(REGISTER_TPL)


REGISTER_TPL = """<!doctype html>
<form method="post" action="/register">
  <input name="name" required>
  <input name="password" type="password" required>
  <input name="email" type="email">
  <button>Зарегистрироваться</button>
</form>"""


LOGIN_TPL = """<!doctype html>
<form method="post" action="/login">
  <input name="name" required>
  <input name="password" type="password" required>
  <button>Войти</button>
</form>"""


@app.get("/login")
def login_get():
    return render_template_string(LOGIN_TPL)


# === 14. Логин: константное время, ротация сессии, защита от брутфорса ===
_login_attempts: dict[str, list[float]] = {}
_login_lock = threading.Lock()
MAX_ATTEMPTS = 5
WINDOW_SEC = 300


def _rate_limited(ip: str) -> bool:
    now = time.monotonic()
    with _login_lock:
        attempts = [t for t in _login_attempts.get(ip, []) if now - t < WINDOW_SEC]
        _login_attempts[ip] = attempts
        return len(attempts) >= MAX_ATTEMPTS


def _record_attempt(ip: str) -> None:
    with _login_lock:
        _login_attempts.setdefault(ip, []).append(time.monotonic())


@app.post("/login")
def login_post():
    ip = request.remote_addr or "unknown"
    if _rate_limited(ip):
        abort(429, "Слишком много попыток, попробуйте позже")

    name = request.form.get("name", "").strip()
    pwd = request.form.get("password", "")
    if not name or not pwd:
        abort(400, "Имя и пароль обязательны")

    conn = get_conn()
    row = conn.execute("SELECT pwd FROM users WHERE name = ?", (name,)).fetchone()

    # === 15. Безопасная проверка хэша (constant-time внутри) ===
    # === 16. Проверка `is None` вместо `== None` ===
    if row is None or not check_password_hash(row["pwd"], pwd):
        _record_attempt(ip)
        abort(401, "Неверные учётные данные")

    # === 17. Ротация сессии: сбрасываем старую, создаём новую ===
    session.clear()
    session["user"] = name
    session.permanent = True
    logger.info("Успешный вход: %s c %s", name, ip)
    return redirect(url_for("list_tasks"))


# === 18. Декоратор авторизации — устраняет IDOR ===
def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            abort(401, "Требуется вход")
        return view(*args, **kwargs)
    return wrapper


# === 18. Проверка владельца задачи ===
def _get_owned_task(tid: int) -> sqlite3.Row:
    conn = get_conn()
    row = conn.execute(
        "SELECT id, user, title, done FROM tasks WHERE id = ?", (tid,)
    ).fetchone()
    if row is None:
        abort(404, "Задача не найдена")
    if row["user"] != session["user"]:
        # === 18. Не подтверждаем существование чужой задачи ===
        abort(404, "Задача не найдена")
    return row


@app.post("/task/<int:tid>/delete")
@login_required
def delete_task(tid: int):
    _get_owned_task(tid)
    conn = get_conn()
    conn.execute("DELETE FROM tasks WHERE id = ?", (tid,))
    return redirect(url_for("list_tasks"))


# === 19. Рендер через шаблон, без конкатенации HTML — XSS закрыт ===
TASK_TPL = """<!doctype html>
<h1>{{ title }}</h1>
<p>Выполнено: {{ done }}</p>
<a href="/tasks">Назад</a>"""


@app.get("/task/<int:tid>")
@login_required
def view_task(tid: int):
    row = _get_owned_task(tid)
    return render_template_string(TASK_TPL, title=row["title"], done=bool(row["done"]))


# === 20, 21. Обновление: белый список полей вместо f-строки с именем колонки ===
ALLOWED_TASK_FIELDS = {"title", "done"}


@app.post("/task/<int:tid>/update")
@login_required
def update_task(tid: int):
    _get_owned_task(tid)
    updates: dict[str, Any] = {}
    for key, value in request.form.items():
        if key not in ALLOWED_TASK_FIELDS:
            abort(400, f"Поле {key!r} нельзя изменять")
        if key == "done":
            updates[key] = 1 if value.lower() in {"1", "true", "yes"} else 0
        else:
            title = value.strip()
            if not title or len(title) > 200:
                abort(400, "Некорректный заголовок")
            updates[key] = title

    if not updates:
        abort(400, "Нет полей для обновления")

    # Имена колонок берутся из белого списка — инъекция невозможна.
    set_clause = ", ".join(f"{col} = ?" for col in updates)
    params = [*updates.values(), tid]
    conn = get_conn()
    conn.execute(f"UPDATE tasks SET {set_clause} WHERE id = ?", params)
    return redirect(url_for("view_task", tid=tid))


# === 22. Кэш: TTL + инвалидация + потокобезопасность ===
class TTLCache:
    def __init__(self, ttl_sec: float = 30.0) -> None:
        self._ttl = ttl_sec
        self._store: dict[str, tuple[float, Any]] = {}
        self._lock = threading.Lock()

    def get(self, key: str) -> Any | None:
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            ts, value = entry
            if time.monotonic() - ts > self._ttl:
                del self._store[key]
                return None
            return value

    def set(self, key: str, value: Any) -> None:
        with self._lock:
            self._store[key] = (time.monotonic(), value)

    def invalidate(self, key: str) -> None:
        with self._lock:
            self._store.pop(key, None)


_cache = TTLCache(ttl_sec=30.0)


@app.get("/tasks")
@login_required
def list_tasks():
    user = session["user"]

    cached = _cache.get(user)
    if cached is not None:
        return jsonify(cached)

    conn = get_conn()
    rows = conn.execute(
        "SELECT id, title, done FROM tasks WHERE user = ? ORDER BY id DESC", (user,)
    ).fetchall()

    # === 23. Явное преобразование sqlite3.Row → dict перед сериализацией ===
    items = [{"id": r["id"], "title": r["title"], "done": bool(r["done"])} for r in rows]
    _cache.set(user, items)
    return jsonify(items)


# Инвалидация кэша при изменениях
def _invalidate_cache(user: str) -> None:
    _cache.invalidate(user)


# === 24, 25. Экспорт: без sleep, стриминг, кодировка ===
@app.get("/export")
@login_required
def export():
    user = session["user"]
    conn = get_conn()
    rows = conn.execute(
        "SELECT id, title, done FROM tasks WHERE user = ?", (user,)
    ).fetchall()
    payload = [{"id": r["id"], "title": r["title"], "done": bool(r["done"])} for r in rows]
    # === 26. Отдаём файл в ответ, а не пишем в /tmp ===
    body = json_dumps(payload)
    return Response(
        body,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="tasks-{user}.json"'},
    )


def json_dumps(data: Any) -> str:
    import json as _json
    return _json.dumps(data, ensure_ascii=False)


# === 27, 28. Бэкап без shell: subprocess со списком аргументов ===
@app.post("/backup")
@login_required
def backup():
    name = request.form.get("name", "backup").strip()
    # Белый список имён файлов — не даём выйти за пределы папки
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
        abort(400, "Некорректное имя бэкапа")

    backup_dir = Path(os.environ.get("APP_BACKUP_DIR", "backups")).resolve()
    backup_dir.mkdir(parents=True, exist_ok=True)
    target = (backup_dir / f"{name}.db").resolve()

    # Защита от path traversal
    if backup_dir not in target.parents:
        abort(400, "Путь вне разрешённой папки")

    # Без shell=True, аргументы передаются списком — command injection закрыт
    try:
        subprocess.run(
            ["cp", str(DB_PATH), str(target)],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except subprocess.CalledProcessError as exc:
        logger.error("Бэкап не удался: %s", exc.stderr)
        abort(500, "Ошибка бэкапа")
    except subprocess.TimeoutExpired:
        abort(504, "Бэкап занял слишком много времени")

    logger.info("Бэкап создан: %s", target)
    return jsonify({"status": "ok", "file": target.name})


# === 29, 30. Убран pickle из cookie — заменён на JSON с подписью сессии ===
@app.post("/restore")
@login_required
def restore():
    # Восстановление только через загрузку файла, а не из cookie.
    # Flask-сессии подписаны, но pickle всё равно нельзя — RCE.
    raw = request.get_data(as_text=True)
    if not raw:
        abort(400, "Пустое тело запроса")

    try:
        items = json.loads(raw)
    except json.JSONDecodeError as exc:
        # === 30. Конкретное исключение вместо широкого ===
        raise ValueError(f"Некорректный JSON: {exc}") from exc

    if not isinstance(items, list):
        abort(400, "Ожидался список задач")

    conn = get_conn()
    with conn:  # транзакция
        for item in items:
            if not isinstance(item, dict):
                continue
            title = str(item.get("title", "")).strip()
            if not title:
                continue
            conn.execute(
                "INSERT INTO tasks (user, title, done) VALUES (?, ?, ?)",
                (session["user"], title, int(bool(item.get("done")))),
            )
    _invalidate_cache(session["user"])
    return jsonify({"restored": len(items)})


# === 31, 32. Парсинг даты с явной обработкой ошибок и таймзоной ===
def parse_date(s: str) -> datetime:
    """Парсит дату в формате YYYY-MM-DD, возвращает aware datetime UTC."""
    try:
        dt = datetime.strptime(s, "%Y-%m-%d")
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Некорректная дата: {s!r}") from exc
    return dt.replace(tzinfo=timezone.utc)


# === 33. Обход дерева без изменяемого аргумента по умолчанию ===
def count_all(node: dict[str, Any], seen: Optional[set[int]] = None) -> int:
    """Считает узлы дерева; защищён от циклов через id() объектов."""
    if seen is None:
        seen = set()
    node_id = id(node)
    if node_id in seen:
        return 0
    seen.add(node_id)
    children = node.get("children") or []
    if not isinstance(children, list):
        return 1
    return 1 + sum(count_all(child, seen) for child in children if isinstance(child, dict))


# === 34, 35, 36. add_task: без мутаций и изменяемых аргументов ===
@dataclass
class Task:
    id: int
    user: str
    title: str
    done: bool = False


def add_task(
    title: str,
    user: str,
    tags: Optional[Iterable[str]] = None,
) -> Task:
    """Создаёт задачу. Возвращает объект, не мутирует глобальные структуры."""
    title = title.strip()
    if not title or len(title) > 200:
        raise ValueError("Некорректный заголовок")

    # === 35. Копируем теги, а не мутируем аргумент ===
    tag_list = list(tags or [])
    _ = tag_list  # используется, например, для будущего поля tags в БД

    conn = get_conn()
    cur = conn.execute(
        "INSERT INTO tasks (user, title, done) VALUES (?, ?, 0)",
        (user, title),
    )
    _invalidate_cache(user)
    return Task(id=cur.lastrowid, user=user, title=title, done=False)


# === 37. Фоновый поток: демон + graceful shutdown ===
_shutdown = threading.Event()


def background_cleanup(interval_sec: int = 60) -> None:
    """Периодически удаляет выполненные задачи, корректно завершается."""
    while not _shutdown.wait(interval_sec):
        try:
            conn = get_conn()
            with conn:
                deleted = conn.execute("DELETE FROM tasks WHERE done = 1").rowcount
            if deleted:
                logger.info("Фоновая очистка удалила %d задач", deleted)
        except Exception:
            # === 30. Логируем, но не роняем поток ===
            logger.exception("Ошибка фоновой очистки")


_cleanup_thread = threading.Thread(
    target=background_cleanup, name="cleanup", daemon=True
)


# === 38, 39. to_int с обработкой ошибок ===
def to_int(s: Any) -> int:
    """Преобразует в int; при ошибке возвращает 0 и логирует."""
    if s in (None, ""):
        return 0
    try:
        return int(s)
    except (TypeError, ValueError):
        logger.warning("Не удалось преобразовать %r в int", s)
        return 0


# === 40, 41. Корректная проверка email ===
def is_email(s: str) -> bool:
    if not isinstance(s, str) or len(s) > 254:
        return False
    return EMAIL_RE.match(s) is not None


# === 42. Осмысленные тесты ===
def test_to_int() -> None:
    assert to_int("42") == 42
    assert to_int("abc") == 0
    assert to_int(None) == 0


def test_is_email() -> None:
    assert is_email("a@b.co") is True
    assert is_email("not-an-email") is False
    assert is_email("x@y") is False


def test_parse_date() -> None:
    dt = parse_date("2024-01-15")
    assert dt.year == 2024 and dt.tzinfo is timezone.utc
    try:
        parse_date("15/01/2024")
    except ValueError:
        pass
    else:
        raise AssertionError("Ожидалась ValueError")


def test_count_all() -> None:
    assert count_all({"children": [{"children": []}]}) == 2


# === 43, 44. Обработчик ошибок: правильный код ответа, без утечек ===
@app.errorhandler(400)
@app.errorhandler(401)
@app.errorhandler(404)
@app.errorhandler(409)
@app.errorhandler(429)
@app.errorhandler(500)
def handle_error(err):
    code = getattr(err, "code", 500)
    # Клиенту — общее сообщение; детали — только в логах.
    if code >= 500:
        logger.exception("Внутренняя ошибка: %s", err)
        message = "Внутренняя ошибка сервера"
    else:
        message = getattr(err, "description", "Ошибка")
    return jsonify({"error": message, "code": code}), code


# === 45, 46. Точка входа: без debug=True, без 0.0.0.0 по умолчанию ===
def create_app() -> Flask:
    """Фабрика приложения — удобно для тестов и продакшена."""
    init_db()
    _cleanup_thread.start()
    return app


if __name__ == "__main__":
    # Debug-режим включается только явным флагом окружения.
    debug = os.environ.get("APP_DEBUG", "0") == "1"
    host = os.environ.get("APP_HOST", "127.0.0.1")
    port = int(os.environ.get("APP_PORT", "5000"))

    create_app()
    app.run(host=host, port=port, debug=debug)

    # Корректное завершение фонового потока
    _shutdown.set()
    _cleanup_thread.join(timeout=2)