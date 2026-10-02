# -*- coding: utf-8 -*-
# ПЛОХОЙ КОД #2 — пример для code review
# Приложение "Менеджер задач"

import flask
from flask import *
import sqlite3, hashlib, os, sys, json, re, time, threading, pickle, subprocess
from datetime import *
from random import *

app = Flask(__name__)
app.secret_key = "secret"  # 1. Секрет захардкожен

DB = "tasks.db"
conn = sqlite3.connect(DB, check_same_thread=False)  # 2. Глобальное соединение
cursor = conn.cursor()
tasks = []  # 3. Дублирование: и БД, и список в памяти
lock = None  # 4. Lock объявлен, но не инициализирован


# 5. Функция-«бог»: создаёт таблицы, пользователя, задачу и логирует всё сразу
def init():
    cursor.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER, name TEXT, pwd TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS tasks (id INTEGER, user TEXT, title TEXT, done INT)")
    cursor.execute("INSERT INTO users VALUES (1, 'admin', 'admin')")  # 6. Пароль в открытом виде
    conn.commit()
    print("init done  Untitled1:27 - # -*- coding: utf-8 -*-.py:27")  # 7. print вместо логов
    for i in range(1000):
        tasks.append(i)  # 8. Бессмысленное заполнение списка


# 9. Регистрация без валидации
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["name"]  # 10. Нет проверки на KeyError
        pwd = request.form["password"]
        # 11. Слабый хэш и соль отсутствует
        h = hashlib.md5(pwd.encode()).hexdigest()
        cursor.execute(f"INSERT INTO users VALUES (NULL, '{name}', '{h}')")  # 12. SQL-инъекция
        conn.commit()
        return "ok"
    return """
        <form method=post>
        <input name=name><input name=password type=password>
        <button>go</button></form>
    """  # 13. HTML-инъекция: пользовательские данные не экранируются


# 14. Логин: сравнение через ==, нет защиты от брутфорса
@app.route("/login", methods=["POST"])
def login():
    name = request.form.get("name")
    pwd = request.form.get("password")
    if not name or not pwd:
        return "no"
    h = hashlib.md5(pwd.encode()).hexdigest()
    cursor.execute("SELECT * FROM users WHERE name=? AND pwd=?", (name, h))
    row = cursor.fetchone()
    if row == None:  # 15. Сравнение с None через == вместо is
        return "bad"
    session["user"] = name  # 16. Нет ротации session id
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=3650)  # 17. Сессия на 10 лет
    return "ok"


# 18. Удаление задачи без проверки владельца (IDOR)
@app.route("/task/<int:tid>/delete")
def delete_task(tid):
    cursor.execute("DELETE FROM tasks WHERE id=?", (tid,))
    conn.commit()
    return "deleted"


# 19. Рендер строки вместо шаблона, XSS
@app.route("/task/<int:tid>")
def view_task(tid):
    cursor.execute("SELECT title, done FROM tasks WHERE id=?", (tid,))
    row = cursor.fetchone()
    if not row:
        return "not found", 404
    return "<h1>" + row[0] + "</h1><p>done: " + str(row[1]) + "</p>"


# 20. Массовое присваивание через setattr — prototype pollution / mass assignment
@app.route("/task/<int:tid>/update", methods=["POST"])
def update_task(tid):
    for k, v in request.form.items():
        cursor.execute(f"UPDATE tasks SET {k}=? WHERE id=?", (v, tid))  # 21. Имя колонки из ввода
    conn.commit()
    return "updated"


# 22. Кэш без инвалидации
cache = {}

@app.route("/tasks")
def list_tasks():
    user = session.get("user")
    if user in cache:
        return json.dumps(cache[user])
    cursor.execute("SELECT * FROM tasks WHERE user=?", (user,))
    rows = cursor.fetchall()
    cache[user] = rows
    return json.dumps(rows)  # 23. Возможен TypeError: sqlite3.Row не JSON-сериализуем


# 24. Долгая операция в обработчике запроса, без таймаута
@app.route("/export")
def export():
    result = []
    for row in cursor.execute("SELECT * FROM tasks"):
        time.sleep(0.01)  # 25. Искусственная задержка
        result.append(row)
    with open("/tmp/export.json", "w") as f:  # 26. Жёсткий путь, нет encoding
        json.dump(result, f)
    return "exported"


# 27. Доверяем пользовательскому вводу и запускаем shell
@app.route("/backup", methods=["POST"])
def backup():
    name = request.form.get("name", "backup")
    os.system("cp tasks.db " + name)  # 28. Command injection
    return "backup done"


# 29. Десериализация pickle из cookie — RCE
@app.route("/restore")
def restore():
    data = request.cookies.get("state")
    if data:
        obj = pickle.loads(bytes.fromhex(data))  # 30. pickle из недоверенного источника
        tasks.extend(obj)
    return "restored"


# 31. Парсинг даты без обработки ошибок
def parse_date(s):
    return datetime.strptime(s, "%Y-%m-%d")  # 32. ValueError не пойман


# 33. Рекурсивный обход с бесконечным циклом на циклических ссылках
def count_all(node, seen=[]):
    if node in seen:
        return 0
    seen.append(node)
    return 1 + sum(count_all(child, seen) for child in node.get("children", []))


# 34. Изменение аргумента по умолчанию и мутация глобального списка
def add_task(title, user="admin", tags=[]):
    tags.append(user)  # 35. Мутация аргумента
    tasks.append(title)  # 36. Мутация глобального состояния
    cursor.execute("INSERT INTO tasks (user, title, done) VALUES (?, ?, 0)", (user, title))
    conn.commit()
    return tasks


# 37. Поток без демона и без join — «потерянный» поток
def background_cleanup():
    while True:
        time.sleep(60)
        cursor.execute("DELETE FROM tasks WHERE done=1")
        conn.commit()

threading.Thread(target=background_cleanup).start()


# 38. Некорректный парсинг числа
def to_int(s):
    return int(s) if s else 0  # 39. int("abc") → ValueError


# 40. Проверка email регуляркой-«монстром»
def is_email(s):
    return re.match(r"^.+@.+\..+$", s) is not None  # 41. Пропускает "a@b.c" и мусор


# 42. Тест, который ничего не проверяет
def test_all():
    assert True or False
    assert 1 == 1


# 43. Обработчик ошибок возвращает 200 и стек
@app.errorhandler(Exception)
def on_error(e):
    return str(e), 200  # 44. Клиент видит внутренние детали


# 45. Debug-режим в "production"
if __name__ == "__main__":
    init()
    app.run(host="0.0.0.0", debug=True, port=5000)  # 46. debug=True на 0.0.0.0 — RCE