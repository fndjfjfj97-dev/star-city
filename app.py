import os, sqlite3, uuid
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory, abort
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "starcity.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "static", "uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "gif"}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key-before-deployment")
app.config["MAX_CONTENT_LENGTH"] = 8 * 1024 * 1024

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('client','worker'))
        );
        CREATE TABLE IF NOT EXISTS requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER NOT NULL REFERENCES users(id),
            service TEXT NOT NULL,
            phone TEXT NOT NULL,
            details TEXT DEFAULT '',
            status TEXT NOT NULL DEFAULT 'Новая',
            worker_id INTEGER REFERENCES users(id),
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_id INTEGER NOT NULL REFERENCES requests(id) ON DELETE CASCADE,
            sender_id INTEGER NOT NULL REFERENCES users(id),
            body TEXT DEFAULT '',
            image TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );
        """)
        worker = con.execute("SELECT id FROM users WHERE email=?", ("worker@starcity.local",)).fetchone()
        if not worker:
            con.execute(
                "INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                ("Сотрудник Star City", "worker@starcity.local",
                 generate_password_hash("StarCity2026!"), "worker")
            )

def current_user():
    if "user_id" not in session:
        return None
    with db() as con:
        return con.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()

def login_required(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Сначала войдите в аккаунт.", "warning")
                return redirect(url_for("login"))
            if role and user["role"] != role:
                abort(403)
            return fn(*args, **kwargs)
        return wrapped
    return decorator

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.context_processor
def inject_user():
    return {"me": current_user()}

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not name or not email or len(password) < 8:
            flash("Заполните все поля. Пароль должен быть не короче 8 символов.", "danger")
            return render_template("register.html")
        try:
            with db() as con:
                cur = con.execute(
                    "INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                    (name, email, generate_password_hash(password), "client")
                )
                session["user_id"] = cur.lastrowid
            flash("Аккаунт создан. Теперь можно оставить заявку.", "success")
            return redirect(url_for("client_dashboard"))
        except sqlite3.IntegrityError:
            flash("Этот email уже зарегистрирован.", "danger")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        with db() as con:
            user = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("staff_dashboard" if user["role"] == "worker" else "client_dashboard"))
        flash("Неверный email или пароль.", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Вы вышли из аккаунта.", "success")
    return redirect(url_for("index"))

@app.route("/client")
@login_required("client")
def client_dashboard():
    user = current_user()
    with db() as con:
        requests = con.execute("""
            SELECT r.*, u.name AS worker_name
            FROM requests r LEFT JOIN users u ON u.id=r.worker_id
            WHERE r.client_id=? ORDER BY r.id DESC
        """, (user["id"],)).fetchall()
    return render_template("client.html", requests=requests)

@app.route("/request/new", methods=["POST"])
@login_required("client")
def new_request():
    service = request.form.get("service")
    phone = request.form.get("phone", "").strip()
    details = request.form.get("details", "").strip()
    if service not in ("Квартира без ремонта", "Квартира с ремонтом") or not phone:
        flash("Выберите услугу и укажите телефон.", "danger")
        return redirect(url_for("client_dashboard"))
    with db() as con:
        con.execute(
            "INSERT INTO requests(client_id,service,phone,details,created_at) VALUES(?,?,?,?,?)",
            (current_user()["id"], service, phone, details, datetime.now().strftime("%d.%m.%Y %H:%M"))
        )
    flash("Заявка отправлена! Сотрудник свяжется с вами в чате после принятия.", "success")
    return redirect(url_for("client_dashboard"))

@app.route("/staff")
@login_required("worker")
def staff_dashboard():
    with db() as con:
        requests = con.execute("""
            SELECT r.*, c.name AS client_name, c.email AS client_email
            FROM requests r JOIN users c ON c.id=r.client_id
            ORDER BY CASE WHEN r.status='Новая' THEN 0 ELSE 1 END, r.id DESC
        """).fetchall()
    return render_template("staff.html", requests=requests)

@app.route("/request/<int:req_id>/accept", methods=["POST"])
@login_required("worker")
def accept_request(req_id):
    with db() as con:
        item = con.execute("SELECT * FROM requests WHERE id=?", (req_id,)).fetchone()
        if not item:
            abort(404)
        if item["worker_id"] not in (None, current_user()["id"]):
            flash("Эту заявку уже принял другой сотрудник.", "warning")
        else:
            con.execute("UPDATE requests SET status='В работе', worker_id=? WHERE id=?",
                        (current_user()["id"], req_id))
            flash("Заявка принята. Чат открыт.", "success")
    return redirect(url_for("chat", req_id=req_id))

def get_request_for_user(req_id):
    user = current_user()
    with db() as con:
        item = con.execute("""
            SELECT r.*, c.name AS client_name, w.name AS worker_name
            FROM requests r JOIN users c ON c.id=r.client_id
            LEFT JOIN users w ON w.id=r.worker_id WHERE r.id=?
        """, (req_id,)).fetchone()
    if not item:
        abort(404)
    if user["role"] == "client" and item["client_id"] != user["id"]:
        abort(403)
    if user["role"] == "worker" and item["worker_id"] != user["id"]:
        abort(403)
    return item

@app.route("/chat/<int:req_id>", methods=["GET", "POST"])
@login_required()
def chat(req_id):
    item = get_request_for_user(req_id)
    if not item["worker_id"]:
        flash("Чат откроется, когда сотрудник примет заявку.", "warning")
        return redirect(url_for("client_dashboard" if current_user()["role"] == "client" else "staff_dashboard"))
    if request.method == "POST":
        body = request.form.get("body", "").strip()
        image_name = ""
        upload = request.files.get("image")
        if upload and upload.filename:
            if not allowed_file(upload.filename):
                flash("Можно прикрепить PNG, JPG, WEBP или GIF.", "danger")
                return redirect(url_for("chat", req_id=req_id))
            ext = upload.filename.rsplit(".", 1)[1].lower()
            image_name = f"{uuid.uuid4().hex}.{ext}"
            upload.save(os.path.join(UPLOAD_DIR, image_name))
        if body or image_name:
            with db() as con:
                con.execute(
                    "INSERT INTO messages(request_id,sender_id,body,image,created_at) VALUES(?,?,?,?,?)",
                    (req_id, current_user()["id"], body, image_name,
                     datetime.now().strftime("%d.%m.%Y %H:%M"))
                )
        return redirect(url_for("chat", req_id=req_id))
    with db() as con:
        messages = con.execute("""
            SELECT m.*, u.name AS sender_name, u.role AS sender_role
            FROM messages m JOIN users u ON u.id=m.sender_id
            WHERE m.request_id=? ORDER BY m.id
        """, (req_id,)).fetchall()
    return render_template("chat.html", item=item, messages=messages)

@app.errorhandler(403)
def forbidden(_):
    return render_template("error.html", message="У вас нет доступа к этой странице."), 403

@app.errorhandler(404)
def not_found(_):
    return render_template("error.html", message="Страница или заявка не найдена."), 404

os.makedirs(UPLOAD_DIR, exist_ok=True)
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
