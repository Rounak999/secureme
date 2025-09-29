from flask import Flask, request, render_template, redirect, session, g, make_response, url_for
import sqlite3
import secrets
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'super-secret-key'

app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True
)

FLAG = "CTF{**********}"
DATABASE = 'users.db'


# ---------------------- DB Utilities ----------------------

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        # Create tables if they do not exist
        db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                firstname TEXT,
                lastname TEXT,
                csrf_token TEXT
            );
        ''')
        db.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            );
        ''')
        db.commit()

        admin_email = "admin@admin.com"
        admin_pass = "**********" 
        hashed = generate_password_hash(admin_pass)

        existing = db.execute("SELECT * FROM users WHERE email = ?", (admin_email,)).fetchone()
        if not existing:
            db.execute(
                "INSERT INTO users (email, password, firstname, lastname) VALUES (?, ?, ?, ?)",
                (admin_email, hashed, "Admin", "User")
            )
            db.commit()
            print(f"[INIT] Admin user created with email={admin_email} and password={admin_pass}")
        else:
            print("[INIT] Admin user already exists.")


# ---------------------- Security Headers ----------------------

@app.after_request
def add_csp_header(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'nonce-a9xkP3tLmC7eZ2qR'; "
        "script-src 'nonce-a9xkP3tLmC7eZ2qR'; base-uri 'self'; require-trusted-types-for 'script'"
    )
    return response


# ---------------------- Auth Decorator ----------------------

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
        if not user:
            session.clear()
            return redirect(url_for('login'))
        g.current_user = user
        return f(*args, **kwargs)
    return decorated_function


# ---------------------- Routes ----------------------

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect('/posts')
    return redirect('/login')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        firstname = request.form.get('firstname')
        lastname = request.form.get('lastname')

        try:
            db = get_db()
            db.execute('''
                INSERT INTO users (email, password, firstname, lastname)
                VALUES (?, ?, ?, ?)
            ''', (email, password, firstname, lastname))
            db.commit()
            return redirect('/login')
        except sqlite3.IntegrityError:
            return "Email already exists."
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            # Generate and store initial CSRF token in DB
            new_token = secrets.token_hex(16)
            db.execute("UPDATE users SET csrf_token = ? WHERE id = ?", (new_token, user['id']))
            db.commit()
            return redirect('/posts')
        return "Invalid email or password"
    return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return "If your email exists, you'll receive further instructions."
    return render_template('forgot_password.html')


@app.route('/account', methods=['GET', 'POST', 'OPTIONS'])
@login_required
def account():
    if request.method == 'OPTIONS':
        return make_response('', 204)

    db = get_db()
    user = g.current_user

    if request.method == 'POST':
        csrf_token = request.form.get('csrf_token')
        token_in_db = db.execute("SELECT csrf_token FROM users WHERE id = ?", (session['user_id'],)).fetchone()['csrf_token']
        if csrf_token != token_in_db:
            return "Invalid CSRF token", 403

        firstname = request.form.get('firstname') or user['firstname']
        lastname = request.form.get('lastname') or user['lastname']
        email = request.form.get('email') or user['email']

        try:
            db.execute('''
                UPDATE users
                SET firstname = ?, lastname = ?, email = ?
                WHERE id = ?
            ''', (firstname, lastname, email, session['user_id']))
            db.commit()
            return "Account updated successfully"
        except sqlite3.IntegrityError:
            return "Email already in use"

    new_token = secrets.token_hex(16)
    db.execute("UPDATE users SET csrf_token = ? WHERE id = ?", (new_token, session['user_id']))
    db.commit()
    return render_template('account.html', user=user, csrf_token=new_token)


@app.route('/posts', methods=['GET', 'POST'])
@login_required
def posts():
    db = get_db()
    user = g.current_user

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        if not title or not content:
            return "Title and content required.", 400
        db.execute('''
            INSERT INTO posts (user_id, title, content)
            VALUES (?, ?, ?)
        ''', (user['id'], title, content))
        db.commit()

    all_posts = db.execute('''
        SELECT posts.id, posts.title, posts.content, posts.created_at, users.firstname, users.lastname
        FROM posts
        JOIN users ON posts.user_id = users.id
        ORDER BY posts.created_at DESC
    ''').fetchall()

    try:
        user_email = (user['email'] or "").lower()
    except Exception:
        user_email = ""

    flag_to_show = FLAG if user_email == "admin@admin.com" else None

    return render_template('posts.html', posts=all_posts, user=user, flag=flag_to_show)


# ---------------------- Main ----------------------

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8000, debug=False, ssl_context=('cert.pem', 'key.pem'))
