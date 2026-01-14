from flask import Flask, render_template, request, redirect, url_for, flash, session, g
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

app = Flask(__name__)
app.secret_key = 'dev-key-change-in-production'

DATABASE = 'problems.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS problems (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT,
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            problem_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (problem_id) REFERENCES problems (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        );
    ''')
    conn.commit()
    conn.close()

def get_current_user():
    if 'user_id' in session:
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        return user
    return None

@app.context_processor
def inject_user():
    return {'current_user': get_current_user()}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# Auth routes
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        if not username or not password:
            flash('Username and password required')
            return render_template('register.html')

        if len(password) < 4:
            flash('Password must be at least 4 characters')
            return render_template('register.html')

        conn = get_db()
        existing = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
        if existing:
            conn.close()
            flash('Username already taken')
            return render_template('register.html')

        conn.execute(
            'INSERT INTO users (username, password_hash) VALUES (?, ?)',
            (username, generate_password_hash(password))
        )
        conn.commit()
        conn.close()
        flash('Account created! Please log in.')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            flash('Logged in successfully')
            return redirect(url_for('index'))

        flash('Invalid username or password')
        return render_template('login.html')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out')
    return redirect(url_for('index'))

# Main routes
@app.route('/')
def index():
    conn = get_db()
    problems = conn.execute('''
        SELECT p.*, u.username FROM problems p
        JOIN users u ON p.user_id = u.id
        ORDER BY p.created_at DESC
    ''').fetchall()
    categories = conn.execute(
        'SELECT DISTINCT category FROM problems WHERE category != "" ORDER BY category'
    ).fetchall()
    conn.close()
    return render_template('index.html', problems=problems, categories=categories)

@app.route('/category/<name>')
def category(name):
    conn = get_db()
    problems = conn.execute('''
        SELECT p.*, u.username FROM problems p
        JOIN users u ON p.user_id = u.id
        WHERE p.category = ?
        ORDER BY p.created_at DESC
    ''', (name,)).fetchall()
    categories = conn.execute(
        'SELECT DISTINCT category FROM problems WHERE category != "" ORDER BY category'
    ).fetchall()
    conn.close()
    return render_template('category.html', problems=problems, categories=categories, current_category=name)

@app.route('/problem/<int:id>')
def problem(id):
    conn = get_db()
    problem = conn.execute('''
        SELECT p.*, u.username FROM problems p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    ''', (id,)).fetchone()
    comments = conn.execute('''
        SELECT c.*, u.username FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.problem_id = ?
        ORDER BY c.created_at ASC
    ''', (id,)).fetchall()
    conn.close()
    if problem is None:
        flash('Problem not found')
        return redirect(url_for('index'))
    return render_template('problem.html', problem=problem, comments=comments)

@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        category = request.form.get('category', '').strip()

        if not title or not description:
            flash('Title and description are required')
            return render_template('submit.html')

        conn = get_db()
        conn.execute(
            'INSERT INTO problems (title, description, category, user_id) VALUES (?, ?, ?, ?)',
            (title, description, category, session['user_id'])
        )
        conn.commit()
        conn.close()
        flash('Problem submitted successfully!')
        return redirect(url_for('index'))

    return render_template('submit.html')

@app.route('/problem/<int:id>/comment', methods=['POST'])
@login_required
def add_comment(id):
    content = request.form['content'].strip()

    if not content:
        flash('Comment cannot be empty')
        return redirect(url_for('problem', id=id))

    conn = get_db()
    conn.execute(
        'INSERT INTO comments (problem_id, user_id, content) VALUES (?, ?, ?)',
        (id, session['user_id'], content)
    )
    conn.commit()
    conn.close()
    return redirect(url_for('problem', id=id))

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
