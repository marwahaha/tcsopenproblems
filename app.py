from flask import Flask, render_template, request, redirect, url_for, flash, session
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
            user_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        );

        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );

        CREATE TABLE IF NOT EXISTS problem_categories (
            problem_id INTEGER NOT NULL,
            category_id INTEGER NOT NULL,
            PRIMARY KEY (problem_id, category_id),
            FOREIGN KEY (problem_id) REFERENCES problems (id),
            FOREIGN KEY (category_id) REFERENCES categories (id)
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

def get_categories_for_problem(conn, problem_id):
    """Get all categories for a problem."""
    return conn.execute('''
        SELECT c.* FROM categories c
        JOIN problem_categories pc ON c.id = pc.category_id
        WHERE pc.problem_id = ?
        ORDER BY c.name
    ''', (problem_id,)).fetchall()

def get_all_categories(conn):
    """Get all categories that have at least one problem."""
    return conn.execute('''
        SELECT DISTINCT c.name FROM categories c
        JOIN problem_categories pc ON c.id = pc.category_id
        ORDER BY c.name
    ''').fetchall()

def add_categories_to_problem(conn, problem_id, category_string):
    """Parse comma-separated categories and link them to a problem."""
    if not category_string:
        return
    categories = [c.strip() for c in category_string.split(',') if c.strip()]
    for cat_name in categories:
        # Get or create category
        existing = conn.execute('SELECT id FROM categories WHERE name = ?', (cat_name,)).fetchone()
        if existing:
            cat_id = existing['id']
        else:
            cursor = conn.execute('INSERT INTO categories (name) VALUES (?)', (cat_name,))
            cat_id = cursor.lastrowid
        # Link to problem
        conn.execute('INSERT OR IGNORE INTO problem_categories (problem_id, category_id) VALUES (?, ?)',
                    (problem_id, cat_id))

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
    # Add categories to each problem
    problems_with_cats = []
    for p in problems:
        cats = get_categories_for_problem(conn, p['id'])
        problems_with_cats.append({'problem': p, 'categories': cats})
    categories = get_all_categories(conn)
    conn.close()
    return render_template('index.html', problems=problems_with_cats, categories=categories)

@app.route('/category/<name>')
def category(name):
    conn = get_db()
    problems = conn.execute('''
        SELECT p.*, u.username FROM problems p
        JOIN users u ON p.user_id = u.id
        JOIN problem_categories pc ON p.id = pc.problem_id
        JOIN categories c ON pc.category_id = c.id
        WHERE c.name = ?
        ORDER BY p.created_at DESC
    ''', (name,)).fetchall()
    problems_with_cats = []
    for p in problems:
        cats = get_categories_for_problem(conn, p['id'])
        problems_with_cats.append({'problem': p, 'categories': cats})
    categories = get_all_categories(conn)
    conn.close()
    return render_template('category.html', problems=problems_with_cats, categories=categories, current_category=name)

@app.route('/problem/<int:id>')
def problem(id):
    conn = get_db()
    problem = conn.execute('''
        SELECT p.*, u.username FROM problems p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = ?
    ''', (id,)).fetchone()
    if problem is None:
        conn.close()
        flash('Problem not found')
        return redirect(url_for('index'))
    categories = get_categories_for_problem(conn, id)
    comments = conn.execute('''
        SELECT c.*, u.username FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.problem_id = ?
        ORDER BY c.created_at ASC
    ''', (id,)).fetchall()
    conn.close()
    return render_template('problem.html', problem=problem, categories=categories, comments=comments)

@app.route('/submit', methods=['GET', 'POST'])
@login_required
def submit():
    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        category_string = request.form.get('categories', '').strip()

        if not title or not description:
            flash('Title and description are required')
            return render_template('submit.html')

        conn = get_db()
        cursor = conn.execute(
            'INSERT INTO problems (title, description, user_id) VALUES (?, ?, ?)',
            (title, description, session['user_id'])
        )
        problem_id = cursor.lastrowid
        add_categories_to_problem(conn, problem_id, category_string)
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
