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
            is_admin INTEGER DEFAULT 0,
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

        CREATE TABLE IF NOT EXISTS votes (
            user_id INTEGER NOT NULL,
            problem_id INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, problem_id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (problem_id) REFERENCES problems (id)
        );

        CREATE TABLE IF NOT EXISTS ratings (
            user_id INTEGER NOT NULL,
            problem_id INTEGER NOT NULL,
            impact INTEGER NOT NULL CHECK (impact >= 1 AND impact <= 5),
            solvability INTEGER NOT NULL CHECK (solvability >= 1 AND solvability <= 5),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, problem_id),
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (problem_id) REFERENCES problems (id)
        );
    ''')
    conn.commit()

    # Add is_admin column if it doesn't exist (for existing databases)
    try:
        conn.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER DEFAULT 0')
        conn.commit()
    except sqlite3.OperationalError:
        pass  # Column already exists

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
        existing = conn.execute('SELECT id FROM categories WHERE name = ?', (cat_name,)).fetchone()
        if existing:
            cat_id = existing['id']
        else:
            cursor = conn.execute('INSERT INTO categories (name) VALUES (?)', (cat_name,))
            cat_id = cursor.lastrowid
        conn.execute('INSERT OR IGNORE INTO problem_categories (problem_id, category_id) VALUES (?, ?)',
                    (problem_id, cat_id))

def get_vote_count(conn, problem_id):
    """Get the number of votes for a problem."""
    result = conn.execute('SELECT COUNT(*) as count FROM votes WHERE problem_id = ?', (problem_id,)).fetchone()
    return result['count']

def user_has_voted(conn, user_id, problem_id):
    """Check if a user has voted for a problem."""
    result = conn.execute('SELECT 1 FROM votes WHERE user_id = ? AND problem_id = ?', (user_id, problem_id)).fetchone()
    return result is not None

def get_avg_ratings(conn, problem_id):
    """Get average impact and solvability ratings for a problem."""
    result = conn.execute('''
        SELECT AVG(impact) as avg_impact, AVG(solvability) as avg_solvability, COUNT(*) as count
        FROM ratings WHERE problem_id = ?
    ''', (problem_id,)).fetchone()
    return {
        'avg_impact': round(result['avg_impact'], 1) if result['avg_impact'] else None,
        'avg_solvability': round(result['avg_solvability'], 1) if result['avg_solvability'] else None,
        'count': result['count']
    }

def get_user_rating(conn, user_id, problem_id):
    """Get a user's rating for a problem."""
    return conn.execute(
        'SELECT impact, solvability FROM ratings WHERE user_id = ? AND problem_id = ?',
        (user_id, problem_id)
    ).fetchone()

def get_current_user():
    if 'user_id' in session:
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()
        return user
    return None

@app.context_processor
def inject_user():
    user = get_current_user()
    return {
        'current_user': user,
        'is_admin': user['is_admin'] if user else False
    }

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue')
            return redirect(url_for('login'))
        user = get_current_user()
        if not user or not user['is_admin']:
            flash('Admin access required')
            return redirect(url_for('index'))
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
    # Get problems with average ratings, sorted by avg solvability then impact
    problems = conn.execute('''
        SELECT p.*, u.username,
               (SELECT COUNT(*) FROM votes v WHERE v.problem_id = p.id) as vote_count,
               (SELECT AVG(impact) FROM ratings r WHERE r.problem_id = p.id) as avg_impact,
               (SELECT AVG(solvability) FROM ratings r WHERE r.problem_id = p.id) as avg_solvability,
               (SELECT COUNT(*) FROM ratings r WHERE r.problem_id = p.id) as rating_count
        FROM problems p
        JOIN users u ON p.user_id = u.id
        ORDER BY avg_solvability DESC NULLS LAST, avg_impact DESC NULLS LAST, p.created_at DESC
    ''').fetchall()

    user_id = session.get('user_id')
    problems_with_data = []
    for p in problems:
        cats = get_categories_for_problem(conn, p['id'])
        has_voted = user_has_voted(conn, user_id, p['id']) if user_id else False
        problems_with_data.append({
            'problem': p,
            'categories': cats,
            'vote_count': p['vote_count'],
            'has_voted': has_voted,
            'avg_impact': round(p['avg_impact'], 1) if p['avg_impact'] else None,
            'avg_solvability': round(p['avg_solvability'], 1) if p['avg_solvability'] else None,
            'rating_count': p['rating_count']
        })
    categories = get_all_categories(conn)
    conn.close()
    return render_template('index.html', problems=problems_with_data, categories=categories)

@app.route('/category/<name>')
def category(name):
    conn = get_db()
    problems = conn.execute('''
        SELECT p.*, u.username,
               (SELECT COUNT(*) FROM votes v WHERE v.problem_id = p.id) as vote_count,
               (SELECT AVG(impact) FROM ratings r WHERE r.problem_id = p.id) as avg_impact,
               (SELECT AVG(solvability) FROM ratings r WHERE r.problem_id = p.id) as avg_solvability,
               (SELECT COUNT(*) FROM ratings r WHERE r.problem_id = p.id) as rating_count
        FROM problems p
        JOIN users u ON p.user_id = u.id
        JOIN problem_categories pc ON p.id = pc.problem_id
        JOIN categories c ON pc.category_id = c.id
        WHERE c.name = ?
        ORDER BY avg_solvability DESC NULLS LAST, avg_impact DESC NULLS LAST, p.created_at DESC
    ''', (name,)).fetchall()

    user_id = session.get('user_id')
    problems_with_data = []
    for p in problems:
        cats = get_categories_for_problem(conn, p['id'])
        has_voted = user_has_voted(conn, user_id, p['id']) if user_id else False
        problems_with_data.append({
            'problem': p,
            'categories': cats,
            'vote_count': p['vote_count'],
            'has_voted': has_voted,
            'avg_impact': round(p['avg_impact'], 1) if p['avg_impact'] else None,
            'avg_solvability': round(p['avg_solvability'], 1) if p['avg_solvability'] else None,
            'rating_count': p['rating_count']
        })
    categories = get_all_categories(conn)
    conn.close()
    return render_template('category.html', problems=problems_with_data, categories=categories, current_category=name)

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
    vote_count = get_vote_count(conn, id)
    user_id = session.get('user_id')
    has_voted = user_has_voted(conn, user_id, id) if user_id else False

    # Get ratings
    avg_ratings = get_avg_ratings(conn, id)
    user_rating = get_user_rating(conn, user_id, id) if user_id else None

    comments = conn.execute('''
        SELECT c.*, u.username FROM comments c
        JOIN users u ON c.user_id = u.id
        WHERE c.problem_id = ?
        ORDER BY c.created_at ASC
    ''', (id,)).fetchall()
    conn.close()
    return render_template('problem.html', problem=problem, categories=categories,
                         comments=comments, vote_count=vote_count, has_voted=has_voted,
                         avg_ratings=avg_ratings, user_rating=user_rating)

@app.route('/problem/<int:id>/vote', methods=['POST'])
@login_required
def vote(id):
    conn = get_db()
    user_id = session['user_id']

    existing = conn.execute('SELECT 1 FROM votes WHERE user_id = ? AND problem_id = ?',
                           (user_id, id)).fetchone()
    if existing:
        conn.execute('DELETE FROM votes WHERE user_id = ? AND problem_id = ?', (user_id, id))
    else:
        conn.execute('INSERT INTO votes (user_id, problem_id) VALUES (?, ?)', (user_id, id))

    conn.commit()
    conn.close()
    return redirect(request.referrer or url_for('problem', id=id))

@app.route('/problem/<int:id>/rate', methods=['POST'])
@login_required
def rate(id):
    conn = get_db()
    user_id = session['user_id']

    try:
        impact = int(request.form['impact'])
        solvability = int(request.form['solvability'])

        if not (1 <= impact <= 5 and 1 <= solvability <= 5):
            flash('Ratings must be between 1 and 5')
            return redirect(url_for('problem', id=id))

        # Insert or replace rating
        conn.execute('''
            INSERT OR REPLACE INTO ratings (user_id, problem_id, impact, solvability)
            VALUES (?, ?, ?, ?)
        ''', (user_id, id, impact, solvability))
        conn.commit()
        flash('Rating submitted!')
    except (ValueError, KeyError):
        flash('Invalid rating values')

    conn.close()
    return redirect(url_for('problem', id=id))

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

# Admin routes
@app.route('/admin')
@admin_required
def admin_dashboard():
    conn = get_db()
    categories = conn.execute('SELECT * FROM categories ORDER BY name').fetchall()
    conn.close()
    return render_template('admin/dashboard.html', categories=categories)

@app.route('/admin/problem/<int:id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_problem(id):
    conn = get_db()
    problem = conn.execute('SELECT * FROM problems WHERE id = ?', (id,)).fetchone()
    if not problem:
        conn.close()
        flash('Problem not found')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        title = request.form['title'].strip()
        description = request.form['description'].strip()
        category_string = request.form.get('categories', '').strip()

        if not title or not description:
            flash('Title and description are required')
            categories = get_categories_for_problem(conn, id)
            category_string = ', '.join([c['name'] for c in categories])
            conn.close()
            return render_template('admin/edit_problem.html', problem=problem, category_string=category_string)

        conn.execute('UPDATE problems SET title = ?, description = ? WHERE id = ?',
                    (title, description, id))
        # Update categories - remove old ones and add new ones
        conn.execute('DELETE FROM problem_categories WHERE problem_id = ?', (id,))
        add_categories_to_problem(conn, id, category_string)
        conn.commit()
        conn.close()
        flash('Problem updated successfully')
        return redirect(url_for('problem', id=id))

    categories = get_categories_for_problem(conn, id)
    category_string = ', '.join([c['name'] for c in categories])
    conn.close()
    return render_template('admin/edit_problem.html', problem=problem, category_string=category_string)

@app.route('/admin/problem/<int:id>/delete', methods=['POST'])
@admin_required
def admin_delete_problem(id):
    conn = get_db()
    # Delete related data first (foreign key constraints)
    conn.execute('DELETE FROM problem_categories WHERE problem_id = ?', (id,))
    conn.execute('DELETE FROM comments WHERE problem_id = ?', (id,))
    conn.execute('DELETE FROM votes WHERE problem_id = ?', (id,))
    conn.execute('DELETE FROM ratings WHERE problem_id = ?', (id,))
    conn.execute('DELETE FROM problems WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('Problem deleted successfully')
    return redirect(url_for('index'))

@app.route('/admin/comment/<int:id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_comment(id):
    conn = get_db()
    comment = conn.execute('SELECT * FROM comments WHERE id = ?', (id,)).fetchone()
    if not comment:
        conn.close()
        flash('Comment not found')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        content = request.form['content'].strip()
        if not content:
            flash('Comment cannot be empty')
            conn.close()
            return render_template('admin/edit_comment.html', comment=comment)

        conn.execute('UPDATE comments SET content = ? WHERE id = ?', (content, id))
        conn.commit()
        problem_id = comment['problem_id']
        conn.close()
        flash('Comment updated successfully')
        return redirect(url_for('problem', id=problem_id))

    conn.close()
    return render_template('admin/edit_comment.html', comment=comment)

@app.route('/admin/comment/<int:id>/delete', methods=['POST'])
@admin_required
def admin_delete_comment(id):
    conn = get_db()
    comment = conn.execute('SELECT problem_id FROM comments WHERE id = ?', (id,)).fetchone()
    if comment:
        problem_id = comment['problem_id']
        conn.execute('DELETE FROM comments WHERE id = ?', (id,))
        conn.commit()
        conn.close()
        flash('Comment deleted successfully')
        return redirect(url_for('problem', id=problem_id))
    conn.close()
    flash('Comment not found')
    return redirect(url_for('index'))

@app.route('/admin/category/<int:id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_category(id):
    conn = get_db()
    category = conn.execute('SELECT * FROM categories WHERE id = ?', (id,)).fetchone()
    if not category:
        conn.close()
        flash('Category not found')
        return redirect(url_for('admin_dashboard'))

    if request.method == 'POST':
        name = request.form['name'].strip()
        if not name:
            flash('Category name cannot be empty')
            conn.close()
            return render_template('admin/edit_category.html', category=category)

        # Check if name is already taken by another category
        existing = conn.execute('SELECT id FROM categories WHERE name = ? AND id != ?', (name, id)).fetchone()
        if existing:
            flash('Category name already exists')
            conn.close()
            return render_template('admin/edit_category.html', category=category)

        conn.execute('UPDATE categories SET name = ? WHERE id = ?', (name, id))
        conn.commit()
        conn.close()
        flash('Category updated successfully')
        return redirect(url_for('admin_dashboard'))

    conn.close()
    return render_template('admin/edit_category.html', category=category)

@app.route('/admin/category/<int:id>/delete', methods=['POST'])
@admin_required
def admin_delete_category(id):
    conn = get_db()
    # Remove category associations first
    conn.execute('DELETE FROM problem_categories WHERE category_id = ?', (id,))
    conn.execute('DELETE FROM categories WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('Category deleted successfully')
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True, port=5000)
