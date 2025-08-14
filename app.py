"""
Student Result Management Website (Flask + SQLite) — Upgraded
-------------------------------------------------------------
Single-file app you can run and extend.

New in this upgrade:
- CSRF protection (session token)
- Role-based users (Admin & Staff)
- Password reset via time-limited token (no email wiring yet; shows token for demo)
- CSV import/export for Students & Results
- Pagination & search on Students page
- Grade calculations (total, percentage, letter grade)
- Printable mark sheet for students

How to run:
1) pip install flask SQLAlchemy itsdangerous
2) python app1.py
3) Open http://127.0.0.1:5000

Default admin (auto-created):
- username: admin
- password: admin123

NOTE: This keeps a simple UI using PicoCSS. In production, add HTTPS, strong secrets, proper email for reset links, and thorough validation.
"""
from datetime import datetime
from typing import List, Optional, Tuple
import csv
import io
import os
import secrets

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    send_file,
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, scoped_session
from jinja2 import DictLoader
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# ----------------------------
# App & DB setup
# ----------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("APP_SECRET", "dev-secret-change-me")

engine = create_engine("sqlite:///results.db", echo=False, future=True)
SessionLocal = scoped_session(sessionmaker(bind=engine, autoflush=False, autocommit=False))
Base = declarative_base()

# ----------------------------
# Models
# ----------------------------
class AdminUser(Base):
    __tablename__ = "admin_users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="admin")  # 'admin' or 'staff'
    created_at = Column(DateTime, default=datetime.utcnow)

class ClassRoom(Base):
    __tablename__ = "classes"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    section = Column(String(10), nullable=True)
    students = relationship("Student", back_populates="classroom", cascade="all, delete")
    __table_args__ = (UniqueConstraint("name", "section", name="uq_class_name_section"),)

class Student(Base):
    __tablename__ = "students"
    id = Column(Integer, primary_key=True)
    reg_no = Column(String(50), unique=True, nullable=False)
    name = Column(String(120), nullable=False)
    email = Column(String(120), unique=True, nullable=True)
    password_hash = Column(String(255), nullable=False)
    class_id = Column(Integer, ForeignKey("classes.id"), nullable=False)
    classroom = relationship("ClassRoom", back_populates="students")
    results = relationship("Result", back_populates="student", cascade="all, delete")

class Subject(Base):
    __tablename__ = "subjects"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    class_id = Column(Integer, ForeignKey("classes.id"), nullable=False)
    classroom = relationship("ClassRoom")
    results = relationship("Result", back_populates="subject", cascade="all, delete")
    __table_args__ = (UniqueConstraint("name", "class_id", name="uq_subject_name_class"),)

class Result(Base):
    __tablename__ = "results"
    id = Column(Integer, primary_key=True)
    student_id = Column(Integer, ForeignKey("students.id"), nullable=False)
    subject_id = Column(Integer, ForeignKey("subjects.id"), nullable=False)
    marks = Column(Integer, nullable=False)
    max_marks = Column(Integer, nullable=False, default=100)
    student = relationship("Student", back_populates="results")
    subject = relationship("Subject", back_populates="results")
    __table_args__ = (UniqueConstraint("student_id", "subject_id", name="uq_result_student_subject"),)

# ----------------------------
# Utilities: DB, Auth, CSRF, Tokens, Grades
# ----------------------------

def get_db():
    return SessionLocal()

# --- CSRF (simple session token) ---
CSRF_SESSION_KEY = "_csrf_token"

def get_csrf_token() -> str:
    token = session.get(CSRF_SESSION_KEY)
    if not token:
        token = secrets.token_hex(16)
        session[CSRF_SESSION_KEY] = token
    return token

@app.context_processor
def inject_csrf():
    return {"csrf_token": get_csrf_token}

def require_csrf():
    form_token = request.form.get("csrf_token")
    if not form_token or form_token != session.get(CSRF_SESSION_KEY):
        abort(400, description="Invalid CSRF token")

# --- Auth helpers ---

def is_admin_logged_in() -> bool:
    return session.get("admin_logged_in") is True

def current_admin_role() -> Optional[str]:
    return session.get("admin_role")

def require_admin(role: Optional[str] = None):
    if not is_admin_logged_in():
        flash("Please login as admin.", "warning")
        return redirect(url_for("admin_login"))
    if role and current_admin_role() != role and current_admin_role() != "admin":
        flash("Insufficient privileges.", "warning")
        return redirect(url_for("admin_dashboard"))


def is_student_logged_in() -> bool:
    return session.get("student_id") is not None

def current_student_id() -> Optional[int]:
    return session.get("student_id")

# --- Token for password reset ---

def serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(app.secret_key, salt="reset")

# --- Grades ---

def compute_totals(results: List[Result]) -> Tuple[int, int, float, str]:
    total = sum(r.marks for r in results)
    max_total = sum(r.max_marks for r in results) or 1
    percentage = round((total / max_total) * 100, 2)
    grade = (
        "A+" if percentage >= 90 else
        "A" if percentage >= 80 else
        "B+" if percentage >= 70 else
        "B" if percentage >= 60 else
        "C" if percentage >= 50 else
        "D" if percentage >= 40 else
        "F"
    )
    return total, max_total, percentage, grade

# ----------------------------
# Templates (DictLoader)
# ----------------------------
TEMPLATES = {
    "base.html": """
    <!doctype html>
    <html lang=\"en\">
    <head>
        <meta charset=\"utf-8\" />
        <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
        <title>{% block title %}Result Manager{% endblock %}</title>
        <link rel=\"stylesheet\" href=\"https://cdn.jsdelivr.net/npm/@picocss/pico@2/css/pico.min.css\" />
        <style>
            .container { max-width: 1000px; margin: auto; }
            .muted { color: #777; font-size: .9rem; }
            .badge { padding: .15rem .5rem; border-radius: .4rem; background: #eee; }
            @media print { nav, .no-print { display:none !important; } body{background:#fff;} }
        </style>
    </head>
    <body>
        <nav class=\"container\">
            <ul><li><strong>Student Result Manager</strong></li></ul>
            <ul>
                <li><a href=\"/\">Home</a></li>
                <li><a href=\"{{ url_for('student_login') }}\">Student Login</a></li>
                <li><a href=\"{{ url_for('admin_login') }}\">Admin</a></li>
            </ul>
        </nav>
        <main class=\"container\">
            {% with messages = get_flashed_messages(with_categories=true) %}
              {% if messages %}
                <div class=\"no-print\">
                  {% for category, message in messages %}
                    <article class=\"{{ 'secondary' if category=='info' else category }}\">{{ message }}</article>
                  {% endfor %}
                </div>
              {% endif %}
            {% endwith %}
            {% block content %}{% endblock %}
        </main>
        <footer class=\"container muted no-print\" style=\"margin-top:2rem\">Flask • Starter project (upgraded)</footer>
    </body>
    </html>
    """,
    "home.html": """
    {% extends 'base.html' %}
    {% block title %}Home • Result Manager{% endblock %}
    {% block content %}
    <h2>Welcome</h2>
    <p>Use this portal to manage and view student results.</p>
    <div class=\"grid\">
        <article>
            <h3>Students</h3>
            <p>Login with your Registration Number and password.</p>
            <a href=\"{{ url_for('student_login') }}\" role=\"button\">Student Login</a>
        </article>
        <article>
            <h3>Administrators</h3>
            <p>Manage classes, students, subjects and results.</p>
            <a href=\"{{ url_for('admin_login') }}\" role=\"button\">Admin Login</a>
        </article>
    </div>
    {% endblock %}
    """,
    "admin_login.html": """
    {% extends 'base.html' %}
    {% block title %}Admin Login{% endblock %}
    {% block content %}
    <h2>Admin Login</h2>
    <form method=\"post\">
        <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\" />
        <label>Username <input name=\"username\" required></label>
        <label>Password <input type=\"password\" name=\"password\" required></label>
        <button type=\"submit\">Login</button>
    </form>
    {% endblock %}
    """,
    "admin_dashboard.html": """
    {% extends 'base.html' %}
    {% block title %}Admin Dashboard{% endblock %}
    {% block content %}
    <h2>Admin Dashboard</h2>
    <p class=\"no-print\">
        <a href=\"{{ url_for('admin_classes') }}\" role=\"button\">Classes</a>
        <a href=\"{{ url_for('admin_students') }}\" role=\"button\">Students</a>
        <a href=\"{{ url_for('admin_subjects') }}\" role=\"button\">Subjects</a>
        <a href=\"{{ url_for('admin_results_add') }}\" role=\"button\">Add Results</a>
        {% if session.get('admin_role')=='admin' %}
          <a href=\"{{ url_for('admin_users') }}\" role=\"button\">Staff Users</a>
        {% endif %}
        <a href=\"{{ url_for('admin_logout') }}\" role=\"button\" class=\"contrast\">Logout</a>
    </p>
    {% endblock %}
    """,
    "student_login.html": """
    {% extends 'base.html' %}
    {% block title %}Student Login{% endblock %}
    {% block content %}
    <h2>Student Login</h2>
    <form method=\"post\">
        <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\" />
        <label>Registration Number <input name=\"reg_no\" required></label>
        <label>Password <input type=\"password\" name=\"password\" required></label>
        <button type=\"submit\">Login</button>
    </form>
    <details>
      <summary>Forgot password?</summary>
      <form method=\"post\" action=\"{{ url_for('student_reset_request') }}\">
        <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\" />
        <label>Registration Number <input name=\"reg_no\" required></label>
        <button type=\"submit\">Generate Reset Link</button>
      </form>
    </details>
    {% endblock %}
    """,
    "student_portal.html": """
    {% extends 'base.html' %}
    {% block title %}My Results{% endblock %}
    {% block content %}
    <h2>Welcome, {{ student.name }}</h2>
    <p>Class: <span class=\"badge\">{{ student.classroom.name }}{% if student.classroom.section %} - {{ student.classroom.section }}{% endif %}</span>
    &nbsp;•&nbsp; Reg No: <span class=\"badge\">{{ student.reg_no }}</span></p>

    {% if results %}
    <table>
        <thead><tr><th>Subject</th><th>Marks</th><th>Max</th></tr></thead>
        <tbody>
        {% for r in results %}
            <tr><td>{{ r.subject.name }}</td><td>{{ r.marks }}</td><td>{{ r.max_marks }}</td></tr>
        {% endfor %}
        </tbody>
    </table>
    <p><strong>Total:</strong> {{ totals[0] }} / {{ totals[1] }} &nbsp; | &nbsp;
       <strong>%:</strong> {{ totals[2] }} &nbsp; | &nbsp; <strong>Grade:</strong> {{ totals[3] }}</p>
    <p class=\"no-print\"><a href=\"{{ url_for('student_marksheet') }}\" role=\"button\">Print Mark Sheet</a></p>
    {% else %}
        <p>No results published yet.</p>
    {% endif %}
    <p class=\"no-print\"><a href=\"{{ url_for('student_logout') }}\">Logout</a></p>
    {% endblock %}
    """,
    "marksheet.html": """
    {% extends 'base.html' %}
    {% block title %}Mark Sheet{% endblock %}
    {% block content %}
    <article>
      <header>
        <h3 style=\"text-align:center\">OFFICIAL MARK SHEET</h3>
      </header>
      <p><strong>Name:</strong> {{ s.name }} &nbsp; | &nbsp; <strong>Reg No:</strong> {{ s.reg_no }}<br>
      <strong>Class:</strong> {{ s.classroom.name }}{% if s.classroom.section %} - {{ s.classroom.section }}{% endif %}</p>
      <table>
        <thead><tr><th>Subject</th><th>Marks</th><th>Max</th></tr></thead>
        <tbody>
        {% for r in results %}
          <tr><td>{{ r.subject.name }}</td><td>{{ r.marks }}</td><td>{{ r.max_marks }}</td></tr>
        {% endfor %}
        </tbody>
      </table>
      <p><strong>Total:</strong> {{ totals[0] }} / {{ totals[1] }} &nbsp; | &nbsp;
         <strong>%:</strong> {{ totals[2] }} &nbsp; | &nbsp; <strong>Grade:</strong> {{ totals[3] }}</p>
    </article>
    <p class=\"no-print\"><button onclick=\"window.print()\">Print</button></p>
    {% endblock %}
    """,
    "classes.html": """
    {% extends 'base.html' %}
    {% block title %}Classes{% endblock %}
    {% block content %}
    <h2>Classes</h2>
    <details open class=\"no-print\">
      <summary>Add Class</summary>
      <form method=\"post\" action=\"{{ url_for('admin_classes_add') }}\">
        <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\" />
        <div class=\"grid\">
            <label>Name <input name=\"name\" required></label>
            <label>Section <input name=\"section\"></label>
        </div>
        <button type=\"submit\">Add</button>
      </form>
    </details>
    <table>
      <thead><tr><th>ID</th><th>Name</th><th>Section</th><th class=\"no-print\"></th></tr></thead>
      <tbody>
        {% for c in classes %}
          <tr>
            <td>{{ c.id }}</td><td>{{ c.name }}</td><td>{{ c.section or '-' }}</td>
            <td class=\"no-print\">
              <form method=\"post\" action=\"{{ url_for('admin_classes_delete', class_id=c.id) }}\" onsubmit=\"return confirm('Delete class?');\">
                <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\" />
                <button class=\"contrast\">Delete</button>
              </form>
            </td>
          </tr>
        {% endfor %}
      </tbody>
    </table>
    {% endblock %}
    """,
    "students.html": """
    {% extends 'base.html' %}
    {% block title %}Students{% endblock %}
    {% block content %}
    <h2>Students</h2>
    <form class=\"grid no-print\" method=\"get\">
      <label>Search <input name=\"q\" value=\"{{ q or '' }}\" placeholder=\"name or reg no\"></label>
      <label>Per Page
        <select name=\"pp\">
          {% for n in [5,10,20,50] %}
             <option value=\"{{n}}\" {% if pp==n %}selected{% endif %}>{{n}}</option>
          {% endfor %}
        </select>
      </label>
      <button>Apply</button>
    </form>

    <details open class=\"no-print\">
      <summary>Add Student</summary>
      <form method=\"post\" action=\"{{ url_for('admin_students_add') }}\">
        <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\" />
        <div class=\"grid\">
          <label>Reg. No <input name=\"reg_no\" required></label>
          <label>Name <input name=\"name\" required></label>
          <label>Email <input type=\"email\" name=\"email\"></label>
          <label>Class
            <select name=\"class_id\" required>
              {% for c in classes %}
                <option value=\"{{ c.id }}\">{{ c.name }}{% if c.section %} - {{ c.section }}{% endif %}</option>
              {% endfor %}
            </select>
          </label>
          <label>Temp Password <input name=\"password\" required placeholder=\"e.g. Pass@123\"></label>
        </div>
        <button type=\"submit\">Add</button>
      </form>
    </details>

    <p class=\"no-print\">
      <a href=\"{{ url_for('admin_students_export') }}\" role=\"button\">Export CSV</a>
      <details style=\"display:inline-block\">
        <summary role=\"button\">Import CSV</summary>
        <form method=\"post\" action=\"{{ url_for('admin_students_import') }}\" enctype=\"multipart/form-data\">
          <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\" />
          <input type=\"file\" name=\"file\" accept=\".csv\" required>
          <button type=\"submit\">Upload</button>
        </form>
      </details>
    </p>

    <table>
      <thead><tr><th>ID</th><th>Reg No</th><th>Name</th><th>Email</th><th>Class</th><th class=\"no-print\"></th></tr></thead>
      <tbody>
        {% for s in students %}
        <tr>
          <td>{{ s.id }}</td>
          <td>{{ s.reg_no }}</td>
          <td>{{ s.name }}</td>
          <td>{{ s.email or '-' }}</td>
          <td>{{ s.classroom.name }}{% if s.classroom.section %} - {{ s.classroom.section }}{% endif %}</td>
          <td class=\"no-print\">
            <form method=\"post\" action=\"{{ url_for('admin_students_delete', student_id=s.id) }}\" onsubmit=\"return confirm('Delete student?');\">
              <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\" />
              <button class=\"contrast\">Delete</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>

    <nav class=\"no-print\">
      <ul>
        {% if page>1 %}<li><a href=\"?q={{q}}&pp={{pp}}&page={{page-1}}\">Prev</a></li>{% endif %}
        <li>Page {{page}}</li>
        {% if has_more %}<li><a href=\"?q={{q}}&pp={{pp}}&page={{page+1}}\">Next</a></li>{% endif %}
      </ul>
    </nav>
    {% endblock %}
    """,
    "subjects.html": """
    {% extends 'base.html' %}
    {% block title %}Subjects{% endblock %}
    {% block content %}
    <h2>Subjects</h2>
    <details open class=\"no-print\">
      <summary>Add Subject</summary>
      <form method=\"post\" action=\"{{ url_for('admin_subjects_add') }}\">
        <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\" />
        <div class=\"grid\">
          <label>Name <input name=\"name\" required></label>
          <label>Class
            <select name=\"class_id\" required>
              {% for c in classes %}
                <option value=\"{{ c.id }}\">{{ c.name }}{% if c.section %} - {{ c.section }}{% endif %}</option>
              {% endfor %}
            </select>
          </label>
        </div>
        <button type=\"submit\">Add</button>
      </form>
    </details>

    <table>
      <thead><tr><th>ID</th><th>Name</th><th>Class</th><th class=\"no-print\"></th></tr></thead>
      <tbody>
        {% for s in subjects %}
        <tr>
          <td>{{ s.id }}</td>
          <td>{{ s.name }}</td>
          <td>{{ s.classroom.name }}{% if s.classroom.section %} - {{ s.classroom.section }}{% endif %}</td>
          <td class=\"no-print\">
            <form method=\"post\" action=\"{{ url_for('admin_subjects_delete', subject_id=s.id) }}\" onsubmit=\"return confirm('Delete subject?');\">
              <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\" />
              <button class=\"contrast\">Delete</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% endblock %}
    """,
    "results_add.html": """
    {% extends 'base.html' %}
    {% block title %}Add Results{% endblock %}
    {% block content %}
    <h2>Add / Update Results</h2>
    <form method=\"get\" action=\"{{ url_for('admin_results_add') }}\">
      <label>Choose Class
        <select name=\"class_id\" onchange=\"this.form.submit()\">
          <option value=\"\">-- select --</option>
          {% for c in classes %}
            <option value=\"{{ c.id }}\" {% if class_id and c.id == class_id %}selected{% endif %}>{{ c.name }}{% if c.section %} - {{ c.section }}{% endif %}</option>
          {% endfor %}
        </select>
      </label>
    </form>

    {% if class_id %}
      <form method=\"post\">
        <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\" />
        <input type=\"hidden\" name=\"class_id\" value=\"{{ class_id }}\" />
        <label>Student
          <select name=\"student_id\" required>
            {% for s in students %}
              <option value=\"{{ s.id }}\">{{ s.reg_no }} - {{ s.name }}</option>
            {% endfor %}
          </select>
        </label>
        <label>Subject
          <select name=\"subject_id\" required>
            {% for sub in subjects %}
              <option value=\"{{ sub.id }}\">{{ sub.name }}</option>
            {% endfor %}
          </select>
        </label>
        <div class=\"grid\">
          <label>Marks <input type=\"number\" name=\"marks\" min=\"0\" required></label>
          <label>Max Marks <input type=\"number\" name=\"max_marks\" min=\"1\" value=\"100\" required></label>
        </div>
        <button type=\"submit\">Save</button>
      </form>

      <p class=\"no-print\">
        <a href=\"{{ url_for('admin_results_export', class_id=class_id) }}\" role=\"button\">Export Results CSV</a>
        <details style=\"display:inline-block\">
          <summary role=\"button\">Import Results CSV</summary>
          <form method=\"post\" action=\"{{ url_for('admin_results_import', class_id=class_id) }}\" enctype=\"multipart/form-data\">
            <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\" />
            <input type=\"file\" name=\"file\" accept=\".csv\" required>
            <button>Upload</button>
          </form>
        </details>
      </p>
    {% else %}
      <p class=\"muted\">Select a class to begin.</p>
    {% endif %}

    {% endblock %}
    """,
    "admin_users.html": """
    {% extends 'base.html' %}
    {% block title %}Staff Users{% endblock %}
    {% block content %}
    <h2>Staff Users</h2>
    <details open class=\"no-print\">
      <summary>Add Staff</summary>
      <form method=\"post\" action=\"{{ url_for('admin_users_add') }}\">
        <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\" />
        <div class=\"grid\">
          <label>Username <input name=\"username\" required></label>
          <label>Password <input name=\"password\" required></label>
          <label>Role
            <select name=\"role\">
              <option value=\"staff\">staff</option>
              <option value=\"admin\">admin</option>
            </select>
          </label>
        </div>
        <button type=\"submit\">Add</button>
      </form>
    </details>

    <table>
      <thead><tr><th>ID</th><th>Username</th><th>Role</th><th class=\"no-print\"></th></tr></thead>
      <tbody>
        {% for u in users %}
        <tr>
          <td>{{ u.id }}</td><td>{{ u.username }}</td><td>{{ u.role }}</td>
          <td class=\"no-print\">
            {% if u.username != 'admin' %}
            <form method=\"post\" action=\"{{ url_for('admin_users_delete', user_id=u.id) }}\" onsubmit=\"return confirm('Delete user?');\">
              <input type=\"hidden\" name=\"csrf_token\" value=\"{{ csrf_token() }}\" />
              <button class=\"contrast\">Delete</button>
            </form>
            {% endif %}
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% endblock %}
    """,
}

app.jinja_loader = DictLoader(TEMPLATES)

# ----------------------------
# Routes - Public
# ----------------------------
@app.route("/")
def home():
    return render_template("home.html")

# ----------------------------
# Routes - Admin Auth & Dashboard
# ----------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        require_csrf()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.query(AdminUser).filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session["admin_logged_in"] = True
            session["admin_role"] = user.role
            flash("Welcome, %s!" % user.role, "success")
            return redirect(url_for("admin_dashboard"))
        flash("Invalid credentials", "warning")
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_role", None)
    flash("Logged out", "info")
    return redirect(url_for("home"))

@app.route("/admin")
def admin_dashboard():
    if not is_admin_logged_in():
        return require_admin()
    return render_template("admin_dashboard.html")

# ----------------------------
# Admin: Classes
# ----------------------------
@app.route("/admin/classes")
def admin_classes():
    if not is_admin_logged_in():
        return require_admin()
    db = get_db()
    classes = db.query(ClassRoom).order_by(ClassRoom.name, ClassRoom.section).all()
    return render_template("classes.html", classes=classes)

@app.route("/admin/classes/add", methods=["POST"])
def admin_classes_add():
    if not is_admin_logged_in():
        return require_admin()
    require_csrf()
    name = request.form.get("name", "").strip()
    section = (request.form.get("section", "").strip() or None)
    if not name:
        flash("Class name is required", "warning")
        return redirect(url_for("admin_classes"))
    db = get_db()
    c = ClassRoom(name=name, section=section)
    db.add(c)
    try:
        db.commit()
        flash("Class added", "success")
    except Exception:
        db.rollback()
        flash("Could not add class (maybe duplicate)", "warning")
    return redirect(url_for("admin_classes"))

@app.route("/admin/classes/<int:class_id>/delete", methods=["POST"])
def admin_classes_delete(class_id: int):
    if not is_admin_logged_in():
        return require_admin()
    require_csrf()
    db = get_db()
    obj = db.get(ClassRoom, class_id)
    if not obj:
        abort(404)
    db.delete(obj)
    db.commit()
    flash("Class deleted", "info")
    return redirect(url_for("admin_classes"))

# ----------------------------
# Admin: Students (with search & pagination) + CSV
# ----------------------------
@app.route("/admin/students")
def admin_students():
    if not is_admin_logged_in():
        return require_admin()
    db = get_db()
    q = request.args.get("q", "").strip() or None
    page = max(1, request.args.get("page", type=int, default=1))
    pp = request.args.get("pp", type=int, default=10)
    query = db.query(Student)
    if q:
        like = f"%{q}%"
        query = query.filter((Student.name.ilike(like)) | (Student.reg_no.ilike(like)))
    total_count = query.count()
    students = query.order_by(Student.id.desc()).limit(pp).offset((page-1)*pp).all()
    has_more = page * pp < total_count
    classes = db.query(ClassRoom).order_by(ClassRoom.name, ClassRoom.section).all()
    return render_template("students.html", students=students, classes=classes, q=q, page=page, pp=pp, has_more=has_more)

@app.route("/admin/students/add", methods=["POST"])
def admin_students_add():
    if not is_admin_logged_in():
        return require_admin()
    require_csrf()
    reg_no = request.form.get("reg_no", "").strip()
    name = request.form.get("name", "").strip()
    email = (request.form.get("email") or "").strip() or None
    class_id = request.form.get("class_id")
    password = request.form.get("password", "")
    if not (reg_no and name and class_id and password):
        flash("All fields are required", "warning")
        return redirect(url_for("admin_students"))
    db = get_db()
    s = Student(
        reg_no=reg_no,
        name=name,
        email=email,
        class_id=int(class_id),
        password_hash=generate_password_hash(password),
    )
    db.add(s)
    try:
        db.commit()
        flash("Student added", "success")
    except Exception:
        db.rollback()
        flash("Could not add student (maybe duplicate reg no/email)", "warning")
    return redirect(url_for("admin_students"))

@app.route("/admin/students/<int:student_id>/delete", methods=["POST"])
def admin_students_delete(student_id: int):
    if not is_admin_logged_in():
        return require_admin()
    require_csrf()
    db = get_db()
    s = db.get(Student, student_id)
    if not s:
        abort(404)
    db.delete(s)
    db.commit()
    flash("Student deleted", "info")
    return redirect(url_for("admin_students"))

@app.route("/admin/students/export")
def admin_students_export():
    if not is_admin_logged_in():
        return require_admin()
    db = get_db()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["reg_no", "name", "email", "class_name", "section"])
    for s in db.query(Student).join(ClassRoom).all():
        w.writerow([s.reg_no, s.name, s.email or "", s.classroom.name, s.classroom.section or ""])
    buf.seek(0)
    return send_file(io.BytesIO(buf.read().encode("utf-8")), as_attachment=True, download_name="students.csv", mimetype="text/csv")

@app.route("/admin/students/import", methods=["POST"])
def admin_students_import():
    if not is_admin_logged_in():
        return require_admin()
    require_csrf()
    file = request.files.get("file")
    if not file:
        flash("No file uploaded", "warning")
        return redirect(url_for("admin_students"))
    db = get_db()
    reader = csv.DictReader(io.StringIO(file.read().decode("utf-8")))
    created = 0
    for row in reader:
        class_obj = db.query(ClassRoom).filter_by(name=row.get("class_name"), section=(row.get("section") or None)).first()
        if not class_obj:
            class_obj = ClassRoom(name=row.get("class_name"), section=(row.get("section") or None))
            db.add(class_obj)
            db.flush()
        reg_no = row.get("reg_no")
        if not db.query(Student).filter_by(reg_no=reg_no).first():
            s = Student(reg_no=reg_no, name=row.get("name"), email=row.get("email") or None, class_id=class_obj.id, password_hash=generate_password_hash("Pass@123"))
            db.add(s)
            created += 1
    db.commit()
    flash(f"Imported {created} students (default password Pass@123)", "success")
    return redirect(url_for("admin_students"))

# ----------------------------
# Admin: Subjects
# ----------------------------
@app.route("/admin/subjects")
def admin_subjects():
    if not is_admin_logged_in():
        return require_admin()
    db = get_db()
    subjects = db.query(Subject).order_by(Subject.id.desc()).all()
    classes = db.query(ClassRoom).order_by(ClassRoom.name, ClassRoom.section).all()
    return render_template("subjects.html", subjects=subjects, classes=classes)

@app.route("/admin/subjects/add", methods=["POST"])
def admin_subjects_add():
    if not is_admin_logged_in():
        return require_admin()
    require_csrf()
    name = request.form.get("name", "").strip()
    class_id = request.form.get("class_id")
    if not (name and class_id):
        flash("All fields are required", "warning")
        return redirect(url_for("admin_subjects"))
    db = get_db()
    subj = Subject(name=name, class_id=int(class_id))
    db.add(subj)
    try:
        db.commit()
        flash("Subject added", "success")
    except Exception:
        db.rollback()
        flash("Could not add subject (maybe duplicate per class)", "warning")
    return redirect(url_for("admin_subjects"))

@app.route("/admin/subjects/<int:subject_id>/delete", methods=["POST"])
def admin_subjects_delete(subject_id: int):
    if not is_admin_logged_in():
        return require_admin()
    require_csrf()
    db = get_db()
    subj = db.get(Subject, subject_id)
    if not subj:
        abort(404)
    db.delete(subj)
    db.commit()
    flash("Subject deleted", "info")
    return redirect(url_for("admin_subjects"))

# ----------------------------
# Admin: Results + CSV
# ----------------------------
@app.route("/admin/results/add", methods=["GET", "POST"])
def admin_results_add():
    if not is_admin_logged_in():
        return require_admin()
    db = get_db()
    classes = db.query(ClassRoom).order_by(ClassRoom.name, ClassRoom.section).all()

    if request.method == "GET":
        class_id = request.args.get("class_id", type=int)
        students: List[Student] = []
        subjects: List[Subject] = []
        if class_id:
            students = db.query(Student).filter_by(class_id=class_id).order_by(Student.name).all()
            subjects = db.query(Subject).filter_by(class_id=class_id).order_by(Subject.name).all()
        return render_template("results_add.html", classes=classes, class_id=class_id, students=students, subjects=subjects)

    # POST
    require_csrf()
    student_id = request.form.get("student_id", type=int)
    subject_id = request.form.get("subject_id", type=int)
    marks = request.form.get("marks", type=int)
    max_marks = request.form.get("max_marks", type=int)
    if not all([student_id, subject_id, marks is not None, max_marks]):
        flash("All fields are required", "warning")
        return redirect(url_for("admin_results_add"))

    existing = db.query(Result).filter_by(student_id=student_id, subject_id=subject_id).first()
    if existing:
        existing.marks = marks
        existing.max_marks = max_marks
        msg = "Result updated"
    else:
        db.add(Result(student_id=student_id, subject_id=subject_id, marks=marks, max_marks=max_marks))
        msg = "Result added"
    db.commit()
    flash(msg, "success")
    return redirect(url_for("admin_results_add", class_id=request.form.get("class_id")))

@app.route("/admin/results/export")
def admin_results_export():
    if not is_admin_logged_in():
        return require_admin()
    class_id = request.args.get("class_id", type=int)
    if not class_id:
        abort(400)
    db = get_db()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["reg_no", "subject", "marks", "max_marks"])
    rows = (
        db.query(Result).join(Subject).join(Student)
        .filter(Subject.class_id == class_id)
        .all()
    )
    for r in rows:
        w.writerow([r.student.reg_no, r.subject.name, r.marks, r.max_marks])
    buf.seek(0)
    return send_file(io.BytesIO(buf.read().encode("utf-8")), as_attachment=True, download_name="results.csv", mimetype="text/csv")

@app.route("/admin/results/import/<int:class_id>", methods=["POST"])
def admin_results_import(class_id: int):
    if not is_admin_logged_in():
        return require_admin()
    require_csrf()
    file = request.files.get("file")
    if not file:
        flash("No file uploaded", "warning")
        return redirect(url_for("admin_results_add", class_id=class_id))
    db = get_db()
    subs = {s.name: s.id for s in db.query(Subject).filter_by(class_id=class_id).all()}
    students_by_reg = {s.reg_no: s.id for s in db.query(Student).filter_by(class_id=class_id).all()}
    reader = csv.DictReader(io.StringIO(file.read().decode("utf-8")))
    up = 0
    for row in reader:
        sid = students_by_reg.get(row.get("reg_no"))
        subid = subs.get(row.get("subject"))
        if not sid or not subid:
            continue
        marks = int(row.get("marks", 0))
        max_marks = int(row.get("max_marks", 100))
        existing = db.query(Result).filter_by(student_id=sid, subject_id=subid).first()
        if existing:
            existing.marks = marks
            existing.max_marks = max_marks
        else:
            db.add(Result(student_id=sid, subject_id=subid, marks=marks, max_marks=max_marks))
        up += 1
    db.commit()
    flash(f"Imported/updated {up} results", "success")
    return redirect(url_for("admin_results_add", class_id=class_id))

# ----------------------------
# Admin: Staff users (role-based)
# ----------------------------
@app.route("/admin/users")
def admin_users():
    if not is_admin_logged_in():
        return require_admin()
    if current_admin_role() != "admin":
        return require_admin("admin")
    db = get_db()
    users = db.query(AdminUser).order_by(AdminUser.id.desc()).all()
    return render_template("admin_users.html", users=users)

@app.route("/admin/users/add", methods=["POST"])
def admin_users_add():
    if not is_admin_logged_in():
        return require_admin()
    if current_admin_role() != "admin":
        return require_admin("admin")
    require_csrf()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "staff")
    if not (username and password):
        flash("All fields are required", "warning")
        return redirect(url_for("admin_users"))
    db = get_db()
    u = AdminUser(username=username, password_hash=generate_password_hash(password), role=role)
    db.add(u)
    try:
        db.commit()
        flash("User added", "success")
    except Exception:
        db.rollback()
        flash("Could not add user (maybe duplicate)", "warning")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
def admin_users_delete(user_id: int):
    if not is_admin_logged_in():
        return require_admin()
    if current_admin_role() != "admin":
        return require_admin("admin")
    require_csrf()
    db = get_db()
    u = db.get(AdminUser, user_id)
    if not u or u.username == "admin":
        abort(400)
    db.delete(u)
    db.commit()
    flash("User deleted", "info")
    return redirect(url_for("admin_users"))

# ----------------------------
# Student auth & portal + printable
# ----------------------------
@app.route("/student/login", methods=["GET", "POST"])
def student_login():
    if request.method == "POST":
        require_csrf()
        reg_no = request.form.get("reg_no", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        student = db.query(Student).filter_by(reg_no=reg_no).first()
        if student and check_password_hash(student.password_hash, password):
            session["student_id"] = student.id
            flash("Logged in successfully", "success")
            return redirect(url_for("student_portal"))
        flash("Invalid credentials", "warning")
    return render_template("student_login.html")

@app.route("/student/portal")
def student_portal():
    if not is_student_logged_in():
        flash("Please login first", "warning")
        return redirect(url_for("student_login"))
    db = get_db()
    s = db.get(Student, current_student_id())
    results = (
        db.query(Result)
        .filter(Result.student_id == s.id)
        .join(Subject)
        .order_by(Subject.name)
        .all()
    )
    totals = compute_totals(results)
    return render_template("student_portal.html", student=s, results=results, totals=totals)

@app.route("/student/marksheet")
def student_marksheet():
    if not is_student_logged_in():
        flash("Please login first", "warning")
        return redirect(url_for("student_login"))
    db = get_db()
    s = db.get(Student, current_student_id())
    results = (
        db.query(Result)
        .filter(Result.student_id == s.id)
        .join(Subject)
        .order_by(Subject.name)
        .all()
    )
    totals = compute_totals(results)
    return render_template("marksheet.html", s=s, results=results, totals=totals)

@app.route("/student/logout")
def student_logout():
    session.pop("student_id", None)
    flash("Logged out", "info")
    return redirect(url_for("home"))

# ----------------------------
# Password reset (Student) – demo without email
# ----------------------------
@app.route("/student/reset", methods=["POST"])
def student_reset_request():
    require_csrf()
    reg_no = request.form.get("reg_no", "").strip()
    db = get_db()
    s = db.query(Student).filter_by(reg_no=reg_no).first()
    if not s:
        flash("Registration number not found", "warning")
        return redirect(url_for("student_login"))
    token = serializer().dumps({"type": "student", "id": s.id})
    flash("Reset link (demo): " + url_for("student_reset_with_token", token=token, _external=False), "info")
    return redirect(url_for("student_login"))

@app.route("/student/reset/<token>", methods=["GET", "POST"])
def student_reset_with_token(token: str):
    # 30 min expiry
    try:
        data = serializer().loads(token, max_age=1800)
    except SignatureExpired:
        return "Link expired", 400
    except BadSignature:
        return "Invalid link", 400
    if data.get("type") != "student":
        abort(400)
    db = get_db()
    s = db.get(Student, int(data.get("id")))
    if not s:
        abort(404)
    if request.method == "POST":
        require_csrf()
        newpass = request.form.get("password", "")
        if len(newpass) < 6:
            flash("Password too short", "warning")
        else:
            s.password_hash = generate_password_hash(newpass)
            db.commit()
            flash("Password updated. Please login.", "success")
            return redirect(url_for("student_login"))
    return (
        """
        <h3>Set New Password</h3>
        <form method='post'>
          <input type='hidden' name='csrf_token' value='""" + get_csrf_token() + """'>
          <label>New Password <input name='password' type='password' required></label>
          <button>Save</button>
        </form>
        """
    )

# ----------------------------
# DB init with default admin
# ----------------------------

def init_db():
    Base.metadata.create_all(engine)
    db = get_db()
    if not db.query(AdminUser).filter_by(username="admin").first():
        admin = AdminUser(username="admin", password_hash=generate_password_hash("admin123"), role="admin")
        db.add(admin)
        db.commit()
        app.logger.info("Default admin created: admin/admin123")

# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    init_db()
    app.jinja_env.globals['csrf_token'] = get_csrf_token
    app.run(debug=True)
