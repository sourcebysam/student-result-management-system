"""
Student Result Management Website (Flask + SQLite)
--------------------------------------------------
A compact, single-file starter you can run right away and extend.

Features now:
- Admin login to manage classes, students, subjects, and results
- Students login with Registration Number + password to view ONLY their results
- Multi-class support (ClassRoom model)
- SQLite via SQLAlchemy, password hashing, sessions

How to run:
1) pip install flask SQLAlchemy email_validator
2) python app1.py
3) Open http://127.0.0.1:5000

Default admin (auto-created on first run):
- username: admin
- password: admin123

NOTE: For brevity, this starter uses basic forms and minimal validation.
Add CSRF protection (Flask-WTF) & stronger validation in a later upgrade.
"""
from __future__ import annotations
from datetime import datetime
from typing import Dict, List, Optional

from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, UniqueConstraint
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, scoped_session
from jinja2 import DictLoader

# ----------------------------
# App & DB setup
# ----------------------------
app = Flask(__name__)
app.secret_key = "dev-secret-change-me"  # replace before production

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
    created_at = Column(DateTime, default=datetime.utcnow)

class ClassRoom(Base):
    __tablename__ = "classes"
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)  # e.g., "Grade 10", "BCA 1st Sem"
    section = Column(String(10), nullable=True)  # e.g., "A"

    students = relationship("Student", back_populates="classroom", cascade="all, delete")

    _table_args_ = (
        UniqueConstraint("name", "section", name="uq_class_name_section"),
    )

class Student(Base):
    __tablename__ = "students"
    id = Column(Integer, primary_key=True)
    reg_no = Column(String(50), unique=True, nullable=False)
    name = Column(String(120), nullable=False)
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

    _table_args_ = (
        UniqueConstraint("name", "class_id", name="uq_subject_name_class"),
    )

class Result(Base):
    __tablename__ = "results"
    id = Column(Integer, primary_key=True)
    student_id = Column(Integer, ForeignKey("students.id"), nullable=False)
    subject_id = Column(Integer, ForeignKey("subjects.id"), nullable=False)
    marks = Column(Integer, nullable=False)
    max_marks = Column(Integer, nullable=False, default=100)

    student = relationship("Student", back_populates="results")
    subject = relationship("Subject", back_populates="results")

    _table_args_ = (
        UniqueConstraint("student_id", "subject_id", name="uq_result_student_subject"),
    )

# ----------------------------
# Utility helpers
# ----------------------------

def get_db():
    return SessionLocal()

def is_admin_logged_in() -> bool:
    return session.get("admin_logged_in") is True

def require_admin():
    if not is_admin_logged_in():
        flash("Please login as admin.", "warning")
        return redirect(url_for("admin_login"))


def is_student_logged_in() -> bool:
    return session.get("student_id") is not None


def current_student_id() -> Optional[int]:
    return session.get("student_id")

# ----------------------------
# Templates (single-file via DictLoader)
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
            .container { max-width: 980px; margin: auto; }
            .muted { color: #777; font-size: .9rem; }
            table { width: 100%; }
            .badge { padding: .15rem .5rem; border-radius: .4rem; background: #eee; }
        </style>
    </head>
    <body>
        <nav class=\"container\">
            <ul>
                <li><strong>Student Result Manager</strong></li>
            </ul>
            <ul>
                <li><a href=\"/\">Home</a></li>
                <li><a href=\"{{ url_for('student_login') }}\">Student Login</a></li>
                <li><a href=\"{{ url_for('admin_login') }}\">Admin</a></li>
            </ul>
        </nav>
        <main class=\"container\">
            {% with messages = get_flashed_messages(with_categories=true) %}
              {% if messages %}
                <div>
                  {% for category, message in messages %}
                    <article class=\"{{ 'secondary' if category=='info' else category }}\">{{ message }}</article>
                  {% endfor %}
                </div>
              {% endif %}
            {% endwith %}
            {% block content %}{% endblock %}
        </main>
        <footer class=\"container muted\" style=\"margin-top:2rem\">Made with Flask • Starter project</footer>
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
            <p>Login with your Registration Number and password to view your results.</p>
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
    <p>
        <a href=\"{{ url_for('admin_classes') }}\" role=\"button\">Classes</a>
        <a href=\"{{ url_for('admin_students') }}\" role=\"button\">Students</a>
        <a href=\"{{ url_for('admin_subjects') }}\" role=\"button\">Subjects</a>
        <a href=\"{{ url_for('admin_results_add') }}\" role=\"button\">Add Results</a>
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
        <label>Registration Number <input name=\"reg_no\" required></label>
        <label>Password <input type=\"password\" name=\"password\" required></label>
        <button type=\"submit\">Login</button>
    </form>
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
    {% else %}
        <p>No results published yet.</p>
    {% endif %}
    <p><a href=\"{{ url_for('student_logout') }}\">Logout</a></p>
    {% endblock %}
    """,
    "classes.html": """
    {% extends 'base.html' %}
    {% block title %}Classes{% endblock %}
    {% block content %}
    <h2>Classes</h2>
    <details open>
      <summary>Add Class</summary>
      <form method=\"post\" action=\"{{ url_for('admin_classes_add') }}\">
        <div class=\"grid\">
            <label>Name <input name=\"name\" placeholder=\"BCA 1st Sem\" required></label>
            <label>Section <input name=\"section\" placeholder=\"A\"></label>
        </div>
        <button type=\"submit\">Add</button>
      </form>
    </details>
    <table>
      <thead><tr><th>ID</th><th>Name</th><th>Section</th><th></th></tr></thead>
      <tbody>
        {% for c in classes %}
          <tr>
            <td>{{ c.id }}</td><td>{{ c.name }}</td><td>{{ c.section or '-' }}</td>
            <td>
              <form method=\"post\" action=\"{{ url_for('admin_classes_delete', class_id=c.id) }}\" onsubmit=\"return confirm('Delete class?');\">
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
    <details open>
      <summary>Add Student</summary>
      <form method=\"post\" action=\"{{ url_for('admin_students_add') }}\">
        <div class=\"grid\">
          <label>Reg. No <input name=\"reg_no\" required></label>
          <label>Name <input name=\"name\" required></label>
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

    <table>
      <thead><tr><th>ID</th><th>Reg No</th><th>Name</th><th>Class</th><th></th></tr></thead>
      <tbody>
        {% for s in students %}
        <tr>
          <td>{{ s.id }}</td>
          <td>{{ s.reg_no }}</td>
          <td>{{ s.name }}</td>
          <td>{{ s.classroom.name }}{% if s.classroom.section %} - {{ s.classroom.section }}{% endif %}</td>
          <td>
            <form method=\"post\" action=\"{{ url_for('admin_students_delete', student_id=s.id) }}\" onsubmit=\"return confirm('Delete student?');\">
              <button class=\"contrast\">Delete</button>
            </form>
          </td>
        </tr>
        {% endfor %}
      </tbody>
    </table>
    {% endblock %}
    """,
    "subjects.html": """
    {% extends 'base.html' %}
    {% block title %}Subjects{% endblock %}
    {% block content %}
    <h2>Subjects</h2>
    <details open>
      <summary>Add Subject</summary>
      <form method=\"post\" action=\"{{ url_for('admin_subjects_add') }}\">
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
      <thead><tr><th>ID</th><th>Name</th><th>Class</th><th></th></tr></thead>
      <tbody>
        {% for s in subjects %}
        <tr>
          <td>{{ s.id }}</td>
          <td>{{ s.name }}</td>
          <td>{{ s.classroom.name }}{% if s.classroom.section %} - {{ s.classroom.section }}{% endif %}</td>
          <td>
            <form method=\"post\" action=\"{{ url_for('admin_subjects_delete', subject_id=s.id) }}\" onsubmit=\"return confirm('Delete subject?');\">
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
    {% else %}
      <p class=\"muted\">Select a class to begin.</p>
    {% endif %}

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
# Routes - Admin
# ----------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        user = db.query(AdminUser).filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            session["admin_logged_in"] = True
            flash("Welcome, admin!", "success")
            return redirect(url_for("admin_dashboard"))
        flash("Invalid credentials", "warning")
    return render_template("admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_logged_in", None)
    flash("Logged out", "info")
    return redirect(url_for("home"))

@app.route("/admin")
def admin_dashboard():
    if not is_admin_logged_in():
        return require_admin()
    return render_template("admin_dashboard.html")

# Classes
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
    name = request.form.get("name", "").strip()
    section = request.form.get("section", "").strip() or None
    if not name:
        flash("Class name is required", "warning")
        return redirect(url_for("admin_classes"))
    db = get_db()
    c = ClassRoom(name=name, section=section)
    db.add(c)
    try:
        db.commit()
        flash("Class added", "success")
    except Exception as e:
        db.rollback()
        flash("Could not add class (maybe duplicate)", "warning")
    return redirect(url_for("admin_classes"))

@app.route("/admin/classes/<int:class_id>/delete", methods=["POST"])
def admin_classes_delete(class_id: int):
    if not is_admin_logged_in():
        return require_admin()
    db = get_db()
    obj = db.get(ClassRoom, class_id)
    if not obj:
        abort(404)
    db.delete(obj)
    db.commit()
    flash("Class deleted", "info")
    return redirect(url_for("admin_classes"))

# Students
@app.route("/admin/students")
def admin_students():
    if not is_admin_logged_in():
        return require_admin()
    db = get_db()
    students = db.query(Student).order_by(Student.id.desc()).all()
    classes = db.query(ClassRoom).order_by(ClassRoom.name, ClassRoom.section).all()
    return render_template("students.html", students=students, classes=classes)

@app.route("/admin/students/add", methods=["POST"])
def admin_students_add():
    if not is_admin_logged_in():
        return require_admin()
    reg_no = request.form.get("reg_no", "").strip()
    name = request.form.get("name", "").strip()
    class_id = request.form.get("class_id")
    password = request.form.get("password", "")
    if not (reg_no and name and class_id and password):
        flash("All fields are required", "warning")
        return redirect(url_for("admin_students"))
    db = get_db()
    s = Student(
        reg_no=reg_no,
        name=name,
        class_id=int(class_id),
        password_hash=generate_password_hash(password),
    )
    db.add(s)
    try:
        db.commit()
        flash("Student added", "success")
    except Exception:
        db.rollback()
        flash("Could not add student (maybe duplicate reg no)", "warning")
    return redirect(url_for("admin_students"))

@app.route("/admin/students/<int:student_id>/delete", methods=["POST"])
def admin_students_delete(student_id: int):
    if not is_admin_logged_in():
        return require_admin()
    db = get_db()
    s = db.get(Student, student_id)
    if not s:
        abort(404)
    db.delete(s)
    db.commit()
    flash("Student deleted", "info")
    return redirect(url_for("admin_students"))

# Subjects
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
    db = get_db()
    subj = db.get(Subject, subject_id)
    if not subj:
        abort(404)
    db.delete(subj)
    db.commit()
    flash("Subject deleted", "info")
    return redirect(url_for("admin_subjects"))

# Results add/update
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

# ----------------------------
# Routes - Student
# ----------------------------
@app.route("/student/login", methods=["GET", "POST"])
def student_login():
    if request.method == "POST":
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
    return render_template("student_portal.html", student=s, results=results)

@app.route("/student/logout")
def student_logout():
    session.pop("student_id", None)
    flash("Logged out", "info")
    return redirect(url_for("home"))

# ----------------------------
# DB init with default admin
# ----------------------------

# DB init with default admin
def init_db():
    Base.metadata.create_all(engine)
    db = get_db()
    if not db.query(AdminUser).filter_by(username="admin").first():
        admin = AdminUser(
            username="admin",
            password_hash=generate_password_hash("admin123")
        )
        db.add(admin)
        db.commit()
        app.logger.info("Default admin created: admin/admin123")

# ------------------------------
# Main
# ------------------------------
if __name__ == "__main__":
    init_db()  # Run database initialization on startup
    app.run(debug=True) # Start Flask server