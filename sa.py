import os
import io
import math
import base64
import secrets
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

import qrcode
from flask import Flask, request, redirect, session, render_template_string, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-before-public-deployment")

DATABASE = os.environ.get("DATABASE_PATH", "attendance.db")
REQUIRED_PERCENTAGE = 75

# Set these as environment variables on Render for a real deployment.
TEACHER_USERNAME = os.environ.get("TEACHER_USERNAME", "teacher")
TEACHER_PASSWORD = os.environ.get("TEACHER_PASSWORD", "teacher123")


# --------------------------------------------------
# DATABASE
# --------------------------------------------------

def get_db():
    con = sqlite3.connect(DATABASE)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def initialize_db():
    con = get_db()
    con.executescript("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS subjects (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        );

        CREATE TABLE IF NOT EXISTS classes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject_id INTEGER NOT NULL,
            token TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            FOREIGN KEY(subject_id) REFERENCES subjects(id)
        );

        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id INTEGER NOT NULL,
            class_id INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'Present',
            UNIQUE(student_id, class_id),
            FOREIGN KEY(student_id) REFERENCES students(id),
            FOREIGN KEY(class_id) REFERENCES classes(id)
        );
    """)
    con.commit()
    con.close()


initialize_db()


# --------------------------------------------------
# COMMON PAGE DESIGN
# --------------------------------------------------

def page(title, content):
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{{ title }}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body { margin:0; padding:18px; font-family:Arial,sans-serif;
                   background:#eef2f7; color:#222; }
            .container { max-width:1000px; margin:20px auto; padding:24px;
                         background:white; border-radius:12px;
                         box-shadow:0 3px 15px #0001; }
            h1,h2,h3 { color:#174c72; }
            input,select,button { width:100%; padding:12px; margin:7px 0;
                                  box-sizing:border-box; border-radius:6px;
                                  border:1px solid #ccc; }
            button { color:white; background:#176b87; border:0; cursor:pointer; }
            a { color:#176b87; }
            .card { background:#e8f5f9; border-radius:8px; padding:15px; margin:12px 0; }
            table { width:100%; border-collapse:collapse; margin-top:12px; }
            th,td { border:1px solid #ddd; padding:9px; text-align:left; }
            th { background:#e8f5f9; }
            .nav a { display:inline-block; padding:8px; margin:3px; }
            img { max-width:100%; }
            .message { padding:10px; background:#fff4d6; border-radius:6px; }
            @media(max-width:650px) {
                .container { padding:14px; overflow-x:auto; }
                table { font-size:13px; }
            }
        </style>
    </head>
    <body><div class="container">
        <h1>Smart Attendance System</h1>
        {{ content|safe }}
    </div></body>
    </html>
    """, title=title, content=content)


def safe(value):
    return str(escape(value))


# --------------------------------------------------
# ROLE-BASED ACCESS
# --------------------------------------------------

def login_required(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if session.get("role") != role:
                if role == "teacher":
                    return redirect(url_for("teacher_login"))
                return redirect(url_for("student_login"))
            return func(*args, **kwargs)
        return wrapper
    return decorator


# --------------------------------------------------
# HOME
# --------------------------------------------------

@app.route("/")
def home():
    if session.get("role") == "teacher":
        return redirect(url_for("teacher_dashboard"))
    if session.get("role") == "student":
        return redirect(url_for("student_dashboard"))

    return page("Home", """
        <h2>Welcome</h2>
        <p>Smart Attendance Management System</p>
        <div class="card">
            <h3>Student</h3>
            <a href="/login">Student Login</a>
            <p>Student accounts are created only by the teacher.</p>
        </div>
        <div class="card">
            <h3>Teacher / Faculty</h3>
            <a href="/teacher-login">Teacher Login</a>
        </div>
    """)


# --------------------------------------------------
# STUDENT LOGIN - NO PUBLIC REGISTRATION
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
@app.route("/student-login", methods=["GET", "POST"])
def student_login():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        con = get_db()
        student = con.execute(
            "SELECT * FROM students WHERE username = ?", (username,)
        ).fetchone()
        con.close()

        valid = False
        if student:
            try:
                valid = check_password_hash(student["password"], password)
            except (ValueError, TypeError):
                valid = False

        if valid:
            session.clear()
            session["role"] = "student"
            session["student_id"] = student["id"]
            session["username"] = student["username"]
            return redirect(url_for("student_dashboard"))

        message = "Invalid student username or password."

    return page("Student Login", f"""
        <h2>Student Login</h2>
        <p class="message">{safe(message)}</p>
        <form method="post">
            <input name="username" placeholder="Student Username" required>
            <input name="password" type="password" placeholder="Password" required>
            <button type="submit">Student Login</button>
        </form>
        <p>New students must contact the teacher to receive an account.</p>
        <a href="/">Back to Home</a>
    """)


# --------------------------------------------------
# TEACHER LOGIN - SEPARATE FROM STUDENT LOGIN
# --------------------------------------------------

@app.route("/teacher-login", methods=["GET", "POST"])
def teacher_login():
    message = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if secrets.compare_digest(username, TEACHER_USERNAME) and \
           secrets.compare_digest(password, TEACHER_PASSWORD):
            session.clear()
            session["role"] = "teacher"
            session["username"] = TEACHER_USERNAME
            return redirect(url_for("teacher_dashboard"))

        message = "Invalid teacher username or password."

    return page("Teacher Login", f"""
        <h2>Teacher Login</h2>
        <p class="message">{safe(message)}</p>
        <form method="post">
            <input name="username" placeholder="Teacher Username" required>
            <input name="password" type="password" placeholder="Teacher Password" required>
            <button type="submit">Teacher Login</button>
        </form>
        <a href="/">Back to Home</a>
    """)


# --------------------------------------------------
# ATTENDANCE CALCULATIONS - FILTERED BY ONE STUDENT ID
# --------------------------------------------------

def get_student_stats(student_id):
    con = get_db()
    subjects = con.execute("SELECT * FROM subjects ORDER BY name").fetchall()
    result = []

    for subject in subjects:
        total = con.execute("""
            SELECT COUNT(*) FROM classes WHERE subject_id = ?
        """, (subject["id"],)).fetchone()[0]

        attended = con.execute("""
            SELECT COUNT(*)
            FROM attendance a
            JOIN classes c ON c.id = a.class_id
            WHERE a.student_id = ?
              AND c.subject_id = ?
              AND a.status = 'Present'
        """, (student_id, subject["id"])).fetchone()[0]

        percentage = round(attended / total * 100, 2) if total else 0

        if total == 0:
            needed, status = 0, "No classes conducted"
        elif percentage >= REQUIRED_PERCENTAGE:
            needed, status = 0, "Sufficient"
        else:
            needed = math.ceil(
                (REQUIRED_PERCENTAGE * total - 100 * attended)
                / (100 - REQUIRED_PERCENTAGE)
            )
            status = "Attendance Shortage"

        result.append({
            "subject": subject["name"],
            "total": total,
            "attended": attended,
            "absent": total - attended,
            "percentage": percentage,
            "needed": needed,
            "status": status
        })

    # Only this student's attendance history is retrieved.
    history = con.execute("""
        SELECT s.name AS subject, c.created_at AS class_date, a.status
        FROM attendance a
        JOIN classes c ON c.id = a.class_id
        JOIN subjects s ON s.id = c.subject_id
        WHERE a.student_id = ?
        ORDER BY c.id DESC
    """, (student_id,)).fetchall()

    con.close()
    return result, history


def stats_table_rows(stats):
    rows = ""
    for item in stats:
        rows += f"""
        <tr>
            <td>{safe(item['subject'])}</td>
            <td>{item['total']}</td>
            <td>{item['attended']}</td>
            <td>{item['absent']}</td>
            <td>{item['percentage']}%</td>
            <td>{item['needed']}</td>
            <td>{safe(item['status'])}</td>
        </tr>"""
    return rows or '<tr><td colspan="7">No subjects added yet.</td></tr>'


def history_table_rows(history):
    rows = ""
    for item in history:
        rows += f"""
        <tr>
            <td>{safe(item['subject'])}</td>
            <td>{safe(item['class_date'])}</td>
            <td>{safe(item['status'])}</td>
        </tr>"""
    return rows or '<tr><td colspan="3">No attendance marked yet.</td></tr>'


# --------------------------------------------------
# STUDENT DASHBOARD - OWN REPORT ONLY
# --------------------------------------------------

@app.route("/student")
@login_required("student")
def student_dashboard():
    # Read the ID from the authenticated session, never from the URL/form.
    student_id = session["student_id"]

    con = get_db()
    student = con.execute(
        "SELECT name FROM students WHERE id = ?", (student_id,)
    ).fetchone()
    con.close()

    if not student:
        session.clear()
        return redirect(url_for("student_login"))

    stats, history = get_student_stats(student_id)

    return page("Student Dashboard", f"""
        <div class="nav">
            <a href="/student">My Dashboard</a>
            <a href="/scan">Scan QR</a>
            <a href="/logout">Logout</a>
        </div>
        <h2>Student Dashboard</h2>
        <p>Welcome, {safe(student['name'])}!</p>
        <div class="card">
            <h3>My Attendance</h3>
            <p>Required attendance: {REQUIRED_PERCENTAGE}%</p>
            <p>This report belongs only to your student account.</p>
        </div>
        <h3>Subject-wise Attendance</h3>
        <table>
            <tr><th>Subject</th><th>Total</th><th>Attended</th>
            <th>Absent</th><th>Percentage</th><th>More Classes Needed</th>
            <th>Status</th></tr>
            {stats_table_rows(stats)}
        </table>
        <h3>My Attendance History</h3>
        <table>
            <tr><th>Subject</th><th>Date</th><th>Status</th></tr>
            {history_table_rows(history)}
        </table>
        <br><a href="/scan">Scan Attendance QR Code</a>
    """)


# --------------------------------------------------
# QR SCANNER
# --------------------------------------------------

@app.route("/scan")
@login_required("student")
def scan():
    return page("QR Scanner", """
        <div class="nav">
            <a href="/student">My Dashboard</a>
            <a href="/logout">Logout</a>
        </div>
        <h2>Attendance QR Scanner</h2>
        <p>Allow camera access and scan the QR code given by your teacher.</p>
        <div id="reader" style="width:100%"></div>
        <p id="message"></p>
        <script src="https://unpkg.com/html5-qrcode"></script>
        <script>
        function onScanSuccess(decodedText) {
            try {
                const qrURL = new URL(decodedText);
                if (qrURL.origin !== window.location.origin ||
                    !qrURL.pathname.startsWith("/mark/")) {
                    document.getElementById("message").innerText =
                        "Invalid attendance QR code.";
                    return;
                }
                window.location.href = qrURL.href;
            } catch (error) {
                document.getElementById("message").innerText = "Invalid QR code.";
            }
        }
        if (typeof Html5QrcodeScanner !== "undefined") {
            const scanner = new Html5QrcodeScanner(
                "reader", { fps: 10, qrbox: 250 }, false
            );
            scanner.render(onScanSuccess);
        } else {
            document.getElementById("message").innerText =
                "Scanner could not load. Check your internet connection.";
        }
        </script>
    """)


# --------------------------------------------------
# MARK ATTENDANCE - STUDENT SESSION ID IS USED
# --------------------------------------------------

@app.route("/mark/<token>")
@login_required("student")
def mark_attendance(token):
    con = get_db()
    class_info = con.execute("""
        SELECT c.*, s.name AS subject_name
        FROM classes c JOIN subjects s ON s.id = c.subject_id
        WHERE c.token = ?
    """, (token,)).fetchone()

    if not class_info:
        con.close()
        return "Invalid QR code.", 404

    expiry = datetime.fromisoformat(class_info["expires_at"])
    if datetime.now() > expiry:
        con.close()
        return "This QR code has expired.", 400

    student_id = session["student_id"]
    try:
        con.execute("""
            INSERT INTO attendance(student_id, class_id, status)
            VALUES (?, ?, 'Present')
        """, (student_id, class_info["id"]))
        con.commit()
        message = "Attendance marked successfully!"
    except sqlite3.IntegrityError:
        message = "Attendance has already been marked for this class."
    finally:
        con.close()

    return page("Attendance", f"""
        <h2>{safe(message)}</h2>
        <p>Subject: {safe(class_info['subject_name'])}</p>
        <a href="/student">View My Attendance</a>
    """)


# --------------------------------------------------
# TEACHER DASHBOARD
# --------------------------------------------------

@app.route("/teacher")
@login_required("teacher")
def teacher_dashboard():
    con = get_db()
    subjects = con.execute("SELECT * FROM subjects ORDER BY name").fetchall()
    classes = con.execute("""
        SELECT c.*, s.name AS subject_name
        FROM classes c JOIN subjects s ON s.id = c.subject_id
        ORDER BY c.id DESC
    """).fetchall()
    student_count = con.execute("SELECT COUNT(*) FROM students").fetchone()[0]

    subject_options = "".join(
        f'<option value="{s["id"]}">{safe(s["name"])}</option>'
        for s in subjects
    )
    subject_rows = "".join(f"<li>{safe(s['name'])}</li>" for s in subjects)
    class_rows = ""

    for c in classes:
        present = con.execute("""
            SELECT COUNT(*) FROM attendance
            WHERE class_id = ? AND status = 'Present'
        """, (c["id"],)).fetchone()[0]
        class_rows += f"""
        <tr>
            <td>{safe(c['subject_name'])}</td>
            <td>{safe(c['created_at'])}</td>
            <td>{present}</td>
            <td><a href="/qr/{c['id']}">View QR</a></td>
            <td><a href="/teacher/class/{c['id']}">View Records</a></td>
        </tr>"""
    con.close()

    return page("Teacher Dashboard", f"""
        <div class="nav">
            <a href="/teacher">Dashboard</a>
            <a href="/teacher/students">Manage Students</a>
            <a href="/logout">Logout</a>
        </div>
        <h2>Faculty Control Panel</h2>
        <div class="card">
            <h3>Total Registered Students: {student_count}</h3>
            <p>Only teachers can create student accounts.</p>
        </div>

        <h3>1. Create Student Account</h3>
        <form method="post" action="/teacher/add-student">
            <input name="name" placeholder="Student Full Name" required>
            <input name="username" placeholder="Create Student Username" required>
            <input name="password" type="password"
                   placeholder="Set temporary password (minimum 8 characters)"
                   minlength="8" required>
            <button type="submit">Create Student Account</button>
        </form>

        <h3>2. Add Subject</h3>
        <form method="post" action="/teacher/add-subject">
            <input name="subject" placeholder="Enter Subject Name" required>
            <button type="submit">Add Subject</button>
        </form>
        <h3>Available Subjects</h3>
        <ul>{subject_rows or '<li>No subjects added yet.</li>'}</ul>

        <h3>3. Create Attendance Session</h3>
        <form method="post" action="/teacher/create-class">
            <label>Select Subject</label>
            <select name="subject_id" required>{subject_options}</select>
            <label>QR Code Validity (minutes)</label>
            <input name="minutes" type="number" value="5" min="1" max="60" required>
            <button type="submit">Generate QR Code</button>
        </form>

        <h3>4. Class Attendance Records</h3>
        <table>
            <tr><th>Subject</th><th>Date</th><th>Present</th>
            <th>QR Code</th><th>Report</th></tr>
            {class_rows or '<tr><td colspan="5">No classes created yet.</td></tr>'}
        </table>
    """)


# --------------------------------------------------
# TEACHER CREATES STUDENT ACCOUNTS
# --------------------------------------------------

@app.route("/teacher/add-student", methods=["POST"])
@login_required("teacher")
def add_student():
    name = request.form.get("name", "").strip()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not name or not username or not password:
        return "All student fields are required.", 400
    if len(password) < 8:
        return "Password must contain at least 8 characters.", 400
    if username.lower() == TEACHER_USERNAME.lower():
        return "This username is reserved for the teacher.", 400

    con = get_db()
    try:
        con.execute("""
            INSERT INTO students(name, username, password)
            VALUES (?, ?, ?)
        """, (name, username, generate_password_hash(password)))
        con.commit()
        message = "Student account created successfully."
    except sqlite3.IntegrityError:
        message = "That student username already exists."
    finally:
        con.close()

    return page("Student Account", f"""
        <h2>{safe(message)}</h2>
        <a href="/teacher">Back to Teacher Dashboard</a>
    """)


# --------------------------------------------------
# ADD SUBJECT - TEACHER ONLY
# --------------------------------------------------

@app.route("/teacher/add-subject", methods=["POST"])
@login_required("teacher")
def add_subject():
    name = request.form.get("subject", "").strip()
    if not name:
        return "Subject name is required.", 400

    con = get_db()
    try:
        con.execute("INSERT INTO subjects(name) VALUES (?)", (name,))
        con.commit()
    except sqlite3.IntegrityError:
        con.close()
        return "This subject already exists."
    con.close()
    return redirect(url_for("teacher_dashboard"))


# --------------------------------------------------
# CREATE CLASS AND QR - TEACHER ONLY
# --------------------------------------------------

@app.route("/teacher/create-class", methods=["POST"])
@login_required("teacher")
def create_class():
    try:
        subject_id = int(request.form.get("subject_id", ""))
        minutes = int(request.form.get("minutes", 5))
    except ValueError:
        return "Invalid subject or duration.", 400

    if not 1 <= minutes <= 60:
        return "QR validity must be between 1 and 60 minutes.", 400

    con = get_db()
    subject = con.execute(
        "SELECT * FROM subjects WHERE id = ?", (subject_id,)
    ).fetchone()
    if not subject:
        con.close()
        return "Subject not found.", 404

    now = datetime.now()
    expiry = now + timedelta(minutes=minutes)
    token = secrets.token_urlsafe(24)

    con.execute("""
        INSERT INTO classes(subject_id, token, created_at, expires_at)
        VALUES (?, ?, ?, ?)
    """, (subject_id, token, now.isoformat(timespec="seconds"),
          expiry.isoformat(timespec="seconds")))
    con.commit()
    class_id = con.execute("SELECT last_insert_rowid()").fetchone()[0]
    con.close()
    return redirect(url_for("show_qr", class_id=class_id))


# --------------------------------------------------
# SHOW QR - TEACHER ONLY
# --------------------------------------------------

@app.route("/qr/<int:class_id>")
@login_required("teacher")
def show_qr(class_id):
    con = get_db()
    class_info = con.execute("""
        SELECT c.*, s.name AS subject_name
        FROM classes c JOIN subjects s ON s.id = c.subject_id
        WHERE c.id = ?
    """, (class_id,)).fetchone()
    con.close()

    if not class_info:
        return "Class not found.", 404

    attendance_url = request.host_url.rstrip("/") + url_for(
        "mark_attendance", token=class_info["token"]
    )
    qr = qrcode.make(attendance_url)
    buffer = io.BytesIO()
    qr.save(buffer, format="PNG")
    image_data = base64.b64encode(buffer.getvalue()).decode("ascii")

    return page("QR Code", f"""
        <div class="nav"><a href="/teacher">Teacher Dashboard</a>
        <a href="/logout">Logout</a></div>
        <h2>Attendance QR Code</h2>
        <div class="card">
            <p>Subject: {safe(class_info['subject_name'])}</p>
            <p>Created: {safe(class_info['created_at'])}</p>
            <p>Expires: {safe(class_info['expires_at'])}</p>
        </div>
        <img src="data:image/png;base64,{image_data}" alt="Attendance QR Code">
        <p>Students must log in to their own accounts before scanning.</p>
        <a href="/teacher/class/{class_id}">View Attendance Records</a>
    """)


# --------------------------------------------------
# TEACHER: STUDENT LIST
# --------------------------------------------------

@app.route("/teacher/students")
@login_required("teacher")
def teacher_students():
    con = get_db()
    students = con.execute("""
        SELECT id, name, username FROM students ORDER BY name
    """).fetchall()
    con.close()

    rows = ""
    for student in students:
        rows += f"""
        <tr><td>{safe(student['name'])}</td>
        <td>{safe(student['username'])}</td>
        <td><a href="/teacher/student/{student['id']}">View Report</a></td></tr>"""

    return page("Student Management", f"""
        <div class="nav"><a href="/teacher">Dashboard</a>
        <a href="/logout">Logout</a></div>
        <h2>Student Management</h2>
        <table><tr><th>Name</th><th>Username</th><th>Attendance Report</th></tr>
        {rows or '<tr><td colspan="3">No students created yet.</td></tr>'}</table>
    """)


# --------------------------------------------------
# TEACHER: CLASS REPORT
# --------------------------------------------------

@app.route("/teacher/class/<int:class_id>")
@login_required("teacher")
def class_report(class_id):
    con = get_db()
    class_info = con.execute("""
        SELECT c.*, s.name AS subject_name
        FROM classes c JOIN subjects s ON s.id = c.subject_id
        WHERE c.id = ?
    """, (class_id,)).fetchone()

    if not class_info:
        con.close()
        return "Class not found.", 404

    students = con.execute("""
        SELECT st.id, st.name, st.username, a.status
        FROM students st
        LEFT JOIN attendance a
          ON a.student_id = st.id AND a.class_id = ?
        ORDER BY st.name
    """, (class_id,)).fetchall()
    con.close()

    rows = ""
    for student in students:
        status = student["status"] or "Not Marked"
        rows += f"""
        <tr><td>{safe(student['name'])}</td>
        <td>{safe(student['username'])}</td><td>{safe(status)}</td>
        <td><a href="/teacher/student/{student['id']}">Full Report</a></td></tr>"""

    return page("Class Report", f"""
        <div class="nav"><a href="/teacher">Dashboard</a>
        <a href="/logout">Logout</a></div>
        <h2>Class Attendance Report</h2>
        <p>Subject: {safe(class_info['subject_name'])}</p>
        <p>Date: {safe(class_info['created_at'])}</p>
        <table><tr><th>Student</th><th>Username</th><th>Status</th><th>Report</th></tr>
        {rows}</table>
    """)


# --------------------------------------------------
# TEACHER: INDIVIDUAL STUDENT REPORT
# --------------------------------------------------

@app.route("/teacher/student/<int:student_id>")
@login_required("teacher")
def teacher_student_report(student_id):
    con = get_db()
    student = con.execute(
        "SELECT id, name, username FROM students WHERE id = ?", (student_id,)
    ).fetchone()
    con.close()

    if not student:
        return "Student not found.", 404

    stats, history = get_student_stats(student_id)

    return page("Student Report", f"""
        <div class="nav"><a href="/teacher">Dashboard</a>
        <a href="/teacher/students">Students</a>
        <a href="/logout">Logout</a></div>
        <h2>Student Attendance Report</h2>
        <div class="card"><p>Name: {safe(student['name'])}</p>
        <p>Username: {safe(student['username'])}</p></div>
        <h3>Subject-wise Attendance</h3>
        <table><tr><th>Subject</th><th>Total</th><th>Attended</th>
        <th>Absent</th><th>Percentage</th><th>Classes Needed</th><th>Status</th></tr>
        {stats_table_rows(stats)}</table>
        <h3>Attendance History</h3>
        <table><tr><th>Subject</th><th>Date</th><th>Status</th></tr>
        {history_table_rows(history)}</table>
        <br><a href="/teacher/students">Back to Students</a>
    """)


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# --------------------------------------------------
# RUN
# --------------------------------------------------

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
