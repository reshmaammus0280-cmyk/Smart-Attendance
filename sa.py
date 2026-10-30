from flask import (
    Flask, request, redirect, session,
    render_template_string, url_for
)
from werkzeug.security import generate_password_hash, check_password_hash
from markupsafe import escape
import sqlite3
import qrcode
import io
import base64
import secrets
import math
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

DATABASE = "attendance.db"
REQUIRED_PERCENTAGE = 75


# ==================================================
# DATABASE
# ==================================================

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


# ==================================================
# COMMON PAGE DESIGN
# ==================================================

def page(title, content):
    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{{ title }}</title>
        <meta name="viewport"
              content="width=device-width, initial-scale=1">

        <style>
            body {
                margin: 0;
                padding: 20px;
                font-family: Arial, sans-serif;
                background: #eef2f7;
                color: #222;
            }

            .container {
                max-width: 950px;
                margin: 25px auto;
                padding: 25px;
                background: white;
                border-radius: 12px;
                box-shadow: 0 3px 15px #0001;
            }

            h1, h2, h3 {
                color: #174c72;
            }

            input, select, button {
                width: 100%;
                padding: 12px;
                margin: 7px 0;
                box-sizing: border-box;
                border-radius: 6px;
                border: 1px solid #ccc;
            }

            button {
                color: white;
                background: #176b87;
                border: none;
                cursor: pointer;
            }

            a {
                color: #176b87;
            }

            .card {
                background: #e8f5f9;
                border-radius: 8px;
                padding: 15px;
                margin: 12px 0;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 12px;
            }

            th, td {
                border: 1px solid #ddd;
                padding: 9px;
                text-align: left;
            }

            th {
                background: #e8f5f9;
            }

            .nav a {
                display: inline-block;
                padding: 8px;
                margin: 3px;
            }

            img {
                max-width: 100%;
            }
        </style>
    </head>

    <body>
        <div class="container">
            <h1>Smart Attendance System</h1>
            {{ content | safe }}
        </div>
    </body>
    </html>
    """, title=title, content=content)


def safe(value):
    return str(escape(value))


# ==================================================
# LOGIN ACCESS CONTROL
# ==================================================

def login_required(role=None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):

            if "username" not in session:
                return redirect(url_for("login"))

            if role and session.get("role") != role:
                return "Access denied: You do not have permission.", 403

            return func(*args, **kwargs)

        return wrapper
    return decorator


# ==================================================
# HOME
# ==================================================

@app.route("/")
def home():

    if session.get("role") == "teacher":
        return redirect(url_for("teacher_dashboard"))

    if session.get("role") == "student":
        return redirect(url_for("student_dashboard"))

    return page("Home", """
        <h2>Welcome!</h2>
        <p>Smart Attendance Management System</p>

        <div class="card">
            <h3>Student</h3>
            <a href="/register">Student Registration</a><br><br>
            <a href="/login">Student Login</a>
        </div>

        <div class="card">
            <h3>Teacher / Faculty</h3>
            <a href="/login">Faculty Login</a>
        </div>
    """)


# ==================================================
# STUDENT REGISTRATION
# ==================================================

@app.route("/register", methods=["GET", "POST"])
def register():

    message = ""

    if request.method == "POST":

        name = request.form.get("name", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not name or not username or not password:
            message = "Please fill in all fields."

        elif username.lower() == "teacher":
            message = "This username is reserved."

        elif len(password) < 8:
            message = "Password must contain at least 8 characters."

        else:
            con = get_db()

            try:
                con.execute("""
                    INSERT INTO students(name, username, password)
                    VALUES (?, ?, ?)
                """, (
                    name,
                    username,
                    generate_password_hash(password)
                ))

                con.commit()
                message = "Registration successful. Please login."

            except sqlite3.IntegrityError:
                message = "This username already exists."

            finally:
                con.close()

    return page("Student Registration", f"""
        <h2>Student Registration</h2>
        <p>{safe(message)}</p>

        <form method="post">
            <input name="name"
                   placeholder="Full Name" required>

            <input name="username"
                   placeholder="Student Username" required>

            <input name="password"
                   type="password"
                   placeholder="Password (minimum 8 characters)"
                   required>

            <button type="submit">Register</button>
        </form>

        <a href="/login">Already registered? Login</a>
    """)


# ==================================================
# LOGIN
# ==================================================

@app.route("/login", methods=["GET", "POST"])
def login():

    message = ""

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        # DEMO TEACHER ACCOUNT
        # Replace this with securely stored faculty credentials
        if username == "teacher" and password == "teacher123":

            session.clear()
            session["username"] = "teacher"
            session["role"] = "teacher"

            return redirect(url_for("teacher_dashboard"))

        con = get_db()

        student = con.execute("""
            SELECT * FROM students WHERE username = ?
        """, (username,)).fetchone()

        con.close()

        if student:

            stored_password = student["password"]

            try:
                valid = check_password_hash(
                    stored_password, password
                )
            except (ValueError, TypeError):
                valid = False

            # Support accounts created by the previous prototype.
            # Upgrade old plain-text passwords after successful login.
            if not valid and stored_password == password:
                valid = True

                con = get_db()
                con.execute("""
                    UPDATE students SET password = ?
                    WHERE id = ?
                """, (
                    generate_password_hash(password),
                    student["id"]
                ))
                con.commit()
                con.close()

            if valid:

                session.clear()
                session["username"] = student["username"]
                session["student_id"] = student["id"]
                session["role"] = "student"

                return redirect(url_for("student_dashboard"))

        message = "Invalid username or password."

    return page("Login", f"""
        <h2>Login</h2>
        <p>{safe(message)}</p>

        <form method="post">
            <input name="username"
                   placeholder="Username" required>

            <input name="password"
                   type="password"
                   placeholder="Password" required>

            <button type="submit">Login</button>
        </form>

        <div class="card">
            <h3>Demo Faculty Account</h3>
            <p>Username: teacher</p>
            <p>Password: teacher123</p>
            <p>Use this account for your local project demonstration.</p>
        </div>

        <a href="/register">Register as Student</a>
    """)


# ==================================================
# ATTENDANCE CALCULATIONS
# ==================================================

def get_student_stats(student_id):

    con = get_db()

    subjects = con.execute("""
        SELECT * FROM subjects ORDER BY name
    """).fetchall()

    result = []

    for subject in subjects:

        total = con.execute("""
            SELECT COUNT(*) FROM classes
            WHERE subject_id = ?
        """, (subject["id"],)).fetchone()[0]

        attended = con.execute("""
            SELECT COUNT(*)
            FROM attendance a
            JOIN classes c ON c.id = a.class_id
            WHERE a.student_id = ?
              AND c.subject_id = ?
              AND a.status = 'Present'
        """, (
            student_id,
            subject["id"]
        )).fetchone()[0]

        percentage = (
            round(attended / total * 100, 2)
            if total else 0
        )

        if total == 0:
            needed = 0
            status = "No classes conducted"

        elif percentage >= REQUIRED_PERCENTAGE:
            needed = 0
            status = "Sufficient"

        else:
            needed = math.ceil(
                (
                    REQUIRED_PERCENTAGE * total
                    - 100 * attended
                ) / (100 - REQUIRED_PERCENTAGE)
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

    history = con.execute("""
        SELECT
            subjects.name AS subject,
            classes.created_at AS class_date,
            attendance.status AS status
        FROM attendance
        JOIN classes ON classes.id = attendance.class_id
        JOIN subjects ON subjects.id = classes.subject_id
        WHERE attendance.student_id = ?
        ORDER BY classes.id DESC
    """, (student_id,)).fetchall()

    con.close()

    return result, history


# ==================================================
# STUDENT DASHBOARD
# ==================================================

@app.route("/student")
@login_required("student")
def student_dashboard():

    sid = session["student_id"]

    con = get_db()

    student = con.execute("""
        SELECT name FROM students WHERE id = ?
    """, (sid,)).fetchone()

    con.close()

    stats, history = get_student_stats(sid)

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
        </tr>
        """

    history_rows = ""

    for item in history:
        history_rows += f"""
        <tr>
            <td>{safe(item['subject'])}</td>
            <td>{safe(item['class_date'])}</td>
            <td>{safe(item['status'])}</td>
        </tr>
        """

    return page("Student Dashboard", f"""
        <div class="nav">
            <a href="/student">Dashboard</a>
            <a href="/scan">Scan QR</a>
            <a href="/logout">Logout</a>
        </div>

        <h2>Student Dashboard</h2>

        <p>Welcome, {safe(student['name'])}!</p>

        <div class="card">
            <h3>Your Attendance</h3>
            <p>Required attendance: {REQUIRED_PERCENTAGE}%</p>
            <p>You can view your own records only.</p>
        </div>

        <h3>Subject-wise Attendance</h3>

        <table>
            <tr>
                <th>Subject</th>
                <th>Total</th>
                <th>Attended</th>
                <th>Absent</th>
                <th>Percentage</th>
                <th>More Classes Needed</th>
                <th>Status</th>
            </tr>
            {rows}
        </table>

        <h3>Your Attendance History</h3>

        <table>
            <tr>
                <th>Subject</th>
                <th>Date</th>
                <th>Status</th>
            </tr>
            {history_rows}
        </table>

        <br>
        <a href="/scan">Scan Attendance QR Code</a>
        <br><br>
        <a href="/logout">Logout</a>
    """)


# ==================================================
# STUDENT QR SCANNER
# ==================================================

@app.route("/scan")
@login_required("student")
def scan():

    return page("QR Scanner", """
        <div class="nav">
            <a href="/student">My Dashboard</a>
            <a href="/logout">Logout</a>
        </div>

        <h2>Attendance QR Scanner</h2>

        <p>Scan the QR code provided by your teacher.</p>

        <div id="reader" style="width:100%"></div>

        <p id="message"></p>

        <script src="https://unpkg.com/html5-qrcode"></script>

        <script>
            function onScanSuccess(decodedText) {

                try {
                    const qrURL = new URL(decodedText);

                    if (
                        qrURL.origin !== window.location.origin ||
                        !qrURL.pathname.startsWith("/mark/")
                    ) {
                        document.getElementById("message").innerText =
                            "Invalid attendance QR code.";
                        return;
                    }

                    window.location.href = qrURL.href;

                } catch (error) {
                    document.getElementById("message").innerText =
                        "Invalid QR code.";
                }
            }

            if (typeof Html5QrcodeScanner !== "undefined") {

                const scanner = new Html5QrcodeScanner(
                    "reader",
                    { fps: 10, qrbox: 250 },
                    false
                );

                scanner.render(onScanSuccess);

            } else {
                document.getElementById("message").innerText =
                    "Scanner could not load. Check your internet connection.";
            }
        </script>
    """)


# ==================================================
# MARK ATTENDANCE
# ONLY LOGGED-IN STUDENTS CAN USE THIS
# ==================================================

@app.route("/mark/<token>")
@login_required("student")
def mark_attendance(token):

    con = get_db()

    class_info = con.execute("""
        SELECT classes.*, subjects.name AS subject_name
        FROM classes
        JOIN subjects ON subjects.id = classes.subject_id
        WHERE classes.token = ?
    """, (token,)).fetchone()

    if not class_info:
        con.close()
        return "Invalid QR code.", 404

    expiry = datetime.fromisoformat(
        class_info["expires_at"]
    )

    if datetime.now() > expiry:
        con.close()
        return "This QR code has expired."

    try:
        con.execute("""
            INSERT INTO attendance(student_id, class_id, status)
            VALUES (?, ?, 'Present')
        """, (
            session["student_id"],
            class_info["id"]
        ))

        con.commit()
        message = "Attendance marked successfully!"

    except sqlite3.IntegrityError:
        message = "Attendance has already been marked for this class."

    con.close()

    return page("Attendance", f"""
        <h2>{safe(message)}</h2>

        <p>Subject: {safe(class_info['subject_name'])}</p>

        <a href="/student">View My Attendance</a>
    """)


# ==================================================
# TEACHER DASHBOARD
# ==================================================

@app.route("/teacher")
@login_required("teacher")
def teacher_dashboard():

    con = get_db()

    subjects = con.execute("""
        SELECT * FROM subjects ORDER BY name
    """).fetchall()

    classes = con.execute("""
        SELECT
            classes.*,
            subjects.name AS subject_name
        FROM classes
        JOIN subjects ON subjects.id = classes.subject_id
        ORDER BY classes.id DESC
    """).fetchall()

    student_count = con.execute("""
        SELECT COUNT(*) FROM students
    """).fetchone()[0]

    subject_options = "".join(
        f'<option value="{s["id"]}">{safe(s["name"])}</option>'
        for s in subjects
    )

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
        </tr>
        """

    subject_rows = "".join(
        f"<li>{safe(s['name'])}</li>"
        for s in subjects
    )

    con.close()

    return page("Faculty Dashboard", f"""
        <div class="nav">
            <a href="/teacher">Dashboard</a>
            <a href="/teacher/students">Students</a>
            <a href="/logout">Logout</a>
        </div>

        <h2>Faculty Control Panel</h2>

        <div class="card">
            <h3>Total Registered Students: {student_count}</h3>
            <p>Teachers control subjects, classes and attendance reports.</p>
        </div>

        <h3>1. Add Subject</h3>

        <form method="post" action="/teacher/add-subject">
            <input name="subject"
                   placeholder="Enter Subject Name"
                   required>

            <button type="submit">Add Subject</button>
        </form>

        <h3>Available Subjects</h3>
        <ul>{subject_rows}</ul>

        <h3>2. Create Attendance Session</h3>

        <form method="post" action="/teacher/create-class">

            <label>Select Subject</label>

            <select name="subject_id" required>
                {subject_options}
            </select>

            <label>QR Code Validity (minutes)</label>

            <input name="minutes"
                   type="number"
                   value="5"
                   min="1"
                   max="60"
                   required>

            <button type="submit">Generate QR Code</button>

        </form>

        <h3>3. Class Attendance Records</h3>

        <table>
            <tr>
                <th>Subject</th>
                <th>Date</th>
                <th>Present</th>
                <th>QR Code</th>
                <th>Report</th>
            </tr>

            {class_rows}
        </table>

        <br>
        <a href="/teacher/students">Manage Students and Reports</a>
        <br><br>
        <a href="/logout">Logout</a>
    """)


# ==================================================
# ADD SUBJECT
# TEACHER ONLY
# ==================================================

@app.route("/teacher/add-subject", methods=["POST"])
@login_required("teacher")
def add_subject():

    name = request.form.get("subject", "").strip()

    if not name:
        return "Subject name is required.", 400

    con = get_db()

    try:
        con.execute("""
            INSERT INTO subjects(name) VALUES (?)
        """, (name,))

        con.commit()

    except sqlite3.IntegrityError:
        con.close()
        return "This subject already exists."

    con.close()

    return redirect(url_for("teacher_dashboard"))


# ==================================================
# CREATE CLASS AND QR
# TEACHER ONLY
# ==================================================

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

    subject = con.execute("""
        SELECT * FROM subjects WHERE id = ?
    """, (subject_id,)).fetchone()

    if not subject:
        con.close()
        return "Subject not found.", 404

    now = datetime.now()
    expiry = now + timedelta(minutes=minutes)

    token = secrets.token_urlsafe(24)

    con.execute("""
        INSERT INTO classes(
            subject_id, token, created_at, expires_at
        )
        VALUES (?, ?, ?, ?)
    """, (
        subject_id,
        token,
        now.isoformat(timespec="seconds"),
        expiry.isoformat(timespec="seconds")
    ))

    con.commit()

    class_id = con.execute(
        "SELECT last_insert_rowid()"
    ).fetchone()[0]

    con.close()

    return redirect(url_for("show_qr", class_id=class_id))


# ==================================================
# SHOW QR CODE
# TEACHER ONLY
# ==================================================

@app.route("/qr/<int:class_id>")
@login_required("teacher")
def show_qr(class_id):

    con = get_db()

    class_info = con.execute("""
        SELECT classes.*, subjects.name AS subject_name
        FROM classes
        JOIN subjects ON subjects.id = classes.subject_id
        WHERE classes.id = ?
    """, (class_id,)).fetchone()

    con.close()

    if not class_info:
        return "Class not found.", 404

    attendance_url = (
        request.host_url.rstrip("/")
        + url_for("mark_attendance", token=class_info["token"])
    )

    qr = qrcode.make(attendance_url)

    image_buffer = io.BytesIO()
    qr.save(image_buffer, format="PNG")

    image_data = base64.b64encode(
        image_buffer.getvalue()
    ).decode()

    return page("QR Code", f"""
        <div class="nav">
            <a href="/teacher">Faculty Dashboard</a>
            <a href="/logout">Logout</a>
        </div>

        <h2>Attendance QR Code</h2>

        <div class="card">
            <p>Subject: {safe(class_info['subject_name'])}</p>
            <p>Created: {safe(class_info['created_at'])}</p>
            <p>Expires: {safe(class_info['expires_at'])}</p>
        </div>

        <img src="data:image/png;base64,{image_data}"
             alt="Attendance QR Code">

        <p>Ask students to log in and scan this QR code.</p>

        <a href="/teacher/class/{class_id}">
            View Attendance Records
        </a>
        <br><br>
        <a href="/teacher">Back to Dashboard</a>
    """)


# ==================================================
# TEACHER: ALL STUDENTS
# ==================================================

@app.route("/teacher/students")
@login_required("teacher")
def teacher_students():

    con = get_db()

    students = con.execute("""
        SELECT id, name, username
        FROM students
        ORDER BY name
    """).fetchall()

    con.close()

    rows = ""

    for s in students:

        rows += f"""
        <tr>
            <td>{safe(s['name'])}</td>
            <td>{safe(s['username'])}</td>
            <td>
                <a href="/teacher/student/{s['id']}">
                    View Report
                </a>
            </td>
        </tr>
        """

    return page("Student Management", f"""
        <div class="nav">
            <a href="/teacher">Dashboard</a>
            <a href="/logout">Logout</a>
        </div>

        <h2>Student Management</h2>

        <table>
            <tr>
                <th>Name</th>
                <th>Username</th>
                <th>Attendance Report</th>
            </tr>
            {rows}
        </table>
    """)


# ==================================================
# TEACHER: CLASS ATTENDANCE REPORT
# ==================================================

@app.route("/teacher/class/<int:class_id>")
@login_required("teacher")
def class_report(class_id):

    con = get_db()

    class_info = con.execute("""
        SELECT classes.*, subjects.name AS subject_name
        FROM classes
        JOIN subjects ON subjects.id = classes.subject_id
        WHERE classes.id = ?
    """, (class_id,)).fetchone()

    if not class_info:
        con.close()
        return "Class not found.", 404

    students = con.execute("""
        SELECT
            students.id,
            students.name,
            students.username,
            attendance.status
        FROM students
        LEFT JOIN attendance
            ON attendance.student_id = students.id
            AND attendance.class_id = ?
        ORDER BY students.name
    """, (class_id,)).fetchall()

    con.close()

    rows = ""

    for s in students:

        status = s["status"] or "Not Marked"

        rows += f"""
        <tr>
            <td>{safe(s['name'])}</td>
            <td>{safe(s['username'])}</td>
            <td>{safe(status)}</td>
            <td>
                <a href="/teacher/student/{s['id']}">
                    Full Report
                </a>
            </td>
        </tr>
        """

    return page("Class Report", f"""
        <div class="nav">
            <a href="/teacher">Dashboard</a>
            <a href="/logout">Logout</a>
        </div>

        <h2>Class Attendance Report</h2>

        <p>Subject: {safe(class_info['subject_name'])}</p>

        <p>Date: {safe(class_info['created_at'])}</p>

        <table>
            <tr>
                <th>Student</th>
                <th>Username</th>
                <th>Status</th>
                <th>Report</th>
            </tr>

            {rows}
        </table>
    """)


# ==================================================
# TEACHER: INDIVIDUAL STUDENT REPORT
# ==================================================

@app.route("/teacher/student/<int:sid>")
@login_required("teacher")
def teacher_student_report(sid):

    con = get_db()

    student = con.execute("""
        SELECT * FROM students WHERE id = ?
    """, (sid,)).fetchone()

    con.close()

    if not student:
        return "Student not found.", 404

    stats, history = get_student_stats(sid)

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
        </tr>
        """

    history_rows = ""

    for item in history:

        history_rows += f"""
        <tr>
            <td>{safe(item['subject'])}</td>
            <td>{safe(item['class_date'])}</td>
            <td>{safe(item['status'])}</td>
        </tr>
        """

    return page("Student Report", f"""
        <div class="nav">
            <a href="/teacher">Dashboard</a>
            <a href="/teacher/students">Students</a>
            <a href="/logout">Logout</a>
        </div>

        <h2>Student Attendance Report</h2>

        <div class="card">
            <p>Name: {safe(student['name'])}</p>
            <p>Username: {safe(student['username'])}</p>
        </div>

        <h3>Subject-wise Attendance</h3>

        <table>
            <tr>
                <th>Subject</th>
                <th>Total Classes</th>
                <th>Attended</th>
                <th>Absent</th>
                <th>Percentage</th>
                <th>Classes Needed</th>
                <th>Status</th>
            </tr>
            {rows}
        </table>

        <h3>Attendance History</h3>

        <table>
            <tr>
                <th>Subject</th>
                <th>Date</th>
                <th>Status</th>
            </tr>
            {history_rows}
        </table>

        <br>
        <a href="/teacher/students">Back to Students</a>
    """)


# ==================================================
# LOGOUT
# ==================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


# ==================================================
# RUN APPLICATION
# ==================================================

if __name__ == "__main__":
    app.run(debug=True)
