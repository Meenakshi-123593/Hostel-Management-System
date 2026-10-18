from flask import Flask, request, jsonify
import sqlite3
import os
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

app = Flask(name)

BASE_DIR = os.path.dirname(os.path.abspath(file))
DATABASE = os.path.join(BASE_DIR, "hostel.db")

==================== CORS ====================

@app.after_request
def add_cors_headers(response):
origin = request.headers.get("Origin")

if origin:
    response.headers["Access-Control-Allow-Origin"] = origin
    response.headers["Vary"] = "Origin"

response.headers["Access-Control-Allow-Headers"] = (
    "Content-Type, Authorization"
)
response.headers["Access-Control-Allow-Methods"] = (
    "GET, POST, PUT, DELETE, OPTIONS"
)

return response

==================== DATABASE ====================

def get_db():
connection = sqlite3.connect(DATABASE)
connection.row_factory = sqlite3.Row
return connection

def create_table():
connection = get_db()

try:
    connection.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            dob TEXT,
            department TEXT,
            year TEXT,
            academic_year TEXT,
            room_number TEXT,
            phone TEXT
        )
    """)

    columns = {
        row["name"]
        for row in connection.execute(
            "PRAGMA table_info(students)"
        ).fetchall()
    }

    for column in [
        "dob", "department", "year",
        "academic_year", "room_number", "phone"
    ]:
        if column not in columns:
            connection.execute(
                f"ALTER TABLE students ADD COLUMN {column} TEXT"
            )

    connection.executescript("""
        CREATE TABLE IF NOT EXISTS outpasses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            student_name TEXT,
            reason TEXT NOT NULL,
            destination TEXT,
            from_date TEXT,
            to_date TEXT,
            status TEXT DEFAULT 'Pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            student_name TEXT,
            category TEXT,
            description TEXT NOT NULL,
            status TEXT DEFAULT 'Pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            student_name TEXT,
            attendance_date TEXT NOT NULL,
            status TEXT NOT NULL,
            UNIQUE(student_id, attendance_date)
        );

        CREATE TABLE IF NOT EXISTS fees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL UNIQUE,
            total_amount REAL DEFAULT 0,
            paid_amount REAL DEFAULT 0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        );
    """)

    connection.commit()

finally:
    connection.close()

==================== HELPERS ====================

def get_serializer():
secret = os.environ.get("ADMIN_TOKEN_SECRET")

if not secret:
    return None

return URLSafeTimedSerializer(
    secret,
    salt="hostel-admin-auth"
)

def require_admin():
serializer = get_serializer()

if serializer is None:
    return None, (
        jsonify({
            "success": False,
            "message": "Admin token secret is not configured."
        }), 503
    )

authorization = request.headers.get("Authorization", "")
parts = authorization.split(" ", 1)

if len(parts) != 2 or parts[0].lower() != "bearer":
    return None, (
        jsonify({
            "success": False,
            "message": "Admin login required."
        }), 401
    )

try:
    data = serializer.loads(parts[1], max_age=3600)

    if data.get("role") != "admin":
        raise BadSignature("Invalid role")

    return data, None

except (BadSignature, SignatureExpired):
    return None, (
        jsonify({
            "success": False,
            "message": "Admin session expired. Please log in again."
        }), 401
    )

FIXED: Allow OPTIONS preflight requests before checking admin token.

def admin_required(function):
@wraps(function)
def wrapper(*args, **kwargs):
if request.method == "OPTIONS":
return "", 204

    admin, error = require_admin()

    if error:
        return error

    return function(*args, **kwargs)

return wrapper

def read_json():
return request.get_json(silent=True) or {}

def get_student(connection, student_id):
return connection.execute(
"SELECT * FROM students WHERE student_id = ?",
(str(student_id).strip(),)
).fetchone()

def student_not_found():
return jsonify({
"success": False,
"message": "Registered student not found."
}), 404

==================== HOME ====================

@app.route("/", methods=["GET"])
def home():
return jsonify({
"message": "Nehru Group of Institutions Hostel Management System",
"status": "Backend is running successfully"
})

==================== STUDENT REGISTRATION ====================

@app.route("/api/register", methods=["POST", "OPTIONS"])
def register():
if request.method == "OPTIONS":
return "", 204

data = read_json()

student_id = str(data.get("student_id", "")).strip()
name = str(data.get("name", "")).strip()
email = str(data.get("email", "")).strip().lower()
username = str(data.get("username", "")).strip()
password = data.get("password", "")

if not all([student_id, name, email, username, password]):
    return jsonify({
        "success": False,
        "message": "Please fill in all required fields."
    }), 400

if not isinstance(password, str) or len(password) < 6:
    return jsonify({
        "success": False,
        "message": "Password must contain at least 6 characters."
    }), 400

connection = get_db()

try:
    connection.execute("""
        INSERT INTO students (
            student_id, name, email, username, password,
            dob, department, year, academic_year, room_number, phone
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        student_id,
        name,
        email,
        username,
        generate_password_hash(password),
        str(data.get("dob", "")),
        str(data.get("department", "")),
        str(data.get("year", "")),
        str(data.get("academicYear", data.get("academic_year", ""))),
        str(data.get("roomNumber", data.get("room_number", ""))),
        str(data.get("phone", ""))
    ))

    connection.commit()

    return jsonify({
        "success": True,
        "message": "Registration successful!"
    }), 201

except sqlite3.IntegrityError:
    return jsonify({
        "success": False,
        "message": "Student ID, email, or username already exists."
    }), 409

except sqlite3.Error:
    app.logger.exception("Registration error")
    return jsonify({
        "success": False,
        "message": "A database error occurred."
    }), 500

finally:
    connection.close()

==================== STUDENT LOGIN ====================

@app.route("/api/login", methods=["POST", "OPTIONS"])
def login():
if request.method == "OPTIONS":
return "", 204

data = read_json()
username = str(data.get("username", "")).strip()
password = data.get("password", "")

if not username or not password:
    return jsonify({
        "success": False,
        "message": "Enter your username and password."
    }), 400

connection = get_db()

try:
    student = connection.execute(
        "SELECT * FROM students WHERE username = ?",
        (username,)
    ).fetchone()

    if not student or not check_password_hash(
        student["password"], password
    ):
        return jsonify({
            "success": False,
            "message": "Invalid username or password."
        }), 401

    return jsonify({
        "success": True,
        "message": "Login successful!",
        "student": {
            "student_id": student["student_id"],
            "name": student["name"],
            "email": student["email"],
            "username": student["username"],
            "dob": student["dob"],
            "department": student["department"],
            "year": student["year"],
            "academic_year": student["academic_year"],
            "room_number": student["room_number"],
            "phone": student["phone"]
        }
    }), 200

except sqlite3.Error:
    app.logger.exception("Student login error")
    return jsonify({
        "success": False,
        "message": "A database error occurred."
    }), 500

finally:
    connection.close()

==================== ADMIN LOGIN ====================

@app.route("/api/admin/login", methods=["POST", "OPTIONS"])
def admin_login():
if request.method == "OPTIONS":
return "", 204

data = read_json()

username = str(data.get("username", "")).strip()
password = data.get("password", "")

admin_username = os.environ.get("ADMIN_USERNAME")
admin_password = os.environ.get("ADMIN_PASSWORD")
serializer = get_serializer()

if not username or not password:
    return jsonify({
        "success": False,
        "message": "Enter admin username and password."
    }), 400

if not all([admin_username, admin_password, serializer]):
    return jsonify({
        "success": False,
        "message": "Admin configuration is incomplete on the server."
    }), 503

if username != admin_username or password != admin_password:
    return jsonify({
        "success": False,
        "message": "Invalid admin username or password."
    }), 401

token = serializer.dumps({
    "username": admin_username,
    "role": "admin"
})

return jsonify({
    "success": True,
    "message": "Admin login successful.",
    "token": token
}), 200

==================== ADMIN: STUDENTS ====================

@app.route("/api/admin/students", methods=["GET", "OPTIONS"])
@admin_required
def admin_students():
connection = get_db()

try:
    rows = connection.execute("""
        SELECT student_id, name, email, username, dob,
               department, year, academic_year, room_number, phone
        FROM students
        ORDER BY id DESC
    """).fetchall()

    students = [dict(row) for row in rows]

    return jsonify({
        "success": True,
        "count": len(students),
        "students": students
    })

except sqlite3.Error:
    app.logger.exception("Loading admin student records failed")
    return jsonify({
        "success": False,
        "message": "Unable to load student records."
    }), 500

finally:
    connection.close()

==================== STUDENT: SUBMIT OUTPASS ====================

@app.route("/api/outpasses", methods=["GET", "POST", "OPTIONS"])
def outpasses():
if request.method == "OPTIONS":
return "", 204

connection = get_db()

try:
    if request.method == "POST":
        data = read_json()
        student_id = str(data.get("student_id", "")).strip()
        reason = str(data.get("reason", "")).strip()

        if not student_id or not reason:
            return jsonify({
                "success": False,
                "message": "Student ID and reason are required."
            }), 400

        student = get_student(connection, student_id)

        if not student:
            return student_not_found()

        connection.execute("""
            INSERT INTO outpasses (
                student_id, student_name, reason, destination,
                from_date, to_date, status
            )
            VALUES (?, ?, ?, ?, ?, ?, 'Pending')
        """, (
            student_id,
            student["name"],
            reason,
            str(data.get("destination", "")),
            str(data.get("from_date", data.get("fromDate", ""))),
            str(data.get("to_date", data.get("toDate", "")))
        ))

        connection.commit()

        return jsonify({
            "success": True,
            "message": "Outpass request submitted."
        }), 201

    student_id = request.args.get("student_id", "").strip()

    if not student_id:
        return jsonify({
            "success": False,
            "message": "Provide student_id."
        }), 400

    rows = connection.execute("""
        SELECT * FROM outpasses
        WHERE student_id = ?
        ORDER BY id DESC
    """, (student_id,)).fetchall()

    return jsonify({
        "success": True,
        "outpasses": [dict(row) for row in rows]
    })

finally:
    connection.close()

==================== ADMIN: OUTPASSES ====================

@app.route("/api/admin/outpasses", methods=["GET", "OPTIONS"])
@admin_required
def admin_outpasses():
connection = get_db()

try:
    rows = connection.execute("""
        SELECT * FROM outpasses ORDER BY id DESC
    """).fetchall()

    return jsonify({
        "success": True,
        "outpasses": [dict(row) for row in rows]
    })

finally:
    connection.close()

@app.route(
"/api/admin/outpasses/"int:outpass_id" (int:outpass_id)/status",
methods=["POST", "OPTIONS"]
)
@admin_required
def update_outpass(outpass_id):
status = str(read_json().get("status", "")).strip().title()

if status not in ["Approved", "Rejected", "Pending"]:
    return jsonify({
        "success": False,
        "message": "Invalid outpass status."
    }), 400

connection = get_db()

try:
    cursor = connection.execute("""
        UPDATE outpasses SET status = ? WHERE id = ?
    """, (status, outpass_id))

    connection.commit()

    if cursor.rowcount == 0:
        return jsonify({
            "success": False,
            "message": "Outpass not found."
        }), 404

    return jsonify({
        "success": True,
        "message": "Outpass status updated.",
        "status": status
    })

finally:
    connection.close()

==================== STUDENT: COMPLAINTS ====================

@app.route("/api/complaints", methods=["GET", "POST", "OPTIONS"])
def complaints():
if request.method == "OPTIONS":
return "", 204

connection = get_db()

try:
    if request.method == "POST":
        data = read_json()
        student_id = str(data.get("student_id", "")).strip()
        description = str(
            data.get("description", data.get("complaint", ""))
        ).strip()

        if not student_id or not description:
            return jsonify({
                "success": False,
                "message": "Student ID and complaint are required."
            }), 400

        student = get_student(connection, student_id)

        if not student:
            return student_not_found()

        connection.execute("""
            INSERT INTO complaints (
                student_id, student_name, category, description, status
            )
            VALUES (?, ?, ?, ?, 'Pending')
        """, (
            student_id,
            student["name"],
            str(data.get("category", "General")),
            description
        ))

        connection.commit()

        return jsonify({
            "success": True,
            "message": "Complaint submitted successfully."
        }), 201

    student_id = request.args.get("student_id", "").strip()

    if not student_id:
        return jsonify({
            "success": False,
            "message": "Provide student_id."
        }), 400

    rows = connection.execute("""
        SELECT * FROM complaints
        WHERE student_id = ?
        ORDER BY id DESC
    """, (student_id,)).fetchall()

    return jsonify({
        "success": True,
        "complaints": [dict(row) for row in rows]
    })

finally:
    connection.close()

==================== ADMIN: COMPLAINTS ====================

@app.route("/api/admin/complaints", methods=["GET", "OPTIONS"])
@admin_required
def admin_complaints():
connection = get_db()

try:
    rows = connection.execute("""
        SELECT * FROM complaints ORDER BY id DESC
    """).fetchall()

    return jsonify({
        "success": True,
        "complaints": [dict(row) for row in rows]
    })

finally:
    connection.close()

@app.route(
"/api/admin/complaints/"int:complaint_id" (int:complaint_id)/status",
methods=["POST", "OPTIONS"]
)
@admin_required
def update_complaint(complaint_id):
status = str(read_json().get("status", "")).strip().title()

if status not in ["Pending", "In Progress", "Resolved", "Rejected"]:
    return jsonify({
        "success": False,
        "message": "Invalid complaint status."
    }), 400

connection = get_db()

try:
    cursor = connection.execute("""
        UPDATE complaints SET status = ? WHERE id = ?
    """, (status, complaint_id))

    connection.commit()

    if cursor.rowcount == 0:
        return jsonify({
            "success": False,
            "message": "Complaint not found."
        }), 404

    return jsonify({
        "success": True,
        "message": "Complaint status updated."
    })

finally:
    connection.close()

==================== ATTENDANCE ====================

@app.route("/api/attendance", methods=["GET", "OPTIONS"])
def student_attendance():
if request.method == "OPTIONS":
return "", 204

student_id = request.args.get("student_id", "").strip()

if not student_id:
    return jsonify({
        "success": False,
        "message": "Provide student_id."
    }), 400

connection = get_db()

try:
    rows = connection.execute("""
        SELECT * FROM attendance
        WHERE student_id = ?
        ORDER BY attendance_date DESC
    """, (student_id,)).fetchall()

    records = [dict(row) for row in rows]

    return jsonify({
        "success": True,
        "attendance": records,
        "count": len(records)
    })

finally:
    connection.close()

@app.route("/api/admin/attendance", methods=["GET", "POST", "OPTIONS"])
@admin_required
def manage_attendance():
connection = get_db()

try:
    if request.method == "POST":
        data = read_json()
        student_id = str(data.get("student_id", "")).strip()
        attendance_date = str(
            data.get("attendance_date", data.get("date", ""))
        ).strip()
        status = str(data.get("status", "")).strip().title()

        if not student_id or not attendance_date:
            return jsonify({
                "success": False,
                "message": "Student ID and date are required."
            }), 400

        if status not in ["Present", "Absent", "Leave"]:
            return jsonify({
                "success": False,
                "message": "Status must be Present, Absent, or Leave."
            }), 400

        student = get_student(connection, student_id)

        if not student:
            return student_not_found()

        connection.execute("""
            INSERT INTO attendance (
                student_id, student_name, attendance_date, status
            )
            VALUES (?, ?, ?, ?)
            ON CONFLICT(student_id, attendance_date)
            DO UPDATE SET status = excluded.status,
                          student_name = excluded.student_name
        """, (
            student_id,
            student["name"],
            attendance_date,
            status
        ))

        connection.commit()

        return jsonify({
            "success": True,
            "message": "Attendance saved."
        }), 201

    rows = connection.execute("""
        SELECT * FROM attendance ORDER BY attendance_date DESC
    """).fetchall()

    records = [dict(row) for row in rows]

    return jsonify({
        "success": True,
        "attendance": records,
        "count": len(records)
    })

finally:
    connection.close()

==================== FEES ====================

@app.route("/api/fees", methods=["GET", "OPTIONS"])
def student_fees():
if request.method == "OPTIONS":
return "", 204

student_id = request.args.get("student_id", "").strip()

if not student_id:
    return jsonify({
        "success": False,
        "message": "Provide student_id."
    }), 400

connection = get_db()

try:
    student = get_student(connection, student_id)

    if not student:
        return student_not_found()

    row = connection.execute("""
        SELECT * FROM fees WHERE student_id = ?
    """, (student_id,)).fetchone()

    if row:
        fee = dict(row)
    else:
        fee = {
            "student_id": student_id,
            "total_amount": 0,
            "paid_amount": 0,
            "balance": 0,
            "status": "Unpaid"
        }

    total = float(fee.get("total_amount", 0) or 0)
    paid = float(fee.get("paid_amount", 0) or 0)

    fee["balance"] = max(total - paid, 0)

    if total > 0 and paid >= total:
        fee["status"] = "Paid"
    elif paid > 0:
        fee["status"] = "Partially Paid"
    else:
        fee["status"] = "Unpaid"

    return jsonify({
        "success": True,
        "fees": fee
    })

finally:
    connection.close()

@app.route("/api/admin/fees", methods=["GET", "POST", "OPTIONS"])
@admin_required
def manage_fees():
connection = get_db()

try:
    if request.method == "POST":
        data = read_json()
        student_id = str(data.get("student_id", "")).strip()

        try:
            total = float(data.get("total_amount", 0))
            paid = float(data.get("paid_amount", 0))
        except (TypeError, ValueError):
            return jsonify({
                "success": False,
                "message": "Fee amounts must be numbers."
            }), 400

        if not student_id or total < 0 or paid < 0 or paid > total:
            return jsonify({
                "success": False,
                "message": "Check the student ID and fee amounts."
            }), 400

        student = get_student(connection, student_id)

        if not student:
            return student_not_found()

        connection.execute("""
            INSERT INTO fees (
                student_id, total_amount, paid_amount, updated_at
            )
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(student_id)
            DO UPDATE SET
                total_amount = excluded.total_amount,
                paid_amount = excluded.paid_amount,
                updated_at = CURRENT_TIMESTAMP
        """, (student_id, total, paid))

        connection.commit()

        return jsonify({
            "success": True,
            "message": "Fee record saved."
        }), 201

    rows = connection.execute("""
        SELECT
            s.student_id,
            s.name AS student_name,
            COALESCE(f.total_amount, 0) AS total_amount,
            COALESCE(f.paid_amount, 0) AS paid_amount,
            COALESCE(f.total_amount, 0)
                - COALESCE(f.paid_amount, 0) AS balance
        FROM students s
        LEFT JOIN fees f ON s.student_id = f.student_id
        ORDER BY s.id DESC
    """).fetchall()

    records = []

    for row in rows:
        fee = dict(row)

        if fee["total_amount"] > 0 and (
            fee["paid_amount"] >= fee["total_amount"]
        ):
            fee["status"] = "Paid"
        elif fee["paid_amount"] > 0:
            fee["status"] = "Partially Paid"
        else:
            fee["status"] = "Unpaid"

        records.append(fee)

    return jsonify({
        "success": True,
        "fees": records
    })

finally:
    connection.close()

==================== ADMIN DASHBOARD ====================

@app.route("/api/admin/dashboard", methods=["GET", "OPTIONS"])
@admin_required
def admin_dashboard():
connection = get_db()

try:
    students = connection.execute("""
        SELECT student_id, name, email, department, year,
               academic_year, room_number, phone
        FROM students ORDER BY id DESC
    """).fetchall()

    outpasses = connection.execute("""
        SELECT * FROM outpasses ORDER BY id DESC
    """).fetchall()

    complaints = connection.execute("""
        SELECT * FROM complaints ORDER BY id DESC
    """).fetchall()

    attendance_count = connection.execute("""
        SELECT COUNT(*) AS total FROM attendance
    """).fetchone()["total"]

    fee_rows = connection.execute("""
        SELECT
            s.student_id,
            s.name AS student_name,
            COALESCE(f.total_amount, 0) AS total_amount,
            COALESCE(f.paid_amount, 0) AS paid_amount,
            COALESCE(f.total_amount, 0)
                - COALESCE(f.paid_amount, 0) AS balance
        FROM students s
        LEFT JOIN fees f ON s.student_id = f.student_id
        ORDER BY s.id DESC
    """).fetchall()

    fees = []

    for row in fee_rows:
        fee = dict(row)

        if fee["total_amount"] > 0 and (
            fee["paid_amount"] >= fee["total_amount"]
        ):
            fee["status"] = "Paid"
        elif fee["paid_amount"] > 0:
            fee["status"] = "Partially Paid"
        else:
            fee["status"] = "Unpaid"

        fees.append(fee)

    outpass_records = [dict(row) for row in outpasses]
    complaint_records = [dict(row) for row in complaints]

    pending_outpasses = sum(
        1 for item in outpass_records
        if item["status"] == "Pending"
    )

    pending_complaints = sum(
        1 for item in complaint_records
        if item["status"] == "Pending"
    )

    unpaid_fees = sum(
        1 for item in fees
        if item["status"] != "Paid"
    )

    return jsonify({
        "success": True,
        "student_count": len(students),
        "pending_outpass_count": pending_outpasses,
        "attendance_count": attendance_count,
        "pending_complaint_count": pending_complaints,
        "unpaid_fee_count": unpaid_fees,
        "students": [dict(row) for row in students],
        "outpasses": outpass_records,
        "complaints": complaint_records,
        "fees": fees
    })

finally:
    connection.close()

==================== START APPLICATION ====================

create_table()

if name == "main":
app.run(debug=False)
