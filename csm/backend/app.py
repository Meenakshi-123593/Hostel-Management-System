import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "hostel.db")

CORS(app, resources={r"/api/*": {"origins": "*"}})


# ==================== DATABASE ====================

def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_table():
    connection = get_db()

    try:
        connection.executescript("""
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
            );

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

            CREATE TABLE IF NOT EXISTS fee_payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT NOT NULL,
                amount REAL NOT NULL,
                payment_method TEXT,
                transaction_id TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'Success',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS yearly_fees (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT NOT NULL,
                academic_year INTEGER NOT NULL,
                total_amount REAL NOT NULL DEFAULT 0,
                paid_amount REAL NOT NULL DEFAULT 0,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(student_id, academic_year)
            );
        """)

        # Add missing student columns safely.
        student_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(students)"
            ).fetchall()
        }

        for column in [
            "dob", "department", "year",
            "academic_year", "room_number", "phone"
        ]:
            if column not in student_columns:
                connection.execute(
                    f"ALTER TABLE students ADD COLUMN {column} TEXT"
                )

        # Add academic_year to old payment history if necessary.
        payment_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(fee_payments)"
            ).fetchall()
        }

        if "academic_year" not in payment_columns:
            connection.execute(
                "ALTER TABLE fee_payments ADD COLUMN academic_year INTEGER"
            )

            # Associate historical payments with the student's
            # currently registered year without deleting history.
            connection.execute("""
                UPDATE fee_payments
                SET academic_year = COALESCE(
                    (
                        SELECT CAST(year AS INTEGER)
                        FROM students
                        WHERE students.student_id =
                              fee_payments.student_id
                    ),
                    1
                )
                WHERE academic_year IS NULL
            """)

        # Migrate old fee records into the student's current year.
        # INSERT OR IGNORE preserves any existing yearly fee records.
        connection.execute("""
            INSERT OR IGNORE INTO yearly_fees
                (student_id, academic_year, total_amount, paid_amount)
            SELECT
                f.student_id,
                CASE
                    WHEN CAST(s.year AS INTEGER) BETWEEN 1 AND 4
                    THEN CAST(s.year AS INTEGER)
                    ELSE 1
                END,
                COALESCE(f.total_amount, 0),
                COALESCE(f.paid_amount, 0)
            FROM fees f
            JOIN students s ON s.student_id = f.student_id
        """)

        connection.commit()

    finally:
        connection.close()


# ==================== FEE HELPERS ====================

def valid_year(value, default=None):
    try:
        year = int(value)
        if 1 <= year <= 4:
            return year
    except (TypeError, ValueError):
        pass
    return default


def year_label(year):
    return {
        1: "1st Year",
        2: "2nd Year",
        3: "3rd Year",
        4: "4th Year"
    }.get(year, f"Year {year}")


def fee_status(total, paid):
    if total > 0 and paid >= total:
        return "Paid"
    if paid > 0:
        return "Partially Paid"
    return "Unpaid"


def ensure_yearly_fee_rows(connection, student_id):
    """Create missing zero-value records without overwriting fees."""
    for year in range(1, 5):
        connection.execute("""
            INSERT OR IGNORE INTO yearly_fees
                (student_id, academic_year, total_amount, paid_amount)
            VALUES (?, ?, 0, 0)
        """, (student_id, year))


def get_year_fee(connection, student_id, year):
    return connection.execute("""
        SELECT *
        FROM yearly_fees
        WHERE student_id = ? AND academic_year = ?
    """, (student_id, year)).fetchone()


def fee_record(row):
    total = float(row["total_amount"] or 0)
    paid = float(row["paid_amount"] or 0)

    return {
        "id": row["id"],
        "student_id": row["student_id"],
        "academic_year": int(row["academic_year"]),
        "year": int(row["academic_year"]),
        "year_label": year_label(int(row["academic_year"])),
        "total_amount": total,
        "paid_amount": paid,
        "balance": max(total - paid, 0),
        "status": fee_status(total, paid)
    }


def get_fee_totals(connection, student_id):
    rows = connection.execute("""
        SELECT *
        FROM yearly_fees
        WHERE student_id = ?
        ORDER BY academic_year
    """, (student_id,)).fetchall()

    years = [fee_record(row) for row in rows]

    total = sum(item["total_amount"] for item in years)
    paid = sum(item["paid_amount"] for item in years)
    balance = sum(item["balance"] for item in years)

    return {
        "years": years,
        "total_amount": total,
        "paid_amount": paid,
        "balance": balance,
        "status": fee_status(total, paid)
    }


# ==================== AUTH HELPERS ====================

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


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
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


# ==================== HOME ====================

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Nehru Group of Institutions Hostel Management System",
        "status": "Backend is running successfully"
    })


# ==================== REGISTRATION ====================

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
            student_id, name, email, username,
            generate_password_hash(password),
            str(data.get("dob", "")),
            str(data.get("department", "")),
            str(data.get("year", "")),
            str(data.get("academicYear", data.get("academic_year", ""))),
            str(data.get("roomNumber", data.get("room_number", ""))),
            str(data.get("phone", ""))
        ))

        # Prepare four year-wise records for the new student.
        ensure_yearly_fee_rows(connection, student_id)
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


# ==================== STUDENT LOGIN ====================

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


# ==================== ADMIN LOGIN ====================

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


# ==================== ADMIN STUDENTS ====================

@app.route("/api/admin/students", methods=["GET", "OPTIONS"])
@admin_required
def admin_students():
    if request.method == "OPTIONS":
        return "", 204

    connection = get_db()

    try:
        rows = connection.execute("""
            SELECT student_id, name, email, username, dob,
                   department, year, academic_year, room_number, phone
            FROM students ORDER BY id DESC
        """).fetchall()

        students = [dict(row) for row in rows]

        return jsonify({
            "success": True,
            "count": len(students),
            "students": students
        })

    finally:
        connection.close()


# ==================== STUDENT OUTPASSES ====================

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
                student_id, student["name"], reason,
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
            WHERE student_id = ? ORDER BY id DESC
        """, (student_id,)).fetchall()

        return jsonify({
            "success": True,
            "outpasses": [dict(row) for row in rows]
        })

    finally:
        connection.close()


# ==================== ADMIN OUTPASSES ====================

@app.route("/api/admin/outpasses", methods=["GET", "OPTIONS"])
@admin_required
def admin_outpasses():
    if request.method == "OPTIONS":
        return "", 204

    connection = get_db()

    try:
        rows = connection.execute(
            "SELECT * FROM outpasses ORDER BY id DESC"
        ).fetchall()

        return jsonify({
            "success": True,
            "outpasses": [dict(row) for row in rows]
        })

    finally:
        connection.close()


@app.route(
    "/api/admin/outpasses/<int:outpass_id>/status",
    methods=["POST", "OPTIONS"]
)
@admin_required
def update_outpass(outpass_id):
    if request.method == "OPTIONS":
        return "", 204

    status = str(read_json().get("status", "")).strip().title()

    if status not in ["Approved", "Rejected", "Pending"]:
        return jsonify({
            "success": False,
            "message": "Invalid outpass status."
        }), 400

    connection = get_db()

    try:
        cursor = connection.execute(
            "UPDATE outpasses SET status = ? WHERE id = ?",
            (status, outpass_id)
        )
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


# ==================== STUDENT COMPLAINTS ====================

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
                student_id, student["name"],
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
            WHERE student_id = ? ORDER BY id DESC
        """, (student_id,)).fetchall()

        return jsonify({
            "success": True,
            "complaints": [dict(row) for row in rows]
        })

    finally:
        connection.close()


# ==================== ADMIN COMPLAINTS ====================

@app.route("/api/admin/complaints", methods=["GET", "OPTIONS"])
@admin_required
def admin_complaints():
    if request.method == "OPTIONS":
        return "", 204

    connection = get_db()

    try:
        rows = connection.execute(
            "SELECT * FROM complaints ORDER BY id DESC"
        ).fetchall()

        return jsonify({
            "success": True,
            "complaints": [dict(row) for row in rows]
        })

    finally:
        connection.close()


@app.route(
    "/api/admin/complaints/<int:complaint_id>/status",
    methods=["POST", "OPTIONS"]
)
@admin_required
def update_complaint(complaint_id):
    if request.method == "OPTIONS":
        return "", 204

    status = str(read_json().get("status", "")).strip().title()

    if status not in ["Pending", "In Progress", "Resolved", "Rejected"]:
        return jsonify({
            "success": False,
            "message": "Invalid complaint status."
        }), 400

    connection = get_db()

    try:
        cursor = connection.execute(
            "UPDATE complaints SET status = ? WHERE id = ?",
            (status, complaint_id)
        )
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


# ==================== ATTENDANCE ====================

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
    if request.method == "OPTIONS":
        return "", 204

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
                DO UPDATE SET
                    status = excluded.status,
                    student_name = excluded.student_name
            """, (
                student_id, student["name"], attendance_date, status
            ))

            connection.commit()

            return jsonify({
                "success": True,
                "message": "Attendance saved."
            }), 201

        rows = connection.execute(
            "SELECT * FROM attendance ORDER BY attendance_date DESC"
        ).fetchall()

        return jsonify({
            "success": True,
            "attendance": [dict(row) for row in rows],
            "count": len(rows)
        })

    finally:
        connection.close()


# ==================== STUDENT FEES ====================

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

        ensure_yearly_fee_rows(connection, student_id)
        connection.commit()

        totals = get_fee_totals(connection, student_id)

        payment_rows = connection.execute("""
            SELECT id, student_id, academic_year, amount,
                   payment_method, transaction_id, status, created_at
            FROM fee_payments
            WHERE student_id = ?
            ORDER BY id DESC
        """, (student_id,)).fetchall()

        payments = [dict(row) for row in payment_rows]

        for payment in payments:
            payment["academic_year"] = (
                payment["academic_year"] or valid_year(student["year"], 1)
            )
            payment["year_label"] = year_label(payment["academic_year"])

        # Keep "fees" for compatibility with the older student page.
        current_year = valid_year(student["year"], 1)
        current_fee = next(
            item for item in totals["years"]
            if item["academic_year"] == current_year
        )

        return jsonify({
            "success": True,
            "student_id": student_id,
            "year": current_year,
            "fees": current_fee,
            "years": totals["years"],
            "total_amount": totals["total_amount"],
            "paid_amount": totals["paid_amount"],
            "balance": totals["balance"],
            "status": totals["status"],
            "payments": payments
        })

    except sqlite3.Error:
        app.logger.exception("Student fees error")
        return jsonify({
            "success": False,
            "message": "Could not load fee details."
        }), 500

    finally:
        connection.close()


# ==================== STUDENT FEE PAYMENT ====================

@app.route("/api/fees/payment", methods=["POST", "OPTIONS"])
def make_fee_payment():
    if request.method == "OPTIONS":
        return "", 204

    data = read_json()
    student_id = str(data.get("student_id", "")).strip()
    payment_method = str(data.get("payment_method", "Other")).strip()
    academic_year = valid_year(data.get("academic_year"))

    try:
        amount = round(float(data.get("amount", 0)), 2)
    except (TypeError, ValueError):
        return jsonify({
            "success": False,
            "message": "Enter a valid payment amount."
        }), 400

    if not student_id or amount <= 0:
        return jsonify({
            "success": False,
            "message": "Student ID and a positive payment amount are required."
        }), 400

    connection = get_db()

    try:
        student = get_student(connection, student_id)
        if not student:
            return student_not_found()

        if academic_year is None:
            academic_year = valid_year(student["year"], 1)

        ensure_yearly_fee_rows(connection, student_id)

        fee = get_year_fee(connection, student_id, academic_year)

        if not fee:
            return jsonify({
                "success": False,
                "message": "Fee record not found for that academic year."
            }), 404

        total = float(fee["total_amount"] or 0)
        paid = float(fee["paid_amount"] or 0)
        balance = max(total - paid, 0)

        if amount > balance:
            return jsonify({
                "success": False,
                "message": f"Payment exceeds the balance of ₹{balance:.2f}."
            }), 400

        transaction_id = "SIM-" + datetime.now().strftime(
            "%Y%m%d%H%M%S%f"
        )

        # This records a simulated payment, not a real bank transaction.
        connection.execute("""
            INSERT INTO fee_payments (
                student_id, academic_year, amount, payment_method,
                transaction_id, status
            )
            VALUES (?, ?, ?, ?, ?, 'Success')
        """, (
            student_id, academic_year, amount,
            payment_method, transaction_id
        ))

        connection.execute("""
            UPDATE yearly_fees
            SET paid_amount = paid_amount + ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE student_id = ? AND academic_year = ?
        """, (amount, student_id, academic_year))

        connection.commit()

        totals = get_fee_totals(connection, student_id)

        return jsonify({
            "success": True,
            "message": "Payment recorded successfully.",
            "transaction_id": transaction_id,
            "academic_year": academic_year,
            "year_label": year_label(academic_year),
            "total_amount": totals["total_amount"],
            "paid_amount": totals["paid_amount"],
            "balance": totals["balance"],
            "years": totals["years"]
        }), 201

    except sqlite3.Error:
        connection.rollback()
        app.logger.exception("Fee payment error")
        return jsonify({
            "success": False,
            "message": "Could not save the payment."
        }), 500

    finally:
        connection.close()


# ==================== ADMIN FEE MANAGEMENT ====================

@app.route("/api/admin/fees", methods=["GET", "POST", "OPTIONS"])
@admin_required
def manage_fees():
    if request.method == "OPTIONS":
        return "", 204

    connection = get_db()

    try:
        if request.method == "POST":
            data = read_json()
            student_id = str(data.get("student_id", "")).strip()

            academic_year = valid_year(data.get("academic_year"))

            if not student_id:
                return jsonify({
                    "success": False,
                    "message": "Student ID is required."
                }), 400

            student = get_student(connection, student_id)
            if not student:
                return student_not_found()

            if academic_year is None:
                academic_year = valid_year(student["year"], 1)

            try:
                total = round(float(data.get("total_amount", 0)), 2)
            except (TypeError, ValueError):
                return jsonify({
                    "success": False,
                    "message": "Total fee must be a valid number."
                }), 400

            if total < 0:
                return jsonify({
                    "success": False,
                    "message": "Total fee cannot be negative."
                }), 400

            ensure_yearly_fee_rows(connection, student_id)

            existing = get_year_fee(
                connection, student_id, academic_year
            )

            paid = float(existing["paid_amount"] or 0)

            if total < paid:
                return jsonify({
                    "success": False,
                    "message": (
                        "Total fee cannot be less than the amount already paid."
                    )
                }), 400

            connection.execute("""
                UPDATE yearly_fees
                SET total_amount = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE student_id = ? AND academic_year = ?
            """, (total, student_id, academic_year))

            connection.commit()

            return jsonify({
                "success": True,
                "message": (
                    f"{year_label(academic_year)} fee saved successfully."
                )
            }), 200

        # Four rows per student, one for each academic year.
        students = connection.execute("""
            SELECT student_id, name, department, year
            FROM students
            ORDER BY id DESC
        """).fetchall()

        records = []

        for student in students:
            sid = student["student_id"]
            ensure_yearly_fee_rows(connection, sid)

            year_rows = connection.execute("""
                SELECT *
                FROM yearly_fees
                WHERE student_id = ?
                ORDER BY academic_year
            """, (sid,)).fetchall()

            for row in year_rows:
                item = fee_record(row)
                item["student_name"] = student["name"]
                item["name"] = student["name"]
                item["department"] = student["department"]
                item["current_year"] = valid_year(student["year"], 1)
                records.append(item)

        connection.commit()

        return jsonify({
            "success": True,
            "fees": records
        })

    except sqlite3.Error:
        connection.rollback()
        app.logger.exception("Admin fee management error")
        return jsonify({
            "success": False,
            "message": "Could not load or update fee records."
        }), 500

    finally:
        connection.close()


# ==================== ADMIN DASHBOARD ====================

@app.route("/api/admin/dashboard", methods=["GET", "OPTIONS"])
@admin_required
def admin_dashboard():
    if request.method == "OPTIONS":
        return "", 204

    connection = get_db()

    try:
        students = connection.execute("""
            SELECT student_id, name, email, department, year,
                   academic_year, room_number, phone
            FROM students ORDER BY id DESC
        """).fetchall()

        outpasses = connection.execute(
            "SELECT * FROM outpasses ORDER BY id DESC"
        ).fetchall()

        complaints = connection.execute(
            "SELECT * FROM complaints ORDER BY id DESC"
        ).fetchall()

        attendance_count = connection.execute(
            "SELECT COUNT(*) AS total FROM attendance"
        ).fetchone()["total"]

        fee_rows = connection.execute("""
            SELECT
                s.student_id,
                s.name AS student_name,
                s.department,
                yf.academic_year,
                yf.total_amount,
                yf.paid_amount
            FROM students s
            JOIN yearly_fees yf ON yf.student_id = s.student_id
            ORDER BY s.id DESC, yf.academic_year
        """).fetchall()

        fees = []

        for row in fee_rows:
            item = fee_record(row)
            item["student_name"] = row["student_name"]
            item["name"] = row["student_name"]
            item["department"] = row["department"]
            fees.append(item)

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
            1 for item in fees if item["status"] != "Paid"
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


# ==================== START APPLICATION ====================

create_table()

if __name__ == "__main__":
    app.run(debug=False)
