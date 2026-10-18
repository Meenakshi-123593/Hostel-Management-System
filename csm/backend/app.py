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


def initialize_database():
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            dob TEXT,
            department TEXT,
            year INTEGER DEFAULT 1,
            academic_year TEXT,
            room_number TEXT,
            phone TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS outpasses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            reason TEXT,
            destination TEXT,
            date TEXT,
            status TEXT DEFAULT 'Pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS complaints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            category TEXT,
            complaint TEXT,
            status TEXT DEFAULT 'Pending',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            date TEXT NOT NULL,
            status TEXT DEFAULT 'Present'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL,
            total_amount REAL DEFAULT 0,
            paid_amount REAL DEFAULT 0,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS fee_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            amount REAL NOT NULL,
            payment_method TEXT,
            transaction_id TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'Success',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)

    db.commit()
    db.close()


# ==================== RESPONSES ====================

def error(message, status=400):
    return jsonify({
        "success": False,
        "message": message
    }), status


def student_exists(db, student_id):
    return db.execute(
        "SELECT * FROM students WHERE student_id = ?",
        (student_id,)
    ).fetchone()


# ==================== ADMIN AUTHENTICATION ====================

def get_serializer():
    secret = os.environ.get("ADMIN_TOKEN_SECRET")

    if not secret:
        return None

    return URLSafeTimedSerializer(secret)


def admin_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if request.method == "OPTIONS":
            return "", 204

        authorization = request.headers.get("Authorization", "")

        if not authorization.startswith("Bearer "):
            return error("Admin login required", 401)

        serializer = get_serializer()

        if serializer is None:
            return error("Admin authentication is not configured", 503)

        token = authorization.split(" ", 1)[1]

        try:
            serializer.loads(token, max_age=28800)
        except (BadSignature, SignatureExpired):
            return error("Invalid or expired admin session", 401)

        return function(*args, **kwargs)

    return wrapper


# ==================== HOME ====================

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Nehru Group of Institutions Hostel Management System",
        "status": "Backend is running successfully"
    })


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "status": "healthy"
    })


# ==================== STUDENT REGISTRATION ====================

@app.route("/api/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json(silent=True) or {}

    name = str(data.get("name", "")).strip()
    email = str(data.get("email", "")).strip().lower()
    username = str(data.get("username", email)).strip()
    password = str(data.get("password", ""))

    if not name or not email or not username or not password:
        return error("Name, email, username and password are required")

    if len(password) < 6:
        return error("Password must contain at least 6 characters")

    department = str(data.get("department", "")).strip()
    dob = str(data.get("dob", "")).strip()
    phone = str(data.get("phone", "")).strip()

    room_number = str(
        data.get("room_number", data.get("roomNumber", ""))
    ).strip()

    # FIX: Accept year values sent by register.html:
    # "1st Year", "2nd Year", "3rd Year", "4th Year"
    # Also accept numeric values such as 1, 2, 3, 4.

    year_value = str(data.get("year", "1")).strip()

    year_mapping = {
        "1st Year": 1,
        "2nd Year": 2,
        "3rd Year": 3,
        "4th Year": 4
    }

    if year_value in year_mapping:
        year = year_mapping[year_value]
    else:
        try:
            year = int(year_value)
        except (TypeError, ValueError):
            return error("Invalid academic year")

    if year not in (1, 2, 3, 4):
        return error("Year must be between 1 and 4")

    # Academic batch, for example 2025-2028, is stored separately.
    academic_year = str(
        data.get(
            "academic_year",
            data.get("academicYear", str(year))
        )
    ).strip()

    if not academic_year:
        return error("Please select an academic year")

    db = get_db()

    try:
        cursor = db.execute("""
            INSERT INTO students
            (
                name,
                email,
                username,
                password,
                dob,
                department,
                year,
                academic_year,
                room_number,
                phone
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            name,
            email,
            username,
            generate_password_hash(password),
            dob,
            department,
            year,
            academic_year,
            room_number,
            phone
        ))

        # Preserve the existing automatic student ID generation.
        student_id = "STU{:03d}".format(cursor.lastrowid)

        db.execute(
            "UPDATE students SET student_id = ? WHERE id = ?",
            (student_id, cursor.lastrowid)
        )

        db.commit()

        return jsonify({
            "success": True,
            "message": "Registration successful",
            "student_id": student_id
        }), 201

    except sqlite3.IntegrityError:
        db.rollback()
        return error(
            "Email or username already registered",
            409
        )

    except sqlite3.Error:
        db.rollback()
        app.logger.exception("Student registration failed")
        return error("Unable to complete registration", 500)

    finally:
        db.close()


# ==================== STUDENT LOGIN ====================

@app.route("/api/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json(silent=True) or {}

    identity = str(
        data.get("username", data.get("email", ""))
    ).strip().lower()

    password = str(data.get("password", ""))

    if not identity or not password:
        return error("Username/email and password are required")

    db = get_db()

    try:
        student = db.execute("""
            SELECT *
            FROM students
            WHERE lower(username) = ?
               OR lower(email) = ?
               OR lower(student_id) = ?
        """, (
            identity,
            identity,
            identity
        )).fetchone()
    finally:
        db.close()

    if not student or not check_password_hash(
        student["password"], password
    ):
        return error("Invalid login credentials", 401)

    return jsonify({
        "success": True,
        "message": "Login successful",
        "student": {
            "student_id": student["student_id"],
            "name": student["name"],
            "email": student["email"],
            "username": student["username"],
            "department": student["department"],
            "year": student["year"],
            "academic_year": student["academic_year"],
            "room_number": student["room_number"],
            "phone": student["phone"]
        }
    })


# ==================== ADMIN LOGIN ====================

@app.route("/api/admin/login", methods=["POST", "OPTIONS"])
def admin_login():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json(silent=True) or {}

    username = os.environ.get("ADMIN_USERNAME")
    password = os.environ.get("ADMIN_PASSWORD")

    if (
        not username
        or not password
        or not os.environ.get("ADMIN_TOKEN_SECRET")
    ):
        return error("Admin credentials are not configured", 503)

    if (
        data.get("username") != username
        or data.get("password") != password
    ):
        return error("Invalid admin credentials", 401)

    token = get_serializer().dumps({
        "username": username,
        "role": "admin"
    })

    return jsonify({
        "success": True,
        "message": "Admin login successful",
        "token": token
    })


# ==================== ADMIN STUDENT RECORDS ====================

@app.route("/api/admin/students", methods=["GET", "OPTIONS"])
@admin_required
def admin_students():
    db = get_db()

    try:
        rows = db.execute("""
            SELECT
                student_id,
                name,
                email,
                department,
                year,
                academic_year,
                room_number,
                phone
            FROM students
            ORDER BY id DESC
        """).fetchall()
    finally:
        db.close()

    return jsonify({
        "success": True,
        "students": [dict(row) for row in rows]
    })


# ==================== OUTPASSES ====================

@app.route("/api/outpasses", methods=["GET", "POST", "OPTIONS"])
def outpasses():
    if request.method == "OPTIONS":
        return "", 204

    db = get_db()

    if request.method == "POST":
        data = request.get_json(silent=True) or {}

        student_id = str(data.get("student_id", "")).strip()
        reason = data.get("reason", "")
        destination = data.get("destination", "")
        date = data.get("date", "")

        if not student_id:
            db.close()
            return error("Student ID is required")

        if not student_exists(db, student_id):
            db.close()
            return error("Student not found", 404)

        db.execute("""
            INSERT INTO outpasses
            (student_id, reason, destination, date)
            VALUES (?, ?, ?, ?)
        """, (
            student_id,
            reason,
            destination,
            date
        ))

        db.commit()
        db.close()

        return jsonify({
            "success": True,
            "message": "Outpass submitted successfully"
        }), 201

    student_id = request.args.get("student_id")

    if student_id:
        rows = db.execute("""
            SELECT *
            FROM outpasses
            WHERE student_id = ?
            ORDER BY id DESC
        """, (student_id,)).fetchall()
    else:
        rows = db.execute("""
            SELECT *
            FROM outpasses
            ORDER BY id DESC
        """).fetchall()

    db.close()

    return jsonify({
        "success": True,
        "outpasses": [dict(row) for row in rows]
    })


@app.route("/api/admin/outpasses", methods=["GET", "OPTIONS"])
@admin_required
def admin_get_outpasses():
    db = get_db()

    rows = db.execute("""
        SELECT o.*, s.name
        FROM outpasses o
        LEFT JOIN students s ON s.student_id = o.student_id
        ORDER BY o.id DESC
    """).fetchall()

    db.close()

    return jsonify({
        "success": True,
        "outpasses": [dict(row) for row in rows]
    })


@app.route(
    "/api/admin/outpasses/<int:outpass_id>/status",
    methods=["POST", "OPTIONS"]
)
@admin_required
def admin_update_outpass(outpass_id):
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json(silent=True) or {}
    status = data.get("status")

    if status not in ("Pending", "Approved", "Rejected"):
        return error("Invalid outpass status")

    db = get_db()

    cursor = db.execute(
        "UPDATE outpasses SET status = ? WHERE id = ?",
        (status, outpass_id)
    )

    db.commit()
    db.close()

    if cursor.rowcount == 0:
        return error("Outpass not found", 404)

    return jsonify({
        "success": True,
        "message": "Outpass updated"
    })


# ==================== COMPLAINTS ====================

@app.route("/api/complaints", methods=["GET", "POST", "OPTIONS"])
def complaints():
    if request.method == "OPTIONS":
        return "", 204

    db = get_db()

    if request.method == "POST":
        data = request.get_json(silent=True) or {}

        student_id = str(data.get("student_id", "")).strip()
        category = data.get("category", "")
        complaint = data.get(
            "complaint",
            data.get("description", "")
        )

        if not student_id or not complaint:
            db.close()
            return error("Student ID and complaint are required")

        if not student_exists(db, student_id):
            db.close()
            return error("Student not found", 404)

        db.execute("""
            INSERT INTO complaints (student_id, category, complaint)
            VALUES (?, ?, ?)
        """, (
            student_id,
            category,
            complaint
        ))

        db.commit()
        db.close()

        return jsonify({
            "success": True,
            "message": "Complaint submitted successfully"
        }), 201

    student_id = request.args.get("student_id")

    if student_id:
        rows = db.execute("""
            SELECT *
            FROM complaints
            WHERE student_id = ?
            ORDER BY id DESC
        """, (student_id,)).fetchall()
    else:
        rows = db.execute("""
            SELECT *
            FROM complaints
            ORDER BY id DESC
        """).fetchall()

    db.close()

    return jsonify({
        "success": True,
        "complaints": [dict(row) for row in rows]
    })


@app.route("/api/admin/complaints", methods=["GET", "OPTIONS"])
@admin_required
def admin_get_complaints():
    db = get_db()

    rows = db.execute("""
        SELECT c.*, s.name
        FROM complaints c
        LEFT JOIN students s ON s.student_id = c.student_id
        ORDER BY c.id DESC
    """).fetchall()

    db.close()

    return jsonify({
        "success": True,
        "complaints": [dict(row) for row in rows]
    })


@app.route(
    "/api/admin/complaints/<int:complaint_id>/status",
    methods=["POST", "OPTIONS"]
)
@admin_required
def admin_update_complaint(complaint_id):
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json(silent=True) or {}
    status = data.get("status")

    if status not in (
        "Pending",
        "In Progress",
        "Resolved",
        "Rejected"
    ):
        return error("Invalid complaint status")

    db = get_db()

    cursor = db.execute(
        "UPDATE complaints SET status = ? WHERE id = ?",
        (status, complaint_id)
    )

    db.commit()
    db.close()

    if cursor.rowcount == 0:
        return error("Complaint not found", 404)

    return jsonify({
        "success": True,
        "message": "Complaint updated"
    })


# ==================== ATTENDANCE ====================

@app.route("/api/attendance", methods=["GET", "OPTIONS"])
def attendance():
    if request.method == "OPTIONS":
        return "", 204

    student_id = request.args.get("student_id")

    if not student_id:
        return error("Student ID is required")

    db = get_db()

    rows = db.execute("""
        SELECT *
        FROM attendance
        WHERE student_id = ?
        ORDER BY date DESC
    """, (student_id,)).fetchall()

    db.close()

    records = [dict(row) for row in rows]
    total = len(records)

    present = sum(
        1 for row in records
        if str(row["status"]).lower() == "present"
    )

    return jsonify({
        "success": True,
        "attendance": records,
        "total": total,
        "present": present,
        "percentage": round(
            present * 100 / total, 2
        ) if total else 0
    })


@app.route(
    "/api/admin/attendance",
    methods=["GET", "POST", "OPTIONS"]
)
@admin_required
def admin_attendance():
    if request.method == "OPTIONS":
        return "", 204

    db = get_db()

    if request.method == "POST":
        data = request.get_json(silent=True) or {}

        student_id = data.get("student_id")
        date = data.get("date") or datetime.now().strftime("%Y-%m-%d")
        status = data.get("status", "Present")

        if status not in ("Present", "Absent"):
            db.close()
            return error("Status must be Present or Absent")

        if not student_id or not student_exists(db, student_id):
            db.close()
            return error("Student not found", 404)

        existing = db.execute("""
            SELECT id
            FROM attendance
            WHERE student_id = ? AND date = ?
        """, (
            student_id,
            date
        )).fetchone()

        if existing:
            db.execute(
                "UPDATE attendance SET status = ? WHERE id = ?",
                (status, existing["id"])
            )
        else:
            db.execute("""
                INSERT INTO attendance (student_id, date, status)
                VALUES (?, ?, ?)
            """, (
                student_id,
                date,
                status
            ))

        db.commit()
        db.close()

        return jsonify({
            "success": True,
            "message": "Attendance saved"
        })

    rows = db.execute("""
        SELECT a.*, s.name
        FROM attendance a
        LEFT JOIN students s ON s.student_id = a.student_id
        ORDER BY a.date DESC
    """).fetchall()

    db.close()

    return jsonify({
        "success": True,
        "attendance": [dict(row) for row in rows]
    })


# ==================== STUDENT FEES ====================

@app.route("/api/fees", methods=["GET", "OPTIONS"])
def get_fees():
    if request.method == "OPTIONS":
        return "", 204

    student_id = request.args.get("student_id")

    if not student_id:
        return error("Student ID is required")

    db = get_db()

    student = student_exists(db, student_id)

    if not student:
        db.close()
        return error("Student not found", 404)

    fee = db.execute(
        "SELECT * FROM fees WHERE student_id = ?",
        (student_id,)
    ).fetchone()

    payments = db.execute("""
        SELECT *
        FROM fee_payments
        WHERE student_id = ?
        ORDER BY id DESC
    """, (student_id,)).fetchall()

    db.close()

    total = float(fee["total_amount"]) if fee else 0
    paid = float(fee["paid_amount"]) if fee else 0
    balance = max(total - paid, 0)

    return jsonify({
        "success": True,
        "student_id": student_id,
        "year": student["year"],
        "total_amount": total,
        "paid_amount": paid,
        "balance": balance,
        "status": (
            "Paid" if balance == 0 and total > 0
            else "Partial" if paid > 0
            else "Pending"
        ),
        "payments": [dict(row) for row in payments]
    })


# ==================== SIMULATED FEE PAYMENT ====================

@app.route("/api/fees/payment", methods=["POST", "OPTIONS"])
def make_fee_payment():
    if request.method == "OPTIONS":
        return "", 204

    data = request.get_json(silent=True) or {}

    student_id = str(data.get("student_id", "")).strip()

    payment_method = str(
        data.get("payment_method", data.get("method", "UPI"))
    ).strip()

    try:
        amount = float(data.get("amount", 0))
    except (TypeError, ValueError):
        return error("Invalid payment amount")

    if not student_id:
        return error("Student ID is required")

    if amount <= 0:
        return error("Payment amount must be greater than zero")

    if amount > 1000000:
        return error("Payment amount is too large")

    db = get_db()

    if not student_exists(db, student_id):
        db.close()
        return error("Student not found", 404)

    fee = db.execute(
        "SELECT * FROM fees WHERE student_id = ?",
        (student_id,)
    ).fetchone()

    if not fee:
        db.close()
        return error(
            "No fee record configured for this student",
            404
        )

    total = float(fee["total_amount"])
    paid = float(fee["paid_amount"])
    balance = max(total - paid, 0)

    if balance <= 0:
        db.close()
        return error("No outstanding fees")

    if amount > balance:
        db.close()
        return error("Payment exceeds the outstanding balance")

    transaction_id = "SIM-" + datetime.now().strftime(
        "%Y%m%d%H%M%S%f"
    )

    try:
        db.execute("""
            INSERT INTO fee_payments
            (
                student_id,
                amount,
                payment_method,
                transaction_id,
                status
            )
            VALUES (?, ?, ?, ?, 'Success')
        """, (
            student_id,
            amount,
            payment_method,
            transaction_id
        ))

        db.execute("""
            UPDATE fees
            SET paid_amount = paid_amount + ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE student_id = ?
        """, (
            amount,
            student_id
        ))

        db.commit()

        updated = db.execute(
            "SELECT * FROM fees WHERE student_id = ?",
            (student_id,)
        ).fetchone()

        result = {
            "success": True,
            "message": "Simulated payment recorded successfully",
            "transaction_id": transaction_id,
            "amount_paid": amount,
            "total_amount": float(updated["total_amount"]),
            "paid_amount": float(updated["paid_amount"]),
            "balance": max(
                float(updated["total_amount"])
                - float(updated["paid_amount"]),
                0
            )
        }

        db.close()
        return jsonify(result)

    except Exception:
        db.rollback()
        db.close()
        app.logger.exception("Fee payment failed")
        return error("Unable to record payment", 500)


# ==================== ADMIN FEES ====================

@app.route(
    "/api/admin/fees",
    methods=["GET", "POST", "OPTIONS"]
)
@admin_required
def admin_fees():
    if request.method == "OPTIONS":
        return "", 204

    db = get_db()

    if request.method == "POST":
        data = request.get_json(silent=True) or {}

        student_id = str(data.get("student_id", "")).strip()

        try:
            total = float(data.get("total_amount", 0))
        except (TypeError, ValueError):
            db.close()
            return error("Invalid total fee amount")

        if not student_id or total < 0:
            db.close()
            return error(
                "Valid student ID and fee amount are required"
            )

        if not student_exists(db, student_id):
            db.close()
            return error("Student not found", 404)

        existing = db.execute(
            "SELECT * FROM fees WHERE student_id = ?",
            (student_id,)
        ).fetchone()

        if existing:
            paid = float(existing["paid_amount"])

            if total < paid:
                db.close()
                return error(
                    "Total fee cannot be less than the amount paid"
                )

            db.execute("""
                UPDATE fees
                SET total_amount = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE student_id = ?
            """, (
                total,
                student_id
            ))
        else:
            db.execute("""
                INSERT INTO fees
                (student_id, total_amount, paid_amount)
                VALUES (?, ?, 0)
            """, (
                student_id,
                total
            ))

        db.commit()
        db.close()

        return jsonify({
            "success": True,
            "message": "Fee record saved successfully"
        })

    rows = db.execute("""
        SELECT
            s.student_id,
            s.name,
            s.department,
            s.year,
            COALESCE(f.total_amount, 0) AS total_amount,
            COALESCE(f.paid_amount, 0) AS paid_amount,
            MAX(
                COALESCE(f.total_amount, 0)
                - COALESCE(f.paid_amount, 0),
                0
            ) AS balance
        FROM students s
        LEFT JOIN fees f ON f.student_id = s.student_id
        ORDER BY s.year, s.name
    """).fetchall()

    db.close()

    result = []

    for row in rows:
        item = dict(row)

        if item["total_amount"] > 0 and item["balance"] == 0:
            item["status"] = "Paid"
        elif item["paid_amount"] > 0:
            item["status"] = "Partial"
        else:
            item["status"] = "Pending"

        result.append(item)

    return jsonify({
        "success": True,
        "fees": result
    })


# ==================== ADMIN DASHBOARD ====================

@app.route("/api/admin/dashboard", methods=["GET", "OPTIONS"])
@admin_required
def admin_dashboard():
    db = get_db()

    students = db.execute(
        "SELECT COUNT(*) AS count FROM students"
    ).fetchone()["count"]

    pending_outpasses = db.execute("""
        SELECT COUNT(*) AS count
        FROM outpasses
        WHERE status = 'Pending'
    """).fetchone()["count"]

    pending_complaints = db.execute("""
        SELECT COUNT(*) AS count
        FROM complaints
        WHERE status = 'Pending'
    """).fetchone()["count"]

    attendance_count = db.execute(
        "SELECT COUNT(*) AS count FROM attendance"
    ).fetchone()["count"]

    fee_summary = db.execute("""
        SELECT
            COALESCE(SUM(total_amount), 0) AS total,
            COALESCE(SUM(paid_amount), 0) AS paid
        FROM fees
    """).fetchone()

    db.close()

    total_fees = float(fee_summary["total"])
    paid_fees = float(fee_summary["paid"])

    return jsonify({
        "success": True,
        "students": students,
        "registered_students": students,
        "pending_outpasses": pending_outpasses,
        "pending_complaints": pending_complaints,
        "attendance_records": attendance_count,
        "total_fees": total_fees,
        "paid_fees": paid_fees,
        "fee_balance": max(total_fees - paid_fees, 0)
    })


# ==================== STARTUP ====================

initialize_database()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
