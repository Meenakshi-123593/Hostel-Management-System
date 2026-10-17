from flask import Flask, request, jsonify
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "hostel.db")


# ---------------- CORS ----------------

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = (
        "Content-Type, Authorization"
    )
    response.headers["Access-Control-Allow-Methods"] = (
        "GET, POST, OPTIONS"
    )
    return response


# ---------------- DATABASE ----------------

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
            "dob",
            "department",
            "year",
            "academic_year",
            "room_number",
            "phone"
        ]:
            if column not in columns:
                connection.execute(
                    f"ALTER TABLE students ADD COLUMN {column} TEXT"
                )

        connection.commit()

    finally:
        connection.close()


# ---------------- TOKEN SECURITY ----------------

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
            }),
            503
        )

    authorization = request.headers.get("Authorization", "")
    parts = authorization.split(" ", 1)

    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None, (
            jsonify({
                "success": False,
                "message": "Admin login required."
            }),
            401
        )

    token = parts[1].strip()

    try:
        data = serializer.loads(token, max_age=3600)
        return data, None

    except (BadSignature, SignatureExpired):
        return None, (
            jsonify({
                "success": False,
                "message": "Invalid or expired admin session. Please log in again."
            }),
            401
        )


# ---------------- HOME ----------------

@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Nehru Group of Institutions Hostel Management System",
        "status": "Backend is running successfully"
    })


# ---------------- STUDENT REGISTRATION ----------------

@app.route("/api/register", methods=["POST", "OPTIONS"])
def register():
    if request.method == "OPTIONS":
        return jsonify({"message": "OK"}), 200

    data = request.get_json(silent=True) or {}

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
        app.logger.exception("Registration database error")
        return jsonify({
            "success": False,
            "message": "A database error occurred."
        }), 500

    finally:
        connection.close()


# ---------------- STUDENT LOGIN ----------------

@app.route("/api/login", methods=["POST", "OPTIONS"])
def login():
    if request.method == "OPTIONS":
        return jsonify({"message": "OK"}), 200

    data = request.get_json(silent=True) or {}

    username = str(data.get("username", "")).strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "success": False,
            "message": "Please enter your username and password."
        }), 400

    connection = get_db()

    try:
        student = connection.execute("""
            SELECT * FROM students WHERE username = ?
        """, (username,)).fetchone()

        if student and check_password_hash(
            student["password"], password
        ):
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

        return jsonify({
            "success": False,
            "message": "Invalid username or password."
        }), 401

    except sqlite3.Error:
        app.logger.exception("Student login database error")
        return jsonify({
            "success": False,
            "message": "A database error occurred."
        }), 500

    finally:
        connection.close()


# ---------------- ADMIN LOGIN ----------------

@app.route("/api/admin/login", methods=["POST", "OPTIONS"])
def admin_login():
    if request.method == "OPTIONS":
        return jsonify({"message": "OK"}), 200

    data = request.get_json(silent=True) or {}

    username = str(data.get("username", "")).strip()
    password = data.get("password", "")

    if not username or not password:
        return jsonify({
            "success": False,
            "message": "Enter admin username and password."
        }), 400

    admin_username = os.environ.get("ADMIN_USERNAME")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    serializer = get_serializer()

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


# ---------------- ADMIN: VIEW STUDENTS ----------------

@app.route("/api/admin/students", methods=["GET", "OPTIONS"])
def admin_students():
    if request.method == "OPTIONS":
        return jsonify({"message": "OK"}), 200

    admin, error = require_admin()

    if error:
        return error

    if admin.get("role") != "admin":
        return jsonify({
            "success": False,
            "message": "Admin access required."
        }), 403

    connection = get_db()

    try:
        rows = connection.execute("""
            SELECT
                student_id,
                name,
                email,
                username,
                dob,
                department,
                year,
                academic_year,
                room_number,
                phone
            FROM students
            ORDER BY id DESC
        """).fetchall()

        students = [dict(row) for row in rows]

        return jsonify({
            "success": True,
            "count": len(students),
            "students": students
        }), 200

    except sqlite3.Error:
        app.logger.exception("Admin students database error")
        return jsonify({
            "success": False,
            "message": "Unable to retrieve student records."
        }), 500

    finally:
        connection.close()


# ---------------- START APPLICATION ----------------

create_table()

if __name__ == "__main__":
    app.run(debug=False)