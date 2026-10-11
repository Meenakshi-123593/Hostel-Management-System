from flask import Flask, request, jsonify
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "hostel.db")


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


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

        connection.commit()

    finally:
        connection.close()


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "Nehru Group of Institutions Hostel Management System",
        "status": "Backend is running successfully"
    })


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
        app.logger.exception("Login database error")
        return jsonify({
            "success": False,
            "message": "A database error occurred."
        }), 500

    finally:
        connection.close()


create_table()


if __name__ == "__main__":
    app.run(debug=True)
