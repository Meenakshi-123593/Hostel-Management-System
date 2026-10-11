from flask import Flask, request, jsonify
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response

DATABASE = "hostel.db"


def get_db():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_table():
    connection = get_db()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    connection.commit()
    connection.close()


@app.route("/")
def home():
    return jsonify({
        "message": "Nehru Group of Institutions Hostel Management System",
        "status": "Backend is running successfully"
    })


@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json(silent=True) or {}

    student_id = data.get("student_id", "").strip()
    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not all([student_id, name, email, username, password]):
        return jsonify({
            "message": "Please fill in all required fields."
        }), 400

    connection = get_db()

    try:
        connection.execute("""
            INSERT INTO students
            (student_id, name, email, username, password)
            VALUES (?, ?, ?, ?, ?)
        """, (
            student_id,
            name,
            email,
            username,
            generate_password_hash(password)
        ))

        connection.commit()

        return jsonify({
            "message": "Registration successful!"
        }), 201

    except sqlite3.IntegrityError:
        return jsonify({
            "message": "Student ID, email, or username already exists."
        }), 409

    finally:
        connection.close()


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username", "").strip()
    password = data.get("password", "")

    connection = get_db()

    try:
        student = connection.execute("""
            SELECT * FROM students WHERE username = ?
        """, (username,)).fetchone()

        if student and check_password_hash(
            student["password"], password
        ):
            return jsonify({
                "message": "Login successful!",
                "student": {
                    "student_id": student["student_id"],
                    "name": student["name"],
                    "email": student["email"],
                    "username": student["username"]
                }
            })

        return jsonify({
            "message": "Invalid username or password."
        }), 401

    finally:
        connection.close()


# Create the database table when the application starts
create_table()

if __name__ == "__main__":
    app.run(debug=True)
