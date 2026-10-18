# ==================== STUDENT FEES ====================

YEARLY_HOSTEL_FEE = 3000

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

    year_text = str(
        student["year"] or student["academic_year"] or "1"
    )
    year_match = __import__("re").search(r"\d+", year_text)
    current_year = int(year_match.group()) if year_match else 1
    current_year = min(max(current_year, 1), 4)

    row = connection.execute(
        "SELECT * FROM fees WHERE student_id = ?",
        (student_id,)
    ).fetchone()

    if row:
        fee = dict(row)
        total = float(fee["total_amount"] or 0)
        paid = float(fee["paid_amount"] or 0)
    else:
        total = YEARLY_HOSTEL_FEE
        paid = 0

    return jsonify({
        "success": True,
        "fees": {
            "student_id": student_id,
            "student_name": student["name"],
            "year": current_year,
            "total_amount": total,
            "paid_amount": paid,
            "balance": max(total - paid, 0),
            "status": fee_status(total, paid)
        }
    })

finally:
    connection.close()

==================== STUDENT PAYMENT RECORDING ====================

@app.route("/api/fees/payment", methods=["POST", "OPTIONS"])
def record_student_payment():
if request.method == "OPTIONS":
return "", 204

data = read_json()

student_id = str(data.get("student_id", "")).strip()

try:
    amount = float(data.get("payment_amount", 0))
except (TypeError, ValueError):
    return jsonify({
        "success": False,
        "message": "Enter a valid payment amount."
    }), 400

if not student_id or amount <= 0 or not amount.is_integer():
    return jsonify({
        "success": False,
        "message": "A valid student ID and whole-number amount are required."
    }), 400

connection = get_db()

try:
    student = get_student(connection, student_id)

    if not student:
        return student_not_found()

    year_text = str(
        student["year"] or student["academic_year"] or "1"
    )
    year_match = __import__("re").search(r"\d+", year_text)
    current_year = int(year_match.group()) if year_match else 1
    current_year = min(max(current_year, 1), 4)

    # This existing table stores one aggregate fee record per student.
    # The requested year must match the student's registered year.
    requested_year = int(data.get("payment_year", current_year))

    if requested_year != current_year:
        return jsonify({
            "success": False,
            "message": "Payments can only be recorded for the student's registered academic year."
        }), 400

    row = connection.execute(
        "SELECT * FROM fees WHERE student_id = ?",
        (student_id,)
    ).fetchone()

    if row:
        total = float(row["total_amount"] or 0)
        paid = float(row["paid_amount"] or 0)
    else:
        total = YEARLY_HOSTEL_FEE
        paid = 0

    # Initialize a new fee record for the student's current year.
    if total <= 0:
        total = YEARLY_HOSTEL_FEE

    if amount > total - paid:
        return jsonify({
            "success": False,
            "message": "Payment exceeds the outstanding balance.",
            "balance": max(total - paid, 0)
        }), 400

    # Record a simulated payment for the project presentation.
    # No card details or UPI PINs are accepted or stored here.
    new_paid = paid + amount

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
    """, (student_id, total, new_paid))

    connection.commit()

    return jsonify({
        "success": True,
        "message": "Payment record updated.",
        "student_id": student_id,
        "total_amount": total,
        "paid_amount": new_paid,
        "balance": max(total - new_paid, 0),
        "status": fee_status(total, new_paid),
        "simulated": True
    }), 200

except (ValueError, TypeError):
    return jsonify({
        "success": False,
        "message": "Invalid payment details."
    }), 400

except sqlite3.Error:
    connection.rollback()
    app.logger.exception("Recording student payment failed")
    return jsonify({
        "success": False,
        "message": "Unable to save the payment record."
    }), 500

finally:
    connection.close()

==================== ADMIN FEES ====================

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
                "message": "Check student ID and fee amounts."
            }), 400

        if not get_student(connection, student_id):
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
        }), 200

    records = get_all_fees(connection)

    return jsonify({
        "success": True,
        "count": len(records),
        "fees": records
    })

finally:
    connection.close()
