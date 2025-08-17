from flask import Flask, request, jsonify
import os
import dotenv
dotenv.load_dotenv()
import supabase
from flask_cors import CORS
import re
import bcrypt
import logging
import jwt
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

client = supabase.create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_KEY")
)

def is_valid_email(email):
    # Simple regex for email validation
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email) is not None

def is_strong_password(password):
    # At least 8 chars, one uppercase, one lowercase, one number, one special char
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[^\w\s]", password)
    )

@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json()
    username = data.get("username", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    # Input validation
    if not username or not email or not password:
        return jsonify({"error": "All fields are required."}), 400
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email format."}), 400
    if not is_strong_password(password):
        return jsonify({"error": "Password does not meet complexity requirements."}), 400

    # Check if user exists (by username or email)
    try:
        existing = client.table("users").select("id").or_(
            f"username.eq.{username},email.eq.{email}"
        ).execute()
        if existing.data:
            return jsonify({"error": "User already exists."}), 400
    except Exception as e:
        logging.exception("Error checking for existing user")
        return jsonify({"error": "An error occurred. Please try again."}), 400

    # Hash password
    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    # Insert user securely
    try:
        client.table("users").insert({
            "username": username,
            "email": email,
            "password_hash": hashed_pw.decode("utf-8")
        }).execute()
    except Exception as e:
        logging.exception("Error inserting new user")
        return jsonify({"error": "An error occurred. Please try again."}), 400

    return jsonify({"message": "User created"}), 201

JWT_SECRET = os.getenv("JWT_SECRET", "change_this_secret")
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600  # 1 hour

@app.route("/signin", methods=["POST"])
def signin():
    data = request.get_json()
    email = data.get("email", "").strip()
    password = data.get("password", "")

    # Input validation
    if not email or not password:
        return jsonify({"error": "Email and password are required."}), 400
    if not is_valid_email(email):
        return jsonify({"error": "Invalid email format."}), 400

    # Look up user by email
    try:
        result = client.table("users").select("id,username,email,password_hash").eq("email", email).single().execute()
        user = result.data
        if not user:
            return jsonify({"error": "Invalid email or password."}), 401
    except Exception as e:
        logging.exception("Error fetching user for signin")
        return jsonify({"error": "Invalid email or password."}), 401

    # Verify password
    if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        return jsonify({"error": "Invalid email or password."}), 401

    # Generate JWT token
    payload = {
        "user_id": user["id"],
        "email": user["email"],
        "username": user["username"],
        "exp": datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS)
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    return jsonify({
        "token": token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"]
        }
    }), 200

@app.route("/signout", methods=["POST"])
def signout():
    # For JWT, signout is handled on the client by deleting the token.
    # This endpoint is provided for API completeness.
    return jsonify({"message": "Signed out successfully."}), 200

if __name__=="__main__":
    app.run(debug=True)


