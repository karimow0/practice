from flask import Flask, request, render_template_string, redirect, url_for, session
from deepface import DeepFace
import mysql.connector
import bcrypt
import pyotp
import base64
import numpy as np
import cv2
import os
import jwt 
import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")
JWT_SECRET = os.getenv("JWT_SECRET_KEY")


UPLOAD_FOLDER = 'stored_faces'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_db_connection():
    return mysql.connector.connect(**{
        'host': os.getenv("DB_HOST"),
        'user': os.getenv("DB_USER"),
        'password': os.getenv("DB_PASSWORD"),
        'database': os.getenv("DB_NAME")
    })


@app.route('/', methods=['GET', 'POST'])
def login_factor1():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT password_hash FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password_hash'].encode('utf-8')):
            session['login_user'] = username
            return redirect(url_for('login_factor2'))
        return render_template_string(HTML_LOGIN, error="Invalid credentials")
    
    return render_template_string(HTML_LOGIN)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        face_photo = request.form.get('face_photo')

        if not username or not password or not face_photo:
            return render_template_string(HTML_REGISTER, error="All fields required.")

        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
        if cursor.fetchone():
            return render_template_string(HTML_REGISTER, error="Username taken.")

        # Save Image
        image_bytes = base64.b64decode(face_photo.split(",")[1])
        nparr = np.frombuffer(image_bytes, np.uint8)
        frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        image_path = os.path.join(UPLOAD_FOLDER, f"{username}_master.png")
        cv2.imwrite(image_path, frame)

        # Hash Pass & Generate Token
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        mfa_secret = pyotp.random_base32()

        cursor.execute(
            "INSERT INTO users (username, password_hash, mfa_secret, face_img_path) VALUES (%s, %s, %s, %s)",
            (username, hashed_password, mfa_secret, image_path)
        )
        conn.commit()
        cursor.close()
        conn.close()

        totp_uri = f"otpauth://totp/SystemSecurity:{username}?secret={mfa_secret}&issuer=SystemSecurity"
        session['new_uri'] = totp_uri
        session['new_secret'] = mfa_secret
        return redirect(url_for('setup_2fa'))

    return render_template_string(HTML_REGISTER)

@app.route('/setup_2fa')
def setup_2fa():
    uri = session.get('new_uri')
    secret = session.get('new_secret')
    if not uri: return redirect(url_for('login_factor1'))
    return render_template_string(HTML_SETUP_2FA, uri=uri, secret=secret)

@app.route('/factor2', methods=['GET', 'POST'])
def login_factor2():
    username = session.get('login_user')
    if not username: return redirect(url_for('login_factor1'))

    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT mfa_secret FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user and pyotp.TOTP(user['mfa_secret']).verify(otp_code):
            session['passed_factor2'] = True
            return redirect(url_for('login_factor3'))
        return render_template_string(HTML_FACTOR2, error="Invalid Phone Code")

    return render_template_string(HTML_FACTOR2)

@app.route('/factor3', methods=['GET', 'POST'])
def login_factor3():
    username = session.get('login_user')
    if not username or not session.get('passed_factor2'): 
        return redirect(url_for('login_factor1'))

    if request.method == 'POST':
        face_photo = request.form.get('face_photo')
        
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT face_img_path FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        # Save live image to compare
        image_bytes = base64.b64decode(face_photo.split(",")[1])
        nparr = np.frombuffer(image_bytes, np.uint8)
        live_frame = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
        temp_path = f"temp_{username}.png"
        cv2.imwrite(temp_path, live_frame)

        try:
            match = DeepFace.verify(img1_path=user['face_img_path'], img2_path=temp_path, enforce_detection=False, model_name="VGG-Face")
            if match.get("verified"):
                token = jwt.encode(
                    {
                        "username": username, 
                        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
                    },
                    JWT_SECRET, 
                    algorithm="HS256"
                )
                session['jwt_token'] = token
                return redirect(url_for('dashboard'))
        finally:
            if os.path.exists(temp_path): os.remove(temp_path)

        return render_template_string(HTML_FACTOR3, error="Face does not match database!")

    return render_template_string(HTML_FACTOR3)

@app.route('/dashboard')
def dashboard():
    token = session.get('jwt_token')

    if not token:
        return redirect(url_for('login_factor1'))

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"]
        )

        username = payload["username"]

    except jwt.ExpiredSignatureError:
        return redirect(url_for('login_factor1'))

    except jwt.InvalidTokenError:
        return redirect(url_for('login_factor1'))

    return render_template_string(
        HTML_DASHBOARD,
        username=username
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_factor1'))

if __name__ == '__main__':
    # RELOADER IS FALSE. It will not restart on you.
    app.run(debug=True, use_reloader=False, port=5000)