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

os.getenv("SECRET_KEY")
os.getenv("DB_PASSWORD")
os.getenv("JWT_SECRET")

app = Flask(__name__)


UPLOAD_FOLDER = 'stored_faces'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_db_connection():
    return mysql.connector.connect(**db_config)

# =====================================================================
# HTML TEMPLATES (Built directly in Python so you don't need folders)
# =====================================================================

BASE_STYLE = """
<style>
    body { font-family: 'Arial', sans-serif; background: #1a1a2e; color: white; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
    .box { background: #16213e; padding: 40px; border-radius: 10px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); width: 350px; text-align: center; }
    input { width: 90%; padding: 12px; margin: 10px 0; border-radius: 5px; border: none; background: #0f3460; color: white; font-size: 16px; }
    button { width: 100%; padding: 12px; margin-top: 15px; border-radius: 5px; border: none; background: #e94560; color: white; font-size: 16px; font-weight: bold; cursor: pointer; }
    button:hover { background: #ff2a4b; }
    a { color: #e94560; text-decoration: none; font-size: 14px; display: block; margin-top: 15px; }
    video { width: 100%; border-radius: 5px; border: 2px solid #e94560; transform: scaleX(-1); margin-bottom: 15px; }
    .error { color: #ff4d4d; margin-bottom: 10px; font-size: 14px; }
</style>
"""

# 1. LOGIN PAGE (Factor 1)
HTML_LOGIN = BASE_STYLE + """
<div class="box">
    <h2>Client Login</h2>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form action="/" method="POST">
        <input type="text" name="username" placeholder="Username" required>
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Verify Password (Factor 1)</button>
    </form>
    <a href="/register">Create new account</a>
</div>
"""

# 2. REGISTER PAGE
HTML_REGISTER = BASE_STYLE + """
<div class="box">
    <h2>Register Account</h2>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form id="regForm" action="/register" method="POST">
        <input type="text" name="username" placeholder="Choose Username" required>
        <input type="password" name="password" placeholder="Choose Password" required>
        <p style="font-size: 14px;">Master Face Scan:</p>
        <video id="webcam" autoplay playsinline></video>
        <input type="hidden" name="face_photo" id="face_photo">
        <button type="button" onclick="submitForm()">Capture & Register</button>
    </form>
    <a href="/">Back to Login</a>
    <canvas id="canvas" style="display:none;" width="320" height="240"></canvas>
    <script>
        const video = document.getElementById('webcam');
        navigator.mediaDevices.getUserMedia({ video: true }).then(stream => { video.srcObject = stream; });
        function submitForm() {
            const canvas = document.getElementById('canvas');
            canvas.getContext('2d').drawImage(video, 0, 0, 320, 240);
            document.getElementById('face_photo').value = canvas.toDataURL('image/jpeg');
            document.getElementById('regForm').submit();
        }
    </script>
</div>
"""

# 3. 2FA SETUP PAGE (Shows after successful registration)
HTML_SETUP_2FA = BASE_STYLE + """
<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
<div class="box">
    <h2>Registration Success!</h2>
    <p style="font-size: 14px;">Scan with Google Authenticator:</p>
    <div id="qrcode" style="display:flex; justify-content:center; margin: 15px 0; padding:10px; background:white;"></div>
    <p style="font-size: 12px;">Or use secret key: <br><strong style="color:#e94560; font-size:16px;">{{ secret }}</strong></p>
    <a href="/"><button type="button">Go to Login</button></a>
    <script>
        new QRCode(document.getElementById("qrcode"), { text: "{{ uri }}", width: 130, height: 130 });
    </script>
</div>
"""

# 4. FACTOR 2 PAGE (OTP)
HTML_FACTOR2 = BASE_STYLE + """
<div class="box">
    <h2>Factor 2</h2>
    <p>Enter your 6-digit App Code:</p>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form action="/factor2" method="POST">
        <input type="text" name="otp_code" placeholder="000000" maxlength="6" required>
        <button type="submit">Verify Token</button>
    </form>
</div>
"""

# 5. FACTOR 3 PAGE (Face Scan)
HTML_FACTOR3 = BASE_STYLE + """
<div class="box">
    <h2>Factor 3 (Biometrics)</h2>
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form id="faceForm" action="/factor3" method="POST">
        <video id="webcam" autoplay playsinline></video>
        <input type="hidden" name="face_photo" id="face_photo">
        <button type="button" onclick="submitForm()">Scan Face & Enter</button>
    </form>
    <canvas id="canvas" style="display:none;" width="320" height="240"></canvas>
    <script>
        const video = document.getElementById('webcam');
        navigator.mediaDevices.getUserMedia({ video: true }).then(stream => { video.srcObject = stream; });
        function submitForm() {
            const canvas = document.getElementById('canvas');
            canvas.getContext('2d').drawImage(video, 0, 0, 320, 240);
            document.getElementById('face_photo').value = canvas.toDataURL('image/jpeg');
            document.getElementById('faceForm').submit();
        }
    </script>
</div>
"""

# 6. DASHBOARD (Success)
HTML_DASHBOARD = BASE_STYLE + """
<div class="box" style="width: 500px; background: #0f3460;">
    <h1 style="color: #4caf50;">Access Granted</h1>
    <h2>Welcome to the Social Network, @{{ username }}!</h2>
    <p>You have successfully passed 3 levels of authentication.</p>
    <a href="/logout"><button type="button" style="background:#333;">Secure Logout</button></a>
</div>
"""

# =====================================================================
# FLASK ROUTING LOGIC
# =====================================================================

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