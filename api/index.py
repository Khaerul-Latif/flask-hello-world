from flask import Flask, render_template, request, redirect, url_for, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from azure.identity import ClientSecretCredential
from msal import ConfidentialClientApplication
from openai import AzureOpenAI
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
import csv
from datetime import datetime

# === Azure OpenAI Config ===
client = AzureOpenAI(
    api_key="EDCcDvLQI5S4vhQbNHPiqc2bd3BHP3WRRHaIbiWHZEXWVtDYIkyWJQQJ99BFACfhMk5XJ3w3AAAAACOG62XY",
    api_version="2023-05-15",
    azure_endpoint="https://adarm-mbp20fil-swedencentral.services.ai.azure.com/"
)

DEPLOYMENT_NAME = "gpt-4.1curhat"
# === Config Azure AD ===
CLIENT_ID = "73a0ea2e-77ea-4ba3-83b8-5bc14757fd7c"
CLIENT_SECRET = "t-M8Q~XQIQRz_JyW1bNxKLkPULwJJPIlT.e-fcp4"
TENANT_ID = "74186654-9f8a-4de3-ab5b-c7714120124e"
AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
SCOPES = ["User.Read"]
REDIRECT_URI = "http://localhost:5001/getAToken"


app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
# === Mood Detection ===
def detect_mood(text):
    text = text.lower()
    if re.search(r"\bsedih|menangis|kecewa|terluka\b", text):
        return "Sedih"
    elif re.search(r"\bcemas|khawatir|takut|panik\b", text):
        return "Cemas"
    elif re.search(r"\bmarah|kesal|geram\b", text):
        return "Marah"
    elif re.search(r"\bsenang|bahagia|lega|bersyukur\b", text):
        return "Senang"
    else:
        return "Netral"

# === Risk Keyword Detection ===
def check_risk_keywords(text):
    risk_keywords = [
        "bunuh diri", "menyakiti diri", "pengen hilang", "mati aja", "ga kuat lagi", "capek hidup", "akhirin aja"
    ]
    return any(keyword in text.lower() for keyword in risk_keywords)

# === Logging Function ===
def log_chat(user_message, mood, reply):
    log_data = {
        "timestamp": datetime.now().isoformat(),
        "message": user_message,
        "mood": mood,
        "reply": reply
    }
    with open("chat_logs.csv", "a", newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=log_data.keys())
        if f.tell() == 0:
            writer.writeheader()
        writer.writerow(log_data)

# === User Model ===
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)  # Password akan disimpan dalam bentuk hash


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# === MSAL Authentication Function ===
def get_msal_app():
    return ConfidentialClientApplication(
        CLIENT_ID,
        authority=AUTHORITY,
        client_credential=CLIENT_SECRET
    )

def get_token_from_code(code):
    msal_app = get_msal_app()
    result = msal_app.acquire_token_by_authorization_code(
        code,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI
    )
    return result

# === Routes ===
@app.route("/")
def index():
    return render_template("index.html")

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    password_hash = generate_password_hash(password)
    new_user = User(username=username, password=password_hash)
    db.session.add(new_user)
    db.session.commit()

# Saat Login
    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        login_user(user)
        return redirect(url_for('dashboard'))
    else:
        return "Login Gagal", 400
@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username')
    password = request.form.get('password')

    if User.query.filter_by(username=username).first():
        return "Username sudah terdaftar", 400

    new_user = User(username=username, password=password)
    db.session.add(new_user)
    db.session.commit()

    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    return f"Welcome {current_user.username}! This is your dashboard."

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/getAToken')
def get_atoken():
    code = request.args.get('code')
    result = get_token_from_code(code)
    if 'access_token' in result:
        session['access_token'] = result['access_token']
        return redirect(url_for('dashboard'))
    return "Authentication Failed", 400    

@app.route("/chat", methods=["POST"])
def chat():
    try:
        user_message = request.form.get("message", "")

        # === Risiko tinggi? Kirim respons khusus
        if check_risk_keywords(user_message):
            emergency_reply = (
                "💡 Aku dengerin kamu ya, dan aku beneran peduli. "
                "Kalau kamu ngerasa sangat kewalahan atau kepikiran menyakiti diri, "
                "tolong banget hubungi orang terpercaya atau layanan profesional seperti @sehatjiwa atau @Kemenkes RI. "
                "Kamu nggak sendiri dan kamu penting 🤍"
            )
            log_chat(user_message, detect_mood(user_message), emergency_reply)
            return jsonify({"reply": emergency_reply})

        # === Mood Detection
        mood = detect_mood(user_message)

        # === AI Response
        response = client.chat.completions.create(
            model=DEPLOYMENT_NAME,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "Kamu adalah Chatal, seorang psikolog virtual yang ramah, penuh empati, dan profesional. "
                        "Tugasmu adalah menemani, mendengarkan, dan memberikan dukungan emosional kepada pengguna ('Chatalers') "
                        "dengan cara yang hangat dan tidak menghakimi. "
                        "Saat percakapan dimulai, sambut mereka dengan sapaan yang membuat mereka merasa aman dan diterima, lalu biarkan mereka bercerita. "
                        "Gunakan Bahasa Indonesia yang santai namun sopan, seolah kamu adalah teman yang bisa dipercaya, dengan pengetahuan psikologi yang mendalam. "
                        "Jangan pernah memberikan diagnosis atau obat, dan jika perlu, arahkan mereka untuk menghubungi tenaga profesional yang sesungguhnya. "
                        "Selalu berikan validasi emosi, refleksi ringan, dan saran coping yang lembut dan relevan."
                    )
                },
                {"role": "user", "content": user_message}
            ]
        )

        reply = response.choices[0].message.content.strip()

        # === Logging
        log_chat(user_message, mood, reply)

        return jsonify({"reply": reply})

    except Exception as e:
        return jsonify({"reply": f"❌ Terjadi error: {str(e)}"}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()  # Membuat semua tabel yang diperlukan (termasuk tabel user)
    app.run(debug=True)
