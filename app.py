from flask import (
    Flask, render_template, redirect, url_for,
    request, flash, session, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, UserMixin, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import joblib, numpy as np, pandas as pd, os, json


# ─── Flask & DB setup ──────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "replace_me_with_a_secure_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["UPLOAD_FOLDER"] = "uploads"
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ─── MODELS ────────────────────────────────────────────────────────────────
class User(UserMixin, db.Model):
    id       = db.Column(db.Integer, primary_key=True)
    email    = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    
    uploads          = db.relationship("Upload",             backref="user", lazy=True)
    sepsis_preds     = db.relationship("SepsisPrediction",    backref="user", lazy=True)
    survival_preds   = db.relationship("SurvivalPrediction", backref="user", lazy=True)

class Upload(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    filename    = db.Column(db.String(300), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

class SepsisPrediction(db.Model):
    id            = db.Column(db.Integer, primary_key=True)
    probability   = db.Column(db.Float)
    is_sepsis     = db.Column(db.Boolean)
    input_json    = db.Column(db.JSON)
    created_at    = db.Column(db.DateTime, default=datetime.utcnow)
    user_id       = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

class SurvivalPrediction(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    result      = db.Column(db.String(10))  # "Alive"/"Dead"
    input_json  = db.Column(db.JSON)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    user_id     = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# ─── Load ML models ────────────────────────────────────────────────────────
survival_model        = joblib.load("sepsis_model.pkl")            # 3‑feature model
severity_model        = joblib.load("severity_model.pkl")
severity_label_encoder = joblib.load("severity_label_encoder.pkl")

risk_model           = joblib.load("sepsis_risk_model.pkl")          # 11‑feature model
RISK_FEATURES = [
    "temperature", "heart_rate", "resp_rate",
    "systolic_bp", "diastolic_bp", "wbc",
    "platelets", "lactate", "creatinine",
    "bilirubin", "spo2"
]

# ─── ROUTES ────────────────────────────────────────────────────────────────
@app.route("/")
def splash():
    return render_template("splash.html")

# ---------- AUTH ----------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "warning")
            return redirect(url_for("signup"))
        new_user = User(email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash("Signup successful! Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email, pwd = request.form["email"], request.form["password"]
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, pwd):
            login_user(user)
            return redirect(url_for("home"))
        flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

# ---------- DASHBOARD ----------
@app.route("/home")
@login_required
def home():
    # show a flash result from vitals page if any
    sepsis_prediction = session.pop("sepsis_prediction", None)
    sepsis_prob       = session.pop("sepsis_prob", None)

    # last 5 uploads
    recent_uploads = Upload.query.filter_by(user_id=current_user.id)\
                                 .order_by(Upload.uploaded_at.desc())\
                                 .limit(5).all()

    # last 5 sepsis predictions
    recent_preds = SepsisPrediction.query.filter_by(user_id=current_user.id)\
                                         .order_by(SepsisPrediction.created_at.desc())\
                                         .limit(5).all()

    return render_template(
        "index.html",
        sepsis_prediction=sepsis_prediction,
        sepsis_prob=sepsis_prob,
        recent_uploads=recent_uploads,
        recent_preds=recent_preds
    )

@app.route("/idea")
@login_required
def idea():
    return render_template("idea.html")

# ---------- AGE‑BASED SURVIVAL ----------
@app.route("/predict", methods=["POST"])
@login_required
def predict():
      # -------- 1. read form fields --------
    age     = int(request.form["age"])
    gender  = int(request.form["gender"])
    episode = int(request.form["episode_number"])

    df = pd.DataFrame([[age, gender, episode]],
                      columns=["age_years", "sex_0male_1female", "episode_number"])

    # -------- 2. make predictions --------
    alive_flag = survival_model.predict(df)[0]   # 0 / 1
    result_txt = "Alive" if alive_flag == 1 else "Dead"

    severity_code = severity_model.predict(df)[0]
    severity_txt  = severity_label_encoder.inverse_transform([severity_code])[0]

    # -------- 3. store to DB --------------
    record = SurvivalPrediction(
        result=result_txt,
        input_json={"age": age, "gender": gender, "episode": episode},
        user_id=current_user.id,             # link to the logged‑in user
        created_at=datetime.utcnow()         # optional, default already set
    )
    db.session.add(record)
    db.session.commit()

    # -------- 4. show the result page -----
    return render_template("result.html",
                           prediction=result_txt,
                           severity=severity_txt)
# ---------- VITALS‑BASED RISK ----------
@app.route("/sepsis", methods=["GET", "POST"])
@login_required
def sepsis_risk():
    if request.method == "POST":
        try:
            # 1. Collect form inputs in the SAME order as RISK_FEATURES
            values = [float(request.form[f]) for f in RISK_FEATURES]
            X = np.array(values).reshape(1, -1)

            # 2. Predict
            pred = risk_model.predict(X)[0]          # 0 / 1
            prob = risk_model.predict_proba(X)[0][1] # probability of class 1

            # 3. Store to DB
            record = SepsisPrediction(
                probability=float(prob),
                is_sepsis=bool(pred),
                input_json=dict(zip(RISK_FEATURES, values)),
                user_id=current_user.id
            )
            db.session.add(record)
            db.session.commit()

            return render_template("sepsis_result.html",
                                   prediction=pred, probability=prob)

        except Exception as e:
            flash(str(e), "danger")
    return render_template("sepsis_form.html")

# ---------- PDF UPLOAD ----------
@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload_pdf():
    if request.method == "POST":
        file = request.files.get("pdf_file")
        if not (file and file.filename.lower().endswith(".pdf")):
            flash("Please choose a PDF file.", "danger")
            return redirect(url_for("upload_pdf"))

        filename = secure_filename(f"{current_user.id}_{datetime.utcnow().timestamp()}_{file.filename}")
        path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(path)

        db.session.add(Upload(filename=filename, user_id=current_user.id))
        db.session.commit()

        flash("PDF uploaded.", "success")
        return redirect(url_for("upload_pdf"))

    return render_template("upload_pdf.html")

@app.route("/records")
@login_required
def view_pdfs():
    records = Upload.query.filter_by(user_id=current_user.id).all()
    return render_template("view_pdfs.html", records=records)

@app.route("/uploads/<filename>")
@login_required
def serve_pdf(filename):
    # ensure this user owns the file
    Upload.query.filter_by(filename=filename, user_id=current_user.id).first_or_404()
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


@app.route("/prediction_history")
@login_required
def prediction_history():
    raw_history = (SurvivalPrediction
                   .query.filter_by(user_id=current_user.id)
                   .order_by(SurvivalPrediction.created_at.desc())
                   .all())

    history = []
    for row in raw_history:
        data = json.loads(row.input_json) if isinstance(row.input_json, str) else row.input_json
        history.append({
            "created_at": row.created_at,
            "age": data["age"],
            "gender": data["gender"],
            "episode": data["episode"],
            "result": row.result
        })

    return render_template("prediction_history.html", history=history)


@app.route("/sepsis_history")
@login_required
def sepsis_history():
    rows = (SepsisPrediction
            .query.filter_by(user_id=current_user.id)
            .order_by(SepsisPrediction.created_at.desc())
            .all())
    return render_template("sepsis_history.html", rows=rows)


# ─── main ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
