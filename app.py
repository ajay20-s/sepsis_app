from flask import Flask, render_template, redirect, url_for, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import pickle
import pandas as pd
import os
from flask_login import current_user

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Change this
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.login_view = "login"
login_manager.init_app(app)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Load the model
model = pickle.load(open("sepsis_model.pkl", "rb"))
severity_model = pickle.load(open("severity_model.pkl", "rb"))
severity_label_encoder = pickle.load(open("severity_label_encoder.pkl", "rb"))

@app.route('/')
def splash():
    return render_template("splash.html")
@app.route('/predict', methods=["POST"])
@login_required
def predict():
    age = int(request.form['age'])
    gender = int(request.form['gender'])
    episode = int(request.form['episode_number'])

    data = pd.DataFrame([[age, gender, episode]], columns=["age_years", "sex_0male_1female", "episode_number"])

    # Predict survival
    prediction = model.predict(data)[0]
    result = "Alive" if prediction == 1 else "Dead"

    # Predict severity
    severity_pred = severity_model.predict(data)[0]
    severity_label = severity_label_encoder.inverse_transform([severity_pred])[0]

    return render_template("result.html", prediction=result, severity=severity_label)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        user = User.query.filter_by(email=email).first()

        if user:
            print(f"[DEBUG] Found user: {user.email}")
            if check_password_hash(user.password, password):
                login_user(user)
                print(f"[DEBUG] Logged in as: {user.email}")
                print(f"[DEBUG] Authenticated: {current_user.is_authenticated}")
                return redirect(url_for("home"))
            else:
                print("[DEBUG] Password mismatch")
        else:
            print("[DEBUG] User not found")

        flash("Invalid credentials", "danger")

    return render_template("login.html")


@app.route('/signup', methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = request.form["email"]
        password = generate_password_hash(request.form["password"], method='pbkdf2:sha256')

        if User.query.filter_by(email=email).first():
            flash("Email already exists", "warning")
            return redirect(url_for("home"))
        else:
            new_user = User(email=email, password=password)
            db.session.add(new_user)
            db.session.commit()
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for("home"))
    return render_template("signup.html")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))

@app.route('/home')
@login_required
def home():
    return render_template("index.html")

@app.route('/idea')
@login_required
def idea():
    return render_template("idea.html")


if __name__ == '__main__':
    if not os.path.exists("users.db"):
        with app.app_context():
            db.create_all()
    app.run(debug=True)
