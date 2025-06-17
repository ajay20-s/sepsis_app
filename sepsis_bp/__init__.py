from flask import Blueprint, render_template, request
import joblib
import numpy as np
from flask_login import login_required, current_user

sepsis_bp = Blueprint("sepsis_bp", __name__, template_folder="../templates")

model = joblib.load("sepsis_model/sepsis_model.pkl")

FEATURES = [
    "temperature", "heart_rate", "resp_rate",
    "systolic_bp", "diastolic_bp", "wbc",
    "platelets", "lactate", "creatinine",
    "bilirubin", "spo2"
]

@sepsis_bp.route("/sepsis", methods=["GET", "POST"])
@login_required
def sepsis_form():
    if request.method == "POST":
        try:
            values = [float(request.form[f]) for f in FEATURES]
            X = np.array(values).reshape(1, -1)
            prediction = model.predict(X)[0]
            probability = model.predict_proba(X)[0][1]

            return render_template("sepsis_result.html", prediction=prediction, probability=probability)
        except Exception as e:
            return render_template("sepsis_form.html", error=str(e))

    return render_template("sepsis_form.html", error=None)
