import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from imblearn.over_sampling import RandomOverSampler
from imblearn.pipeline import Pipeline
import pickle

# Load data
df = pd.read_csv("s41598-020-73558-3_sepsis_survival_study_cohort.csv")
X = df[['age_years', 'sex_0male_1female', 'episode_number']]
y = df['hospital_outcome_1alive_0dead']

# Build and train model with oversampling
oversample = RandomOverSampler(random_state=42)
model = Pipeline([
    ('oversample', oversample),
    ('classifier', LogisticRegression())
])

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
model.fit(X_train, y_train)

# Save the model
with open("sepsis_model.pkl", "wb") as f:
    pickle.dump(model, f)

# Optional: Print class balance before and after
print("Original class distribution:\n", y.value_counts())
X_bal, y_bal = oversample.fit_resample(X, y)
print("Balanced class distribution:\n", pd.Series(y_bal).value_counts())
