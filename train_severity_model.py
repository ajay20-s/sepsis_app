import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split

# Load modified dataset
df = pd.read_csv("sepsis_with_severity.csv")

# Features and label
X = df[['age_years', 'sex_0male_1female', 'episode_number']]
y = df['severity']

# Encode severity labels
label_encoder = LabelEncoder()
y_encoded = label_encoder.fit_transform(y)  # Low=1, Medium=2, High=0 or similar

# Train model
X_train, X_test, y_train, y_test = train_test_split(X, y_encoded, test_size=0.2, random_state=42)
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Save model and encoder
pickle.dump(model, open("severity_model.pkl", "wb"))
pickle.dump(label_encoder, open("severity_label_encoder.pkl", "wb"))

print("✅ Severity model and encoder saved.")
