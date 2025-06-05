import pandas as pd

# Load your CSV file
df = pd.read_csv("s41598-020-73558-3_sepsis_survival_study_cohort.csv")

# Define severity based on episode_number
def determine_severity(ep):
    if ep >= 4:
        return "High"
    elif ep >= 3:
        return "Medium"
    else:
        return "Low"

df["severity"] = df["episode_number"].apply(determine_severity)

# Save to a new CSV
df.to_csv("sepsis_with_severity.csv", index=False)
print("✅ Saved sepsis_with_severity.csv with severity labels")
