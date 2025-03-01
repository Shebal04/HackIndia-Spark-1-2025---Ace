import joblib
model = joblib.load("models/random_forest.pkl")

print("Expected Features:", model.feature_names_in_)
