import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from imblearn.over_sampling import SMOTE

df = pd.read_csv("data/IDS_dataset.csv")

X = df.drop(columns=["Label"])
y = df["Label"].astype('category').cat.codes  
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

smote = SMOTE(sampling_strategy="auto", random_state=42)
X_train, y_train = smote.fit_resample(X_train, y_train)
clf = RandomForestClassifier(n_estimators=200, max_depth=20, min_samples_split=5, class_weight="balanced", random_state=42)
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy:.4f}")
print(classification_report(y_test, y_pred))
importances = clf.feature_importances_
feature_names = X_train.columns
sorted_features = sorted(zip(feature_names, importances), key=lambda x: x[1], reverse=True)
print("Top Important Features:", sorted_features[:10])
joblib.dump(clf, "models/random_forest.pkl")
print("Model saved successfully!")