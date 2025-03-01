import pandas as pd
import joblib
import sys

model_path = "models/random_forest.pkl"
clf = joblib.load(model_path)


input_data_path = sys.argv[1] 
new_data = pd.read_csv(input_data_path)


X_new = new_data.drop(columns=["Label"], errors='ignore')  

predictions = clf.predict(X_new)
label_mapping = {0: "Normal", 1: "DoS", 2: "Probe", 3: "U2R", 4: "R2L"} 
predicted_labels = [label_mapping[pred] for pred in predictions]


new_data["Predicted_Label"] = predicted_labels
output_path = "data/predictions.csv"
new_data.to_csv(output_path, index=False)
print(f"Predictions saved to {output_path}")
