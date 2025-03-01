import scapy.all as scapy
import pandas as pd
import joblib
import time
from datetime import datetime

model_path = "models/random_forest.pkl"
clf = joblib.load(model_path)
def extract_features(packet):
    features = {
        "Duration": time.time() % 100, 
        "Protocol Type": packet.proto if hasattr(packet, 'proto') else 0,
        "Service": 0,
        "Flag": 0,  
        "Src Bytes": len(packet.original) if hasattr(packet, 'original') else 0,
        "Dst Bytes": len(packet.payload) if hasattr(packet, 'payload') else 0,
        "Land": 0,  
        "Wrong Fragment": 0, 
        "Urgent": 0,
        "Hot Count": 0,  
        "Num Failed Logins": 0,  
        "Num Compromised": 0,  
        "Num Root": 0, 
        "Num File Creations": 0,  
        "Num Shells": 0,  
        "Flow Duration": time.time() % 200, 
        "Flow Bytes/s": len(packet.original) if hasattr(packet, 'original') else 0,
        "Flow Packets/s": 1, 
        "Flow IAT Mean": 0, 
        "Flow IAT Std": 0,  
        "Bwd Packets/s": 0,  
        "Bwd Bytes/s": 0,  
        "Fwd IAT Mean": 0,  
        "Bwd IAT Mean": 0,  
        "Packet Length Mean": len(packet.original) if hasattr(packet, 'original') else 0,
        "Packet Length Std": 0, 
        "Connection Count": 1, 
        "Packets per Second": 1, 
        "Bytes per Second": len(packet.original) if hasattr(packet, 'original') else 0,
    }

    df = pd.DataFrame([features])

    expected_features = [
        "Duration", "Protocol Type", "Service", "Flag", "Src Bytes", "Dst Bytes",
        "Land", "Wrong Fragment", "Urgent", "Hot Count", "Num Failed Logins",
        "Num Compromised", "Num Root", "Num File Creations", "Num Shells",
        "Flow Duration", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
        "Flow IAT Std", "Bwd Packets/s", "Bwd Bytes/s", "Fwd IAT Mean",
        "Bwd IAT Mean", "Packet Length Mean", "Packet Length Std",
        "Connection Count", "Packets per Second", "Bytes per Second"
    ]

    df = df.reindex(columns=expected_features, fill_value=0)
    
    return df

def process_packet(packet):
    print("Packet Captured:", packet.summary()) 

    features_df = extract_features(packet)
    print("Extracted Features:", features_df)
    try:
        prediction = clf.predict(features_df)[0]
        label_mapping = {0: "Normal", 1: "DoS", 2: "Probe", 3: "U2R", 4: "R2L"}
        detected_label = label_mapping.get(prediction, "Unknown")
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Traffic Detected: {detected_label}")

        with open("logs/real_time_log.txt", "a") as log_file:
            log_file.write(f"{timestamp} - {detected_label}\n")
    except Exception as e:
        print("Prediction Error:", e)

print("Starting real-time IDS monitoring... Listening for packets...")

scapy.sniff(iface="Wi-Fi", prn=process_packet, store=False)
