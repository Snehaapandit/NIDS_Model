# train_model.py
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib

# 1. SIMULATE DATASET (Replace this block with pd.read_csv('UNSW_NB15.csv') for final project)
# We use features that are EASY to capture in real-time using Python/Scapy
print("Generating synthetic dataset for training...")
data_size = 5000

# Normal Traffic: Web browsing, HTTP, HTTPS (Ports 80, 443, larger packets)
normal_traffic = pd.DataFrame({
    'src_port': np.random.randint(1024, 65535, data_size // 2),
    'dst_port': np.random.choice([80, 443, 53, 8080], data_size // 2),
    'proto': np.random.choice([6, 17], data_size // 2), # 6=TCP, 17=UDP
    'pkt_len': np.random.normal(500, 100, data_size // 2), # Normal packets are medium/large
    'label': 0 # 0 = Normal
})

# Attack Traffic: Port scanning, Mirai (Ports 23, 22, tiny packets, weird ports)
attack_traffic = pd.DataFrame({
    'src_port': np.random.randint(1024, 65535, data_size // 2),
    'dst_port': np.random.choice([22, 23, 4444, 6667], data_size // 2), # 22/23 = Telnet/SSH brute force
    'proto': np.random.choice([6, 17], data_size // 2),
    'pkt_len': np.random.normal(50, 10, data_size // 2), # Attack packets often small (scanning)
    'label': 1 # 1 = Malicious
})

# Combine
df = pd.concat([normal_traffic, attack_traffic]).sample(frac=1).reset_index(drop=True)

# 2. PREPROCESSING
X = df[['src_port', 'dst_port', 'proto', 'pkt_len']]
y = df['label']

# Split into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# 3. TRAIN MODEL (Random Forest)
print("Training Random Forest Model...")
rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
rf_model.fit(X_train, y_train)

# 4. EVALUATE
y_pred = rf_model.predict(X_test)
print("\n--- Model Performance ---")
print(f"Accuracy: {accuracy_score(y_test, y_pred) * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# 5. SAVE THE MODEL
# We save the 'brain' to a file so the API can load it later
joblib.dump(rf_model, 'ids_model.pkl')
print("\nModel saved as 'ids_model.pkl'. Ready for API deployment!")