#  Network Intrusion Detection System (IDS)

A real-time **Network Intrusion Detection System (IDS)** built using **Flask, Machine Learning, and Packet Sniffing techniques**.

This project captures live network packets, extracts important features, and predicts whether the traffic is **normal or malicious**.

##  Project Overview

The system monitors incoming traffic packets using **Scapy**, sends them to a Flask server, and uses a trained machine learning model to detect threats.

It also includes an **attack simulator** for testing malicious traffic behavior.

##  Features

* Real-time packet sniffing
* ML-based threat detection
* Flask dashboard
* Attack simulation
* Live traffic monitoring
* Threat alerts and statistics
* Malicious packet detection

## 🛠️ Tech Stack

* Python
* Flask
* Scikit-learn
* NumPy
* Joblib
* Scapy

##  Project Structure

```bash
projexa26E4189-main/
│── app.py
│── sniffer_agent.py
│── attack_simulator.py
│── train_model.py
│── ids_model.pkl
│── requirements.txt
```

##  Workflow

1. Train model using synthetic traffic data
2. Run Flask server
3. Start packet sniffer agent
4. Simulate malicious traffic
5. Detect threats in dashboard

##  How to Run

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Start Flask Server

```bash
python app.py
```

### Run Packet Sniffer

```bash
python sniffer_agent.py
```

### Simulate Attack Traffic

```bash
python attack_simulator.py
```

##  Use Cases

* Network security analysis
* Intrusion detection research
* Cybersecurity final year project
* Real-time threat monitoring

##  Future Scope

* Real-time alert notifications
* Advanced anomaly detection
* Dashboard analytics
* Deep learning model integration

##  Author

Developed as a cybersecurity and machine learning based intrusion detection project.

