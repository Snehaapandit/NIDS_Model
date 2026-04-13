# app.py (Updated with Dashboard Support)
from flask import Flask, request, jsonify, render_template
import joblib
import numpy as np
import datetime

app = Flask(__name__)

# Load Model
model = joblib.load('ids_model.pkl')

# Global Storage for Dashboard Stats
stats = {
    "total_packets": 0,
    "total_threats": 0,
    "last_packet_size": 0,
    "recent_alert": None
}

@app.route('/')
def dashboard():
    # Serve the HTML Dashboard
    return render_template('dashboard.html')

@app.route('/analyze', methods=['POST'])
def analyze_traffic():
    global stats
    try:
        data = request.get_json()
        
        # 1. Extract Features
        features = [
            data['src_port'],
            data['dst_port'],
            data['proto'],
            data['pkt_len']
        ]
        
        # 2. Update Stats
        stats["total_packets"] += 1
        stats["last_packet_size"] = data['pkt_len']

        # 3. Predict
        features_array = np.array(features).reshape(1, -1)
        prediction = model.predict(features_array)[0]
        confidence = model.predict_proba(features_array).max()
        
        result_type = "Normal"
        
        # 4. Handle Threats
        if prediction == 1:
            result_type = "Malicious"
            stats["total_threats"] += 1
            
            # Create Alert Object
            stats["recent_alert"] = {
                "time": datetime.datetime.now().strftime("%H:%M:%S"),
                "type": "Anomaly Detected",
                "src_ip": data.get('src_ip', 'Unknown'),
                "confidence": f"{confidence*100:.2f}%"
            }
            print(f"🚨 ALERT: Malicious Traffic! {stats['recent_alert']}")

        return jsonify({"status": "success", "prediction": result_type})

    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Endpoint for Dashboard JS to fetch updates
@app.route('/get_stats', methods=['GET'])
def get_stats():
    global stats
    # Return stats and clear the recent alert so it doesn't duplicate
    response = stats.copy()
    stats["recent_alert"] = None 
    return jsonify(response)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)