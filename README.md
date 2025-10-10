# Real-Time Network Anomaly Detection Dashboard

A real-time network monitoring and anomaly detection system built using **Nmap**, **Isolation Forest**, and **Streamlit**.  
The application scans a target subnet, tracks open ports and services, detects behavioral changes, and flags anomalies.

---

## Features

- Real-time network scanning using **Nmap**
- Host-level feature extraction (open ports, services)
- Anomaly detection using **Isolation Forest**
- Historical trend analysis
- Interactive **Streamlit dashboard**
- Persistent scan history and state tracking

---

## System Architecture

1. **Nmap Scan** to Detect hosts, ports, and services  
2. **Feature Engineering** to Host-level metrics  
3. **State Comparison** to Detect changes across scans  
4. **Isolation Forest** to Flag anomalies  
5. **Streamlit UI** to Visualize & alerts  

---

## Dashboard Preview

### Home Dashboard
![Dashboard Home](assets/dashboard_home.png)

### Latest Scan Summary
![Latest Scan](assets/latest_scan.png)

### Anomaly Alerts
![Anomaly Alerts](assets/anomaly_count_over_time.png)

### Trend Analysis
![Trend Analysis](assets/anomaly_alerts_trends_analysis.png)

---

## How to Run Locally

### Prerequisites
- Python 3.9+
- Nmap installed and added to PATH

### Install dependencies
```bash
pip install streamlit pandas numpy scikit-learn
