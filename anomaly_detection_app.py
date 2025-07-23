# -*- coding: utf-8 -*-

# Importing required libraries
import time
import os
import json
import pandas as pd
import numpy as np
import streamlit as st

# Importing sklearn utilities for modelling
from sklearn.ensemble import IsolationForest


# Defining Streamlit page settings

st.set_page_config(
    page_title="Real-Time Network Anomaly Detection",
    layout="wide"
)



# Defining configuration settings

DEFAULT_SUBNET = "192.168.1.0/24"
DEFAULT_SCAN_INTERVAL = 60

HISTORY_FILE = "scan_history.csv"      # Storing scan history
STATE_FILE = "previous_state.json"     # Storing last scan state



# Defining scan and parsing helpers

def running_nmap_scan(target: str) -> dict:
    """
    Running nmap scan using OS command
    """

    # Creating command for scanning ports and services
    command = f"nmap -sT -sV --open -T4 {target}"

    # Executing scan and capturing output
    output = os.popen(command).read()

    # Returning raw output for parsing
    return {"raw": output}


def extracting_hosts_ports(raw_output: str) -> list:
    """
    Extracting host and open port details from nmap
    """

    # Initialising results container
    results = []

    # Splitting output into lines for processing
    lines = raw_output.splitlines()

    # Tracking current host while parsing
    current_host = None

    for line in lines:
        line = line.strip()

        # Detecting host line
        if line.startswith("Nmap scan report for"):
            # Extracting host identifier
            current_host = line.replace("Nmap scan report for", "").strip()

        # Detecting open port line
        if "/tcp" in line and "open" in line:
            # Splitting port/service fields
            parts = line.split()

            # Extracting port information
            port_proto = parts[0]
            state = parts[1]
            service = parts[2] if len(parts) > 2 else "unknown"

            # Appending extracted record
            results.append({
                "host": current_host,
                "port_proto": port_proto,
                "state": state,
                "service": service
            })

    return results


def building_feature_table(scan_records: list) -> pd.DataFrame:
    """
    Converting scan records into a host-level feature table
    """

    # Creating dataframe from scan records
    df = pd.DataFrame(scan_records)

    # Handling empty scan case
    if df.empty:
        return pd.DataFrame(columns=["host", "open_ports_count", "unique_services_count"])

    # Grouping by host and aggregating features
    features = df.groupby("host").agg(
        open_ports_count=("port_proto", "count"),
        unique_services_count=("service", "nunique")
    ).reset_index()

    return features


def loading_previous_state() -> dict:
    """
    Loading previous scan state from JSON file
    """
    if not os.path.exists(STATE_FILE):
        return {}

    with open(STATE_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def saving_current_state(state: dict) -> None:
    """
    Saving current scan state into JSON file
    """
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def generating_state_from_records(scan_records: list) -> dict:
    """
    Converting scan records into state dictionary
    """

    # Initialising state storage
    state = {}

    for r in scan_records:
        host = r["host"]
        port = r["port_proto"]

        # Creating list if host not present
        if host not in state:
            state[host] = []

        # Appending port into host state
        state[host].append(port)

    return state


def detecting_changes(previous_state: dict, current_state: dict) -> pd.DataFrame:
    """
    Comparing previous and current state for returning change summary per host
    """

    # Collecting all hosts seen in either scan
    all_hosts = sorted(set(previous_state.keys()).union(set(current_state.keys())))

    change_rows = []

    for host in all_hosts:
        prev_ports = set(previous_state.get(host, []))
        curr_ports = set(current_state.get(host, []))

        # Calculating added and removed ports
        added_ports = list(curr_ports - prev_ports)
        removed_ports = list(prev_ports - curr_ports)

        # Creating change summary
        change_rows.append({
            "host": host,
            "new_ports_count": len(added_ports),
            "closed_ports_count": len(removed_ports),
            "added_ports": ",".join(added_ports),
            "removed_ports": ",".join(removed_ports),
            "host_newly_seen": int(host not in previous_state),
            "host_disappeared": int(host not in current_state)
        })

    return pd.DataFrame(change_rows)


def scoring_anomalies(history_df: pd.DataFrame, feature_cols: list) -> pd.DataFrame:
    """
    Training IsolationForest on historical scans and returning anomaly score
    """

    # Handling insufficient data for modelling
    if history_df.shape[0] < 10:
        history_df["anomaly_flag"] = 0
        history_df["anomaly_score"] = 0.0
        return history_df

    # Extracting features for training
    X = history_df[feature_cols].fillna(0)

    # Training Isolation Forest model
    model = IsolationForest(random_state=42, contamination="auto")
    model.fit(X)

    # Predicting anomaly flags (-1 = anomaly)
    preds = model.predict(X)

    # Calculating anomaly scores
    scores = model.decision_function(X)

    # Adding results into dataframe
    history_df["anomaly_flag"] = (preds == -1).astype(int)
    history_df["anomaly_score"] = scores

    return history_df


def saving_history(history_df: pd.DataFrame) -> None:
    """
    Saving scan history into CSV file
    """
    history_df.to_csv(HISTORY_FILE, index=False)


def loading_history() -> pd.DataFrame:
    """
    Loading scan history from CSV file
    """
    if not os.path.exists(HISTORY_FILE):
        return pd.DataFrame()

    return pd.read_csv(HISTORY_FILE)


def running_single_scan(target_subnet: str) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Running scanning cycle
    """

    # Loading previous scan state
    previous_state = loading_previous_state()

    # Running scan
    scan_output = running_nmap_scan(target_subnet)

    # Extracting scan records
    scan_records = extracting_hosts_ports(scan_output["raw"])

    # Building current state
    current_state = generating_state_from_records(scan_records)

    # Detecting changes
    changes_df = detecting_changes(previous_state, current_state)

    # Building feature table
    features_df = building_feature_table(scan_records)

    # keeping host by enforcing required columns before merging
    if features_df.empty:
    	features_df = pd.DataFrame(columns=["host", "open_ports_count", "unique_services_count"])

    if changes_df.empty:
    changes_df = pd.DataFrame(columns=[
        "host", "new_ports_count", "closed_ports_count",
        "added_ports", "removed_ports",
        "host_newly_seen", "host_disappeared"
    ])

    # Merging features and change metrics
    merged = pd.merge(features_df, changes_df, on="host", how="outer").fillna(0)


    # Adding timestamp
    merged["timestamp"] = pd.Timestamp.now()

    # Loading old history and appending new scan results
    old_history = loading_history()
    if old_history.empty:
        history = merged.copy()
    else:
        history = pd.concat([old_history, merged], ignore_index=True)

    # Defining feature columns for anomaly scoring
    model_features = [
        "open_ports_count",
        "unique_services_count",
        "new_ports_count",
        "closed_ports_count",
        "host_newly_seen",
        "host_disappeared"
    ]

    # Scoring anomalies
    history = scoring_anomalies(history, model_features)

    # Saving updated history
    saving_history(history)

    # Saving current scan as previous for next run
    saving_current_state(current_state)

    # Extracting latest scan slice
    latest = history.tail(len(merged))

    # Filtering alerts
    alerts = latest[latest["anomaly_flag"] == 1].copy()

    return merged, history, alerts


# Building Streamlit UI

st.title("Real-Time Network Anomaly Detection Dashboard")
st.write("This tool continuously scans your network using Nmap and flags anomalies using Isolation Forest.")

# Creating sidebar controls
st.sidebar.header("Scan Controls")

target_subnet = st.sidebar.text_input("Target Subnet", value=DEFAULT_SUBNET)
scan_interval = st.sidebar.number_input("Auto Refresh Interval (seconds)", min_value=10, max_value=600, value=DEFAULT_SCAN_INTERVAL)

auto_refresh = st.sidebar.checkbox("Enable Auto Refresh", value=False)

st.sidebar.markdown("---")
run_scan_button = st.sidebar.button("Run Scan Now")

# Displaying dataset storage info
st.sidebar.info(f"History File: {HISTORY_FILE}\n\nState File: {STATE_FILE}")

# Running scan manually
if run_scan_button:
    st.session_state["run_scan"] = True

# Triggering auto refresh
if auto_refresh:
    st.session_state["run_scan"] = True
    time.sleep(scan_interval)
    st.rerun()

# Performing scan if requested
if st.session_state.get("run_scan", False):
    st.session_state["run_scan"] = False

    with st.spinner("Running Nmap scan..."):
        latest_scan, full_history, alerts_df = running_single_scan(target_subnet)

    st.success("Scan completed!")

    # Showing latest scan summary
    st.subheader("Latest Scan Summary")
    st.dataframe(latest_scan, use_container_width=True)

    # Showing anomaly alerts
    st.subheader("Anomaly Alerts")
    if alerts_df.empty:
        st.info("No anomalies detected in the latest scan.")
    else:
        st.warning("Anomalies detected!")
        st.dataframe(alerts_df[["timestamp", "host", "open_ports_count", "new_ports_count", "added_ports", "removed_ports"]], use_container_width=True)

    # Showing trend charts
    st.subheader("Trend Analysis")
    if full_history.empty:
        st.info("No historical data available yet.")
    else:
        # Converting timestamp column to datetime
        full_history["timestamp"] = pd.to_datetime(full_history["timestamp"], errors="coerce")

        col1, col2 = st.columns(2)

        with col1:
            st.write("Open Ports Count Over Time")
            chart_df = full_history.groupby("timestamp")["open_ports_count"].sum().reset_index()
            st.line_chart(chart_df.set_index("timestamp"))

        with col2:
            st.write("Total New Ports Detected Over Time")
            new_ports_df = full_history.groupby("timestamp")["new_ports_count"].sum().reset_index()
            st.line_chart(new_ports_df.set_index("timestamp"))

        st.subheader("Anomaly Count Over Time")
        anomaly_df = full_history.groupby("timestamp")["anomaly_flag"].sum().reset_index()
        st.area_chart(anomaly_df.set_index("timestamp"))

else:
    st.info("Click **Run Scan Now** to start scanning your network.")
