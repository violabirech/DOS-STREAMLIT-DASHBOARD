import streamlit as st
st.set_page_config(page_title="DoS Anomaly Detection", layout="wide")

import pandas as pd
import numpy as np
import uuid
from sklearn.ensemble import IsolationForest
from influxdb_client import InfluxDBClient
import plotly.express as px
from datetime import datetime
from streamlit_autorefresh import st_autorefresh

# --- InfluxDB Configuration ---
INFLUXDB_URL = "https://us-east-1-1.aws.cloud2.influxdata.com"
INFLUXDB_TOKEN = "DfmvA8hl5EeOcpR-d6c_ep6dRtSRbEcEM_Zqp8-1746dURtVqMDGni4rRNQbHouhqmdC7t9Kj6Y-AyOjbBg-zg=="  # Replace this
INFLUXDB_ORG = "Anormally Detection"
INFLUXDB_BUCKET = "realtime"
MEASUREMENT = "network_traffic"

# --- Query InfluxDB ---
def query_influx(start="-5h", limit=1000):
    try:
        client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
        query = f'''
        from(bucket: "{INFLUXDB_BUCKET}")
          |> range(start: {start})
          |> filter(fn: (r) => r["_measurement"] == "{MEASUREMENT}")
          |> filter(fn: (r) => r["_field"] == "packet_rate" or r["_field"] == "packet_length" or r["_field"] == "inter_arrival_time")
          |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
          |> sort(columns: ["_time"], desc: false)
          |> limit(n: {limit})
        '''
        df = client.query_api().query_data_frame(query)
        df = df.rename(columns={"_time": "timestamp"})
        return df[["timestamp", "packet_rate", "packet_length", "inter_arrival_time"]].dropna()
    except Exception as e:
        st.error(f"InfluxDB Error: {e}")
        return pd.DataFrame()

# --- Anomaly Detection ---
def detect_anomalies(df):
    X = df[["packet_rate", "packet_length", "inter_arrival_time"]]
    model = IsolationForest(n_estimators=100, contamination=0.15, random_state=42)
    df["anomaly_score"] = model.fit(X).decision_function(X)
    df["anomaly"] = (model.predict(X) == -1).astype(int)
    return df

# --- Tabs ---
tabs = st.tabs(["Overview", "Live Stream", "Manual Entry", "Metrics", "Historical"])

# --- Tab 1: Overview ---
with tabs[0]:
    st.title("🚨 Real-Time DoS Detection Dashboard")
    st.header("🔎 Overview")
    if st.button("🔄 Refresh Now"):
        st.session_state["refreshed_data"] = query_influx()
    
    df = st.session_state.get("refreshed_data", query_influx())
    if not df.empty:
        df = detect_anomalies(df)
        st.dataframe(df.tail(10), use_container_width=True)
        latest = df.iloc[-1]
        col1, col2, col3 = st.columns(3)
        col1.metric("Packet Rate", f"{latest['packet_rate']:.2f}")
        col2.metric("Packet Length", f"{latest['packet_length']:.1f}")
        col3.metric("Inter-Arrival", f"{latest['inter_arrival_time']:.4f}s")

        st.subheader("Latest Prediction")
        if latest["anomaly"] == 1:
            st.error("🔴 Anomaly Detected")
        else:
            st.success("🟢 Normal Traffic")
    else:
        st.info("No data available yet.")

# --- Tab 2: Live Stream ---
with tabs[1]:
    st.header("📡 Live DoS Stream (Auto-refresh)")
    st_autorefresh(interval=10000, key="live_tab_refresh")
    df = query_influx(start="-1m", limit=200)
    if not df.empty:
        df = detect_anomalies(df)
        st.plotly_chart(px.line(df, x="timestamp", y="packet_rate", color="anomaly", title="Packet Rate (Live)"), use_container_width=True)
        st.dataframe(df.sort_values("timestamp", ascending=False).head(10), use_container_width=True)
    else:
        st.warning("No recent traffic detected.")

# --- Tab 3: Manual Entry ---
with tabs[2]:
    st.header("🧪 Manual Anomaly Prediction")
    col1, col2, col3 = st.columns(3)
    rate = col1.number_input("Packet Rate", 0.0, 10000.0, 100.0)
    length = col2.number_input("Packet Length", 0.0, 2000.0, 500.0)
    iat = col3.number_input("Inter-arrival Time", 0.0001, 10.0, 0.01)
    if st.button("Predict Anomaly"):
        temp = pd.DataFrame([[rate, length, iat]], columns=["packet_rate", "packet_length", "inter_arrival_time"])
        pred = detect_anomalies(temp)
        is_anomaly = pred["anomaly"].iloc[0]
        if is_anomaly:
            st.error("🔴 Anomaly Detected")
        else:
            st.success("🟢 Normal Traffic")

# --- Tab 4: Metrics ---
with tabs[3]:
    st.header("📈 Metrics Overview")
    df = query_influx()
    if not df.empty:
        df = detect_anomalies(df)
        fig = px.histogram(df, x="anomaly", color="anomaly", title="Anomaly Count", nbins=2)
        st.plotly_chart(fig, use_container_width=True)

        line = px.line(df, x="timestamp", y="packet_rate", color="anomaly", title="Packet Rate")
        st.plotly_chart(line, use_container_width=True)
    else:
        st.info("Metrics not available")

# --- Tab 5: Historical Data ---
with tabs[4]:
    st.header("📦 Historical DoS Traffic")
    df = query_influx(start="-24h")
    if not df.empty:
        df = detect_anomalies(df)
        st.dataframe(df.tail(100), use_container_width=True)
        st.download_button("📥 Download CSV", df.to_csv(index=False), "historical_dos.csv", "text/csv")
    else:
        st.info("No historical data found.")
