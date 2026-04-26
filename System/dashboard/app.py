import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
import os

st.set_page_config(page_title="Network Analyzer Pro", layout="wide")

# --- CUSTOM CSS TO HIDE DEPLOY & STOP BUTTONS ---
st.markdown("""
    <style>
    /* Hides the deploy button */
    .stAppDeployButton {
        display: none !important;
    }
    
    /* Hides the "Stop" button and "Running..." indicator in the top right */
    div[data-testid="stStatusWidget"] {
        display: none !important;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🌐 Network Monitoring and Traffic Analysis Dashboard")

# Build the absolute path to packets.csv to avoid directory errors
# This automatically finds the dashboard folder, goes up one level to System, then into data
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "..", "data", "packets.csv")
ALERTS_FILE = os.path.join(BASE_DIR, "..", "data", "alerts.csv")

# Load data
@st.cache_data(ttl=1) # Refresh cache frequently
def load_data():
    df = pd.read_csv(DATA_FILE)
    df['time'] = pd.to_datetime(df['time'])
    return df

try:
    data = load_data()

    # --- SIDEBAR FILTERS ---
    st.sidebar.header("Filters")
    selected_protocols = st.sidebar.multiselect(
        "Select Protocols", 
        options=data["protocol"].unique(), 
        default=data["protocol"].unique()
    )
    
    search_ip = st.sidebar.text_input("Search Source IP")

    # Filter data based on selection
    filtered_data = data[data["protocol"].isin(selected_protocols)]
    if search_ip:
        filtered_data = filtered_data[filtered_data["source_ip"].str.contains(search_ip)]

    # --- DYNAMIC METRICS ---
    protocol_counts = filtered_data["protocol"].value_counts()
    
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Packets", len(filtered_data))
    
    # Dynamically show the top 3 captured protocols
    if len(protocol_counts) > 0:
        col2.metric(f"{protocol_counts.index[0]}", protocol_counts.iloc[0])
    if len(protocol_counts) > 1:
        col3.metric(f"{protocol_counts.index[1]}", protocol_counts.iloc[1])
    if len(protocol_counts) > 2:
        col4.metric(f"{protocol_counts.index[2]}", protocol_counts.iloc[2])

    # --- VISUALIZATIONS ---
    tab1, tab2, tab3, tab4 = st.tabs(["📊 Distribution", "📈 Time Series", "💻 Applications", "🚨 Security Alerts"])

    with tab1:
        c1, c2 = st.columns(2)
        with c1:
            st.subheader("Protocol Share")
            fig1, ax1 = plt.subplots()
            filtered_data["protocol"].value_counts().plot(kind="pie", autopct="%1.1f%%", ax=ax1)
            ax1.set_ylabel("")
            st.pyplot(fig1)
        
        with c2:
            st.subheader("Top Ports")
            fig2, ax2 = plt.subplots()
            filtered_data["port"].value_counts().head(10).plot(kind="bar", ax=ax2, color="skyblue")
            st.pyplot(fig2)

    with tab2:
        st.subheader("Packets Over Time")
        time_data = filtered_data.set_index('time').resample('10S').count()
        st.line_chart(time_data['protocol'])

    with tab3:
        st.subheader("Top Applications by Packet Count")
        if "process_name" in filtered_data.columns:
            fig3, ax3 = plt.subplots()
            top_apps = filtered_data[filtered_data["process_name"] != "Unknown"]["process_name"].value_counts().head(10)
            if not top_apps.empty:
                top_apps.sort_values().plot(kind="barh", ax=ax3, color="mediumseagreen")
                ax3.set_xlabel("Packet Count")
                st.pyplot(fig3)
            else:
                st.info("No known applications captured yet. Make sure capture script is running with privileges.")
        else:
            st.info("Process name data not yet available in the capture logs.")

    with tab4:
        st.subheader("Real-Time Threat Detection")
        if os.path.exists(ALERTS_FILE):
            try:
                alerts_df = pd.read_csv(ALERTS_FILE)
                if not alerts_df.empty:
                    # Highlight high severity alerts
                    def color_severity(val):
                        if val == 'High':
                            return 'color: red; font-weight: bold'
                        elif val == 'Medium':
                            return 'color: orange; font-weight: bold'
                        return 'color: green'
                    
                    st.dataframe(alerts_df.style.map(color_severity, subset=['severity']), use_container_width=True)
                else:
                    st.success("No security threats detected recently.")
            except Exception as e:
                st.warning("Could not load alerts file. It may be currently updating.")
        else:
            st.success("No security threats detected recently.")

    # --- DATA TABLE ---
    st.subheader("Recent Traffic Logs")
    st.dataframe(filtered_data.tail(50), use_container_width=True)

except Exception as e:
    st.error(f"Waiting for network traffic to be captured... (File not generated yet)")

# Auto-refresh every 5 seconds
st.empty()
import time
time.sleep(5)
st.rerun()