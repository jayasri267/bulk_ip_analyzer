# frontend/main.py
import streamlit as st
import tempfile, shutil, os
import sys

# --- Automatically add project root to sys.path ---
current_dir = os.path.dirname(os.path.abspath(__file__))   # frontend/
project_root = os.path.abspath(os.path.join(current_dir, ".."))  # bulk_ip_analyzer/
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# --- Now we can safely import backend modules ---
from backend.ingest import detect_and_parse
from backend.app import analyze_records

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# --- Streamlit page config ---
st.set_page_config(
    page_title="Bulk IP Analysis",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.title("🌐 Bulk IP Analysis — Enhanced Prototype")
st.markdown("""
Upload a PCAP / JSONL / CSV file and get an enriched report with:
- GeoIP locations
- Tor / VPN / Proxy detection
- VoIP heuristic detection
- Interactive charts & maps
""")

# --- File upload ---
uploaded_file = st.file_uploader(
    "Upload PCAP / JSONL / CSV", 
    type=["pcap","pcapng","jsonl","ndjson","json","csv"]
)

if uploaded_file:
    suffix = os.path.splitext(uploaded_file.name)[1]
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        shutil.copyfileobj(uploaded_file, tmp)
        tmp_path = tmp.name

    st.info(f"Parsing {uploaded_file.name} ...")
    try:
        records = detect_and_parse(tmp_path)
        results_df = analyze_records(records)
    except Exception as e:
        st.error(f"Error parsing file: {e}")
        results_df = pd.DataFrame()

    if results_df.empty:
        st.warning("No records found or processing failed.")
    else:
        st.success("✅ Enriched report ready.")

        # --- Dataframe display ---
        st.subheader("Enriched Records")
        st.dataframe(results_df)
        st.download_button(
            "Download report CSV", 
            data=results_df.to_csv(index=False),
            file_name="report.csv"
        )

        # --- GeoIP Choropleth ---
        if "CountryCode" in results_df.columns:
            geo_df = results_df.groupby("CountryCode").size().reset_index(name="Count")
            geo_df = geo_df[geo_df["CountryCode"].notna()]
            if not geo_df.empty:
                st.subheader("🌍 IP Distribution by Country")
                fig_map = px.choropleth(
                    geo_df, 
                    locations="CountryCode",
                    color="Count",
                    color_continuous_scale="Viridis",
                    title="Number of IPs per Country"
                )
                st.plotly_chart(fig_map, use_container_width=True)

        # --- Session Timeline ---
        if "start_time" in results_df.columns and "end_time" in results_df.columns:
            st.subheader("⏱️ SIP/RTP Session Timeline")
            fig_timeline = go.Figure()
            for i, row in results_df.iterrows():
                start = row.get("start_time")
                end = row.get("end_time")
                if pd.notna(start) and pd.notna(end):
                    fig_timeline.add_trace(go.Scatter(
                        x=[start, end],
                        y=[i, i],
                        mode='lines+markers',
                        line=dict(width=6, color='royalblue'),
                        marker=dict(size=10),
                        name=row.get("call_id", f"call_{i}")
                    ))
            fig_timeline.update_layout(
                yaxis=dict(title="Session Index", showticklabels=False),
                xaxis=dict(title="Timestamp"),
                height=400
            )
            st.plotly_chart(fig_timeline, use_container_width=True)

        # --- Security Summary ---
        st.subheader("🔹 Tor / VPN / VoIP Summary")
        summary_cols = ["Tor","VPN/Proxy","VoIP"]
        if any(c in results_df.columns for c in summary_cols):
            summary_counts = {c: results_df[c].sum() if c in results_df.columns else 0 for c in summary_cols}
            fig_anim = px.bar(
                x=list(summary_counts.keys()),
                y=list(summary_counts.values()),
                text=list(summary_counts.values()),
                title="Tor / VPN / VoIP Count",
                labels={"x":"Type","y":"Count"}
            )
            st.plotly_chart(fig_anim, use_container_width=True)

    try:
        os.unlink(tmp_path)
    except Exception:
        pass

# --- Sidebar ---
st.sidebar.header("Quick Tips")
st.sidebar.markdown("""
- For large PCAPs, pre-filter:  
`tshark -r big.pcap -Y "sip || rtp" -w filtered.pcap`  
- API available at `/ingest/upload` and `/ingest/jsonl`
- Supports JSONL / CSV / PCAP
""")
