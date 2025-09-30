import streamlit as st
import pandas as pd
from backend.app import analyze_records

st.title("Bulk IP Analyzer 🚀")

# File uploader
uploaded_file = st.file_uploader("Upload a CSV with IP records", type=["csv", "jsonl"])

if uploaded_file is not None:
    # Read input
    if uploaded_file.name.endswith(".csv"):
        df = pd.read_csv(uploaded_file)
        records = df.to_dict(orient="records")
    else:
        df = pd.read_json(uploaded_file, lines=True)
        records = df.to_dict(orient="records")

    # Run analysis
    st.info("Analyzing records...")
    result_df = analyze_records(records)

    if not result_df.empty:
        st.success("Analysis complete ✅")
        st.dataframe(result_df)  # Display results

        # Allow user to download results
        csv = result_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            label="Download results as CSV",
            data=csv,
            file_name="analysis_results.csv",
            mime="text/csv"
        )
    else:
        st.warning("No enriched records found.")
