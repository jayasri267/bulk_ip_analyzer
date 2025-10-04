# frontend/main.py
import streamlit as st
import tempfile
import shutil
import os
import sys
import sqlite3
import hashlib
import datetime
import re
from typing import Any

# --- Add project root to sys.path so we can import backend modules ---
current_dir = os.path.dirname(os.path.abspath(__file__))   # frontend/
project_root = os.path.abspath(os.path.join(current_dir, ".."))  # bulk_ip_analyzer/
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# --- Import backend processors (assumes these paths exist in your repo) ---
try:
    from backend.ingest import detect_and_parse
    from backend.app import analyze_records
except Exception as e:
    # Keep the app usable even if backend modules fail to import during dev
    detect_and_parse = None
    analyze_records = None
    st = st  # just to avoid linting errors

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

# ===================== Settings =====================
DB_PATH = os.path.join(project_root, "community.db")
UPLOAD_DIR = os.path.join(project_root, "community_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# --------------------- Utilities ---------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    password_hash TEXT,
                    created_at TEXT
                )""")
    c.execute("""CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user TEXT,
                    ip TEXT,
                    description TEXT,
                    file_path TEXT,
                    created_at TEXT,
                    upvotes INTEGER DEFAULT 0,
                    downvotes INTEGER DEFAULT 0
                )""")
    conn.commit()
    conn.close()

def sha256_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def valid_username(u: str) -> bool:
    if not u: 
        return False
    return re.match(r"^[A-Za-z0-9_.-]{3,32}$", u) is not None

def valid_password(p: str) -> bool:
    return len(p) >= 6

def save_uploaded_file(file_obj: Any, filename_prefix: str = "") -> str:
    """
    Accepts a Streamlit UploadedFile (has getbuffer) or an object with .read() or a path-like dict.
    Returns the saved file path.
    """
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S%f")
    # sanitize filename
    original_name = getattr(file_obj, "name", None) or f"file_{ts}"
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", original_name)
    out_name = f"{ts}_{filename_prefix}_{safe_name}" if filename_prefix else f"{ts}_{safe_name}"
    out_path = os.path.join(UPLOAD_DIR, out_name)
    # Different possible types:
    try:
        # Streamlit UploadedFile has getbuffer()
        data = file_obj.getbuffer()
        with open(out_path, "wb") as f:
            f.write(data)
    except Exception:
        try:
            # file-like with read()
            data = file_obj.read()
            # if returned str, encode
            if isinstance(data, str):
                data = data.encode("utf-8")
            with open(out_path, "wb") as f:
                f.write(data)
        except Exception:
            # file_obj might be a path string
            if isinstance(file_obj, str) and os.path.exists(file_obj):
                shutil.copyfile(file_obj, out_path)
            else:
                raise
    return out_path

def save_report(user: str, ip: str, description: str, file_obj: Any = None, filename_prefix: str = ""):
    # save uploaded/provided file and insert DB row
    file_path = None
    if file_obj is not None:
        file_path = save_uploaded_file(file_obj, filename_prefix=filename_prefix)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        "INSERT INTO reports (user, ip, description, file_path, created_at) VALUES (?,?,?,?,?)",
        (user, ip, description or "", file_path, datetime.datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

def get_reports_df(limit: int = 200):
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(f"SELECT * FROM reports ORDER BY created_at DESC LIMIT {limit}", conn)
    conn.close()
    return df

def change_vote(report_id: int, delta_up: int = 0, delta_down: int = 0):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    if delta_up != 0:
        c.execute("UPDATE reports SET upvotes = upvotes + ? WHERE id = ?", (delta_up, report_id))
    if delta_down != 0:
        c.execute("UPDATE reports SET downvotes = downvotes + ? WHERE id = ?", (delta_down, report_id))
    conn.commit()
    conn.close()

# Initialize DB
init_db()

# ===================== Streamlit UI =====================
st.set_page_config(page_title="Bulk IP Analysis", layout="wide", initial_sidebar_state="expanded")

# Session state defaults
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = None

# ----- Auth helpers -----
def register_user(username: str, password: str) -> (bool, str):
    if not valid_username(username):
        return False, "Username must be 3-32 characters: letters, numbers, . _ - allowed."
    if not valid_password(password):
        return False, "Password must be at least 6 characters."
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?,?,?)",
                  (username, sha256_hash(password), datetime.datetime.utcnow().isoformat()))
        conn.commit()
        return True, "User created."
    except sqlite3.IntegrityError:
        return False, "Username already exists."
    finally:
        conn.close()

def authenticate_user(username: str, password: str) -> bool:
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return False
    return row[0] == sha256_hash(password)

# ----- Pages -----
def show_signup():
    st.header("Create an account")
    st.write("Choose a username and password. Username: 3-32 chars, letters/numbers/._-")
    new_user = st.text_input("Username", key="su_user")
    new_pass = st.text_input("Password", type="password", key="su_pass")
    confirm = st.text_input("Confirm Password", type="password", key="su_confirm")
    if st.button("Sign up"):
        if new_pass != confirm:
            st.error("Passwords do not match.")
        else:
            ok, msg = register_user(new_user.strip(), new_pass)
            if ok:
                st.success("Account created — you can login now.")
            else:
                st.error(msg)

def show_login():
    st.header("Sign in")
    username = st.text_input("Username", key="li_user")
    password = st.text_input("Password", type="password", key="li_pass")
    if st.button("Log in"):
        if authenticate_user(username.strip(), password):
            st.session_state.logged_in = True
            st.session_state.username = username.strip()
            st.success(f"Logged in as {st.session_state.username}")
        else:
            st.error("Invalid username or password.")

def show_logout():
    st.write(f"Logged in as **{st.session_state.username}**")
    if st.button("Log out"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.success("Logged out.")

def community_portal_page():
    st.title("Community Portal")
    st.write("Report suspicious IPs and share detector output as proof. Reports are public.")
    if not st.session_state.logged_in:
        st.warning("Please log in to submit a report.")
    col1, col2 = st.columns([2,1])
    with col1:
        ip = st.text_input("Suspicious IP", key="cp_ip")
        desc = st.text_area("Description / Notes (optional)", key="cp_desc")
        proof = st.file_uploader("Attach proof file (CSV/JSON/PCAP) — optional", type=["csv","json","jsonl","pcap","pcapng"], key="cp_proof")
        if st.button("Submit report"):
            if not st.session_state.logged_in:
                st.error("You must be logged in to submit a report.")
            elif not ip:
                st.error("Please specify the suspicious IP.")
            else:
                try:
                    save_report(st.session_state.username, ip.strip(), desc.strip(), proof, filename_prefix="proof")
                    st.success("Report submitted — thank you.")
                    # clear inputs
                    st.experimental_rerun()
                except Exception as e:
                    st.error(f"Error saving report: {e}")
    with col2:
        st.markdown("**Quick tips**")
        st.markdown("- Attach detector output if available (report CSV/JSON).")
        st.markdown("- Keep descriptions factual and include timestamps if possible.")
        st.markdown("- Upvote helpful reports to increase visibility.")
    st.divider()
    st.subheader("Recent Reports")
    reports_df = get_reports_df()
    if reports_df.empty:
        st.info("No reports yet.")
        return
    # show compact listing with upvote/downvote
    for idx, row in reports_df.iterrows():
        st.markdown(f"**IP:** `{row['ip']}` — reported by **{row['user']}** on {row['created_at']}")
        if row.get("description"):
            st.write(row["description"])
        # download proof if exists
        if row["file_path"]:
            try:
                with open(row["file_path"], "rb") as f:
                    data = f.read()
                st.download_button("Download proof file", data=data, file_name=os.path.basename(row["file_path"]), key=f"dl_{row['id']}")
            except Exception as e:
                st.warning(f"Proof file missing ({e})")
        # votes and vote buttons
        colA, colB, colC = st.columns([1,1,6])
        with colA:
            if st.button("👍", key=f"up_{row['id']}"):
                change_vote(row["id"], delta_up=1)
                st.experimental_rerun()
            st.write(f"{int(row['upvotes'])}")
        with colB:
            if st.button("👎", key=f"down_{row['id']}"):
                change_vote(row["id"], delta_down=1)
                st.experimental_rerun()
            st.write(f"{int(row['downvotes'])}")
        with colC:
            # link to show file path for debugging (optional)
            st.caption(f"report id: {row['id']}")
        st.divider()

def analysis_page():
    st.title("Bulk IP Analysis — Enhanced Prototype")
    st.write("Upload PCAP / JSONL / CSV and get an enriched report (Tor, VPN/Proxy, VoIP heuristics, GeoIP).")

    uploaded_file = st.file_uploader("Upload PCAP / JSONL / CSV", type=["pcap","pcapng","jsonl","ndjson","json","csv"])
    results_df = pd.DataFrame()
    temp_uploaded_path = None

    if uploaded_file:
        suffix = os.path.splitext(uploaded_file.name)[1]
        # save uploaded temporarily so backend functions expecting a path can read it
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            shutil.copyfileobj(uploaded_file, tmp)
            temp_uploaded_path = tmp.name

        st.info(f"Parsing {uploaded_file.name} ...")
        try:
            if detect_and_parse is None or analyze_records is None:
                st.warning("Backend ingest/analyze functions not available. Returning empty result for demo.")
                results_df = pd.DataFrame()
            else:
                records = detect_and_parse(temp_uploaded_path)
                results_df = analyze_records(records)
        except Exception as e:
            st.error(f"Error parsing file: {e}")
            results_df = pd.DataFrame()

        # clean up temp file after processing
        try:
            if temp_uploaded_path and os.path.exists(temp_uploaded_path):
                os.unlink(temp_uploaded_path)
        except Exception:
            pass

    if results_df is None:
        results_df = pd.DataFrame()

    if results_df.empty:
        st.info("No enriched records to show yet. Upload a supported file to analyze.")
        return

    # normalize columns to show likely IP column names
    st.subheader("Enriched Records")
    st.dataframe(results_df)

    # Download full report
    csv_bytes = results_df.to_csv(index=False).encode("utf-8")
    st.download_button("Download full report (CSV)", data=csv_bytes, file_name="report.csv")

    # --- Inline "Report IP" UI per row (if logged in) ---
    ip_columns = [c for c in results_df.columns if c.lower() in ("ip","sourceip","src_ip","dst_ip","dstip","srcip","client_ip")]
    # fallback try these names
    if not ip_columns:
        possible = [c for c in results_df.columns if "ip" in c.lower()]
        ip_columns = possible[:1] if possible else []

    st.markdown("---")
    if st.session_state.logged_in:
        st.subheader("Report Suspicious IPs (quick)")
        # create an expander per row
        for i, row in results_df.iterrows():
            # determine ip for this row
            ip_val = None
            for c in ip_columns:
                v = row.get(c)
                if pd.notna(v) and v:
                    ip_val = v
                    break
            # generic fallback: try columns named Source, Src, Dst etc.
            if ip_val is None:
                for c in ["source","src","dst"]:
                    if c in results_df.columns:
                        v = row.get(c)
                        if pd.notna(v):
                            ip_val = v
                            break
            title_ip = ip_val or f"row {i}"
            with st.expander(f"Report {title_ip}"):
                st.write(row.to_dict())
                desc = st.text_area("Optional description", key=f"rdesc_{i}")
                attach_proof = st.checkbox("Attach this full result row as proof (CSV)", key=f"rproof_{i}", value=True)
                if st.button(f"Submit report for {title_ip}", key=f"rbtn_{i}"):
                    # prepare proof file (optional)
                    proof_path_or_file = None
                    try:
                        if attach_proof:
                            # create a small CSV containing just this row
                            tmpf = tempfile.NamedTemporaryFile(delete=False, suffix=".csv")
                            try:
                                single_df = pd.DataFrame([row])
                                single_df.to_csv(tmpf.name, index=False)
                                tmpf.close()
                                proof_path_or_file = tmpf.name
                                # save_report handles path copies
                                save_report(st.session_state.username, str(ip_val), desc or "", proof_path_or_file, filename_prefix="analysis")
                                st.success(f"Reported {title_ip}")
                            finally:
                                # remove tmp; save_report copies the file
                                if proof_path_or_file and os.path.exists(proof_path_or_file):
                                    os.unlink(proof_path_or_file)
                        else:
                            save_report(st.session_state.username, str(ip_val), desc or "", None, filename_prefix="analysis")
                            st.success(f"Reported {title_ip} (no proof attached)")
                    except Exception as e:
                        st.error(f"Failed to save report: {e}")
    else:
        st.info("Log in to report IPs directly from analysis results.")

    # GeoIP map (if CountryCode available)
    if "CountryCode" in results_df.columns:
        geo_df = results_df.groupby("CountryCode").size().reset_index(name="Count")
        geo_df = geo_df[geo_df["CountryCode"].notna()]
        if not geo_df.empty:
            st.subheader("IP Distribution by Country")
            fig_map = px.choropleth(
                geo_df,
                locations="CountryCode",
                color="Count",
                color_continuous_scale="Viridis",
                title="Number of IPs per Country"
            )
            st.plotly_chart(fig_map, use_container_width=True)

    # Session timeline (SIP/RTP)
    if "start_time" in results_df.columns and "end_time" in results_df.columns:
        st.subheader("SIP/RTP Session Timeline")
        fig_timeline = go.Figure()
        for i, row in results_df.iterrows():
            start = row.get("start_time")
            end = row.get("end_time")
            if pd.notna(start) and pd.notna(end):
                fig_timeline.add_trace(go.Scatter(
                    x=[start, end],
                    y=[i, i],
                    mode='lines+markers',
                    line=dict(width=6),
                    marker=dict(size=8),
                    name=row.get("call_id", f"call_{i}")
                ))
        fig_timeline.update_layout(yaxis=dict(title="Session Index", showticklabels=False), xaxis=dict(title="Timestamp"), height=400)
        st.plotly_chart(fig_timeline, use_container_width=True)

    # Tor/VPN/VoIP summary (if columns exist)
    summary_cols = ["Tor", "VPN/Proxy", "VoIP", "VPN", "Proxy"]
    present = [c for c in summary_cols if c in results_df.columns]
    if present:
        st.subheader("Tor / VPN / VoIP Summary")
        counts = {c: int(results_df[c].sum()) if c in results_df.columns else 0 for c in present}
        fig = px.bar(x=list(counts.keys()), y=list(counts.values()), text=list(counts.values()), labels={"x":"Type","y":"Count"})
        st.plotly_chart(fig, use_container_width=True)

# ----- Layout (sidebar nav) -----
menu = ["Analysis", "Community Portal", "Sign Up", "Sign In"]
choice = st.sidebar.selectbox("Menu", menu)

# sidebar show auth status and logout
st.sidebar.markdown("## Account")
if st.session_state.logged_in:
    st.sidebar.success(f"Signed in: {st.session_state.username}")
    if st.sidebar.button("Log out"):
        st.session_state.logged_in = False
        st.session_state.username = None
        st.experimental_rerun()
else:
    st.sidebar.info("Not signed in")

# Choose page
if choice == "Analysis":
    analysis_page()
elif choice == "Community Portal":
    community_portal_page()
elif choice == "Sign Up":
    show_signup()
elif choice == "Sign In":
    show_login()
