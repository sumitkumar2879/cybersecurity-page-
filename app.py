"""
CyberShield - a beginner-friendly security dashboard built with Streamlit.

All data in this file is FAKE (simulated). No real passwords are collected
and no real login monitoring is performed.

Run it with:   streamlit run app.py
"""

import pandas as pd
import streamlit as st

# ---------------------------------------------------------------------------
# 1. PAGE SETUP
# ---------------------------------------------------------------------------
st.set_page_config(page_title="CyberShield", page_icon="🛡️", layout="wide")


# ---------------------------------------------------------------------------
# 2. SETTINGS YOU CAN CUSTOMIZE
# ---------------------------------------------------------------------------
ODD_HOURS_START = 22      # logins at or after 22:00 (10 PM) are "odd hour"
ODD_HOURS_END = 6         # logins before 06:00 (6 AM) are "odd hour"
SUSPICIOUS_SCORE = 2      # a login with this risk score or higher is "suspicious"

# Where each user normally logs in from. Anything else counts as unusual.
USUAL_COUNTRY = {
    "alice": "India",
    "bob": "India",
    "carol": "USA",
    "dave": "UK",
    "admin": "India",
}


# ---------------------------------------------------------------------------
# 3. FAKE LOGIN DATA (20 records)
#    The IP addresses come from ranges reserved for documentation,
#    so they never point to real machines.
# ---------------------------------------------------------------------------
LOGIN_RECORDS = [
    {"username": "admin", "status": "Failed",  "ip": "192.0.2.99",    "country": "Russia", "timestamp": "2026-10-22 02:14:05"},
    {"username": "admin", "status": "Failed",  "ip": "192.0.2.99",    "country": "Russia", "timestamp": "2026-10-22 02:14:38"},
    {"username": "admin", "status": "Failed",  "ip": "192.0.2.99",    "country": "Russia", "timestamp": "2026-10-22 02:15:02"},
    {"username": "admin", "status": "Failed",  "ip": "192.0.2.99",    "country": "Russia", "timestamp": "2026-10-22 02:15:40"},
    {"username": "admin", "status": "Success", "ip": "192.0.2.99",    "country": "Russia", "timestamp": "2026-10-22 02:16:21"},
    {"username": "alice", "status": "Failed",  "ip": "203.0.113.55",  "country": "China",  "timestamp": "2026-10-22 03:30:12"},
    {"username": "alice", "status": "Success", "ip": "203.0.113.10",  "country": "India",  "timestamp": "2026-10-22 09:05:44"},
    {"username": "bob",   "status": "Success", "ip": "203.0.113.11",  "country": "India",  "timestamp": "2026-10-22 09:12:09"},
    {"username": "carol", "status": "Success", "ip": "198.51.100.20", "country": "USA",    "timestamp": "2026-10-22 09:30:51"},
    {"username": "dave",  "status": "Success", "ip": "192.0.2.30",    "country": "UK",     "timestamp": "2026-10-22 10:02:17"},
    {"username": "alice", "status": "Success", "ip": "203.0.113.10",  "country": "India",  "timestamp": "2026-10-22 11:15:30"},
    {"username": "bob",   "status": "Failed",  "ip": "203.0.113.11",  "country": "India",  "timestamp": "2026-10-22 12:40:03"},
    {"username": "bob",   "status": "Success", "ip": "203.0.113.11",  "country": "India",  "timestamp": "2026-10-22 12:40:29"},
    {"username": "carol", "status": "Success", "ip": "198.51.100.20", "country": "USA",    "timestamp": "2026-10-22 14:00:10"},
    {"username": "dave",  "status": "Failed",  "ip": "198.51.100.77", "country": "Brazil", "timestamp": "2026-10-22 15:20:44"},
    {"username": "dave",  "status": "Failed",  "ip": "198.51.100.77", "country": "Brazil", "timestamp": "2026-10-22 15:21:02"},
    {"username": "dave",  "status": "Failed",  "ip": "198.51.100.77", "country": "Brazil", "timestamp": "2026-10-22 15:21:25"},
    {"username": "alice", "status": "Success", "ip": "203.0.113.10",  "country": "India",  "timestamp": "2026-10-22 16:45:00"},
    {"username": "bob",   "status": "Success", "ip": "203.0.113.11",  "country": "India",  "timestamp": "2026-10-22 17:30:36"},
    {"username": "carol", "status": "Success", "ip": "198.51.100.20", "country": "USA",    "timestamp": "2026-10-22 23:40:19"},
]


# ---------------------------------------------------------------------------
# 4. SECURITY CHECKS
#    Each check adds a label to "flags" and points to the "score".
#    More points = more risky.
# ---------------------------------------------------------------------------
def analyze_logins(records, max_failed_attempts):
    """Look at every login and add flags, a risk score, and a risk level."""
    df = pd.DataFrame(records)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)

    # CHECK 1 setup: count failed logins for each IP address.
    failed_per_ip = df[df["status"] == "Failed"].groupby("ip").size()
    repeat_ips = failed_per_ip[failed_per_ip >= max_failed_attempts].index.tolist()

    # CHECK 4 setup: remember recent failures for each (username, IP) pair.
    recent_failures = {}

    all_flags = []
    all_scores = []

    for _, row in df.iterrows():
        flags = []
        score = 0
        pair = (row["username"], row["ip"])

        # CHECK 1: Repeated failed logins from the same IP address.
        if row["ip"] in repeat_ips:
            flags.append("Repeated failed logins")
            score += 3

        # CHECK 2: Login from a country this user does not normally use.
        if row["country"] != USUAL_COUNTRY.get(row["username"]):
            flags.append("Unusual location")
            score += 2

        # CHECK 3: Login at an odd hour (late night or very early morning).
        hour = row["timestamp"].hour
        if hour >= ODD_HOURS_START or hour < ODD_HOURS_END:
            flags.append("Odd hour")
            score += 1

        # CHECK 4: A successful login right after several failures
        # (the attacker may have guessed the password).
        if row["status"] == "Success" and recent_failures.get(pair, 0) >= 2:
            flags.append("Success after failures")
            score += 4

        # Update the failure memory for the next row.
        if row["status"] == "Failed":
            recent_failures[pair] = recent_failures.get(pair, 0) + 1
        else:
            recent_failures[pair] = 0

        all_flags.append(", ".join(flags) if flags else "None")
        all_scores.append(score)

    df["flags"] = all_flags
    df["risk_score"] = all_scores
    df["risk_level"] = df["risk_score"].apply(risk_level)
    df["suspicious"] = df["risk_score"] >= SUSPICIOUS_SCORE
    return df, failed_per_ip


def risk_level(score):
    """Turn a risk score number into a simple label."""
    if score >= 5:
        return "High"
    if score >= 3:
        return "Medium"
    if score >= 1:
        return "Low"
    return "None"


# ---------------------------------------------------------------------------
# 5. LOOK AND FEEL (dark theme, written as CSS)
# ---------------------------------------------------------------------------
st.markdown(
    """
    <style>
    .stApp { background-color: #0E1420; color: #E6EDF7; }
    [data-testid="stSidebar"] { background-color: #131B2B; }
    [data-testid="stHeader"] { background: transparent; }
    .block-container { padding-top: 2rem; max-width: 1200px; }

    h1, h2, h3 { color: #E6EDF7 !important; letter-spacing: -0.01em; }
    .subtitle { color: #8A9BB5; font-size: 1.05rem; margin-bottom: 1.5rem; }

    .card {
        background: #161F2F;
        border: 1px solid #263349;
        border-radius: 10px;
        padding: 1.1rem 1.25rem;
    }
    .card-label { color: #8A9BB5; font-size: 0.9rem; }
    .card-value { font-size: 2.4rem; font-weight: 700; line-height: 1.2; }
    .card-note  { color: #8A9BB5; font-size: 0.8rem; }

    .alert {
        background: #161F2F;
        border: 1px solid #263349;
        border-left: 4px solid #FF5C5C;
        border-radius: 8px;
        padding: 0.7rem 1rem;
        margin-bottom: 0.6rem;
    }
    .alert-title { font-weight: 600; }
    .alert-detail { color: #8A9BB5; font-size: 0.85rem; }
    </style>
    """,
    unsafe_allow_html=True,
)


def metric_card(label, value, color, note):
    """Draw one number card. 'color' is the accent color on its top edge."""
    st.markdown(
        f'<div class="card" style="border-top: 4px solid {color};">'
        f'<div class="card-label">{label}</div>'
        f'<div class="card-value" style="color: {color};">{value}</div>'
        f'<div class="card-note">{note}</div>'
        f"</div>",
        unsafe_allow_html=True,
    )


def color_rows(row):
    """Tint a table row red or amber depending on its risk level."""
    if row["Risk"] == "High":
        style = "background-color: rgba(255, 92, 92, 0.18)"
    elif row["Risk"] == "Medium":
        style = "background-color: rgba(255, 184, 76, 0.16)"
    else:
        style = ""
    return [style] * len(row)


# ---------------------------------------------------------------------------
# 6. SIDEBAR CONTROLS
# ---------------------------------------------------------------------------
st.sidebar.header("Controls")
max_failed = st.sidebar.slider(
    "Failed logins before an IP is flagged", min_value=2, max_value=6, value=3
)
status_filter = st.sidebar.multiselect(
    "Show login status", ["Success", "Failed"], default=["Success", "Failed"]
)
risk_filter = st.sidebar.multiselect(
    "Show risk level",
    ["High", "Medium", "Low", "None"],
    default=["High", "Medium", "Low", "None"],
)
st.sidebar.caption("All data is simulated. No real logins are monitored.")


# ---------------------------------------------------------------------------
# 7. RUN THE ANALYSIS
# ---------------------------------------------------------------------------
data, failed_per_ip = analyze_logins(LOGIN_RECORDS, max_failed)

total_logins = len(data)
successful_logins = int((data["status"] == "Success").sum())
failed_logins = int((data["status"] == "Failed").sum())
suspicious_count = int(data["suspicious"].sum())


# ---------------------------------------------------------------------------
# 8. THE DASHBOARD
# ---------------------------------------------------------------------------
st.title("🛡️ CyberShield")
st.markdown(
    '<div class="subtitle">A simple security dashboard that reviews login '
    "activity and points out anything that looks risky.</div>",
    unsafe_allow_html=True,
)

# --- Four number cards ---
col1, col2, col3, col4 = st.columns(4)
with col1:
    metric_card("Total Logins", total_logins, "#6EA8FE", "All attempts in the log")
with col2:
    metric_card("Successful Logins", successful_logins, "#4ADE80", "Users who got in")
with col3:
    metric_card("Failed Logins", failed_logins, "#FF5C5C", "Attempts that were rejected")
with col4:
    metric_card("Suspicious Activities", suspicious_count, "#FFB84C", "Logins that need a look")

st.write("")

# --- Alerts: one message per suspicious IP address ---
st.subheader("Alerts")
suspicious_rows = data[data["suspicious"]]

if suspicious_rows.empty:
    st.success("No suspicious activity found.")
else:
    for ip, group in suspicious_rows.groupby("ip"):
        user_list = ", ".join(sorted(group["username"].unique()))
        reasons = sorted({f for text in group["flags"] for f in text.split(", ")})
        attempts = len(data[data["ip"] == ip])
        failures = len(data[(data["ip"] == ip) & (data["status"] == "Failed")])
        country = group["country"].iloc[0]
        st.markdown(
            f'<div class="alert">'
            f'<div class="alert-title">{ip} ({country}) - {attempts} attempts, {failures} failed</div>'
            f'<div class="alert-detail">Account: {user_list} &nbsp;|&nbsp; Reasons: {", ".join(reasons)}</div>'
            f"</div>",
            unsafe_allow_html=True,
        )

st.write("")

# --- Login records table ---
st.subheader("Login records")

table = data[
    (data["status"].isin(status_filter)) & (data["risk_level"].isin(risk_filter))
].copy()

table = pd.DataFrame(
    {
        "Time": table["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S"),
        "Username": table["username"],
        "Status": table["status"].map({"Success": "✅ Success", "Failed": "❌ Failed"}),
        "IP Address": table["ip"],
        "Country": table["country"],
        "Risk": table["risk_level"],
        "Flags": table["flags"],
    }
)

st.caption(f"Showing {len(table)} of {total_logins} records. Red = high risk, amber = medium risk.")
st.dataframe(table.style.apply(color_rows, axis=1), use_container_width=True, hide_index=True)

st.write("")

# --- Chart: failed logins per IP ---
st.subheader("Failed logins by IP address")
if failed_per_ip.empty:
    st.info("There are no failed logins to chart.")
else:
    st.bar_chart(failed_per_ip, color="#FF5C5C")

# --- Short explanation of the rules ---
with st.expander("How the security checks work"):
    st.markdown(
        f"""
        Each login starts with a risk score of 0. Every rule that matches adds points.

        - **Repeated failed logins (+3):** the same IP address failed **{max_failed} or more** times.
        - **Unusual location (+2):** the login came from a country that is not the user's usual one.
        - **Odd hour (+1):** the login happened between {ODD_HOURS_START}:00 and 0{ODD_HOURS_END}:00.
        - **Success after failures (+4):** a login worked right after 2 or more failures
          from the same user and IP, which can mean a password was guessed.

        Risk levels: **High** is 5 or more, **Medium** is 3-4, **Low** is 1-2.
        A login counts as *suspicious* when its score is **{SUSPICIOUS_SCORE} or higher**.
        """
    )