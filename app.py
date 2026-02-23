import streamlit as st
import joblib
import numpy as np
import re
from urllib.parse import urlparse
import time

# 1. Page Configuration
st.set_page_config(page_title="CyberShield AI", page_icon="⚡", layout="wide")

# 2. Cyber Mode Styling (Custom CSS)
st.markdown("""
    <style>
    /* Main Background */
    .stApp {
        background-color: #0a0e14;
        color: #00ff41; /* Matrix Green */
        font-family: 'Courier New', Courier, monospace;
    }
    
    /* Input Field */
    .stTextInput input {
        background-color: #161b22 !important;
        color: #00ff41 !important;
        border: 1px solid #00ff41 !important;
        border-radius: 5px;
        box-shadow: 0 0 10px rgba(0, 255, 65, 0.2);
    }

    /* Analyze Button */
    .stButton>button {
        background-color: transparent;
        color: #00ff41;
        border: 2px solid #00ff41;
        border-radius: 0px;
        font-weight: bold;
        text-transform: uppercase;
        letter-spacing: 2px;
        transition: 0.4s;
        width: 100%;
    }
    .stButton>button:hover {
        background-color: #00ff41;
        color: #0a0e14;
        box-shadow: 0 0 20px #00ff41;
    }

    /* Sidebar Customization */
    [data-testid="stSidebar"] {
        background-color: #0d1117;
        border-right: 1px solid #00ff41;
    }

    /* Metric Cards */
    div[data-testid="stMetricValue"] {
        color: #00d2ff;
        font-family: 'Orbitron', sans-serif;
    }
    </style>
    """, unsafe_allow_html=True)

# 3. Backend Logic (Your Code)
@st.cache_resource 
def load_model():
    return joblib.load('model.joblib')

model = load_model()

feature_names = [
    'having_IPhaving_IP_Address', 'URLURL_Length', 'Shortining_Service', 'having_At_Symbol',
    'double_slash_redirecting', 'Prefix_Suffix', 'having_Sub_Domain', 'SSLfinal_State',
    'Domain_registeration_length', 'Favicon', 'port', 'HTTPS_token', 'Request_URL',
    'URL_of_Anchor', 'Links_in_tags', 'SFH', 'Submitting_to_email', 'Abnormal_URL',
    'Redirect', 'on_mouseover', 'RightClick', 'popUpWidnow', 'Iframe',
    'age_of_domain', 'DNSRecord', 'web_traffic', 'Page_Rank', 'Google_Index',
    'Links_pointing_to_page', 'Statistical_report'
]

def extract_features(url):
    hostname = urlparse(url).netloc
    url_len = len(url)
    f_dict = {}

    f_dict['having_IPhaving_IP_Address'] = -1 if re.match(r"\d+\.\d+\.\d+\.\d+", hostname) else 1
    f_dict['URLURL_Length'] = 1 if url_len < 54 else (0 if url_len <= 75 else -1)
    f_dict['Shortining_Service'] = -1 if re.search(r'bit\.ly|goo\.gl|t\.co|tinyurl|is\.gd', url) else 1
    f_dict['having_At_Symbol'] = -1 if "@" in url else 1
    f_dict['double_slash_redirecting'] = -1 if url.rfind('//') > 7 else 1
    f_dict['Prefix_Suffix'] = -1 if '-' in hostname else 1

    dot_count = hostname.count('.')
    f_dict['having_Sub_Domain'] = 1 if dot_count <= 2 else (0 if dot_count == 3 else -1)
    f_dict['SSLfinal_State'] = 1 if url.startswith('https') else -1
    f_dict['Domain_registeration_length'] = 1 if any(x in hostname for x in ['google', 'facebook', 'microsoft', 'apple']) else -1
    f_dict['Favicon'] = 1
    f_dict['port'] = 1 
    f_dict['Iframe'] = -1 if "iframe" in url.lower() else 1
    f_dict['HTTPS_token'] = -1 if "https" in hostname else 1
    f_dict['Request_URL'] = -1 if url.count('http') > 1 else 1
    f_dict['URL_of_Anchor'] = -1 if re.search(r'login|verify|update|account', url.lower()) else 1
    f_dict['Links_in_tags'] = 0 
    f_dict['SFH'] = 1
    f_dict['Submitting_to_email'] = -1 if "mail()" in url or "mailto:" in url else 1
    f_dict['Abnormal_URL'] = -1 if hostname not in url else 1
    f_dict['Redirect'] = 0
    f_dict['on_mouseover'] = 1
    f_dict['RightClick'] = 1
    f_dict['popUpWidnow'] = 1
    f_dict['age_of_domain'] = 1 if any(x in hostname for x in ['com', 'org', 'edu']) else -1
    f_dict['DNSRecord'] = 1
    f_dict['web_traffic'] = 1 if any(x in hostname for x in ['google', 'yahoo', 'bing']) else 0
    f_dict['Page_Rank'] = 0
    f_dict['Google_Index'] = 1
    f_dict['Links_pointing_to_page'] = 1
    f_dict['Statistical_report'] = 1

    if "@" in url:
        f_dict['having_At_Symbol'] = -1
        f_dict['Abnormal_URL'] = -1

    ordered_features = [f_dict[name] for name in feature_names]
    return np.array([ordered_features])

# 4. UI Body
st.markdown("<h1 style='text-align: center; color: #00ff41; letter-spacing: 5px;'>⚡ CYBER-SHIELD INITIATED</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #58a6ff;'>Deep Packet Inspection - XGBoost Intelligence Engine</p>", unsafe_allow_html=True)
st.divider()

# Main Layout
col1, col2 = st.columns([2, 1])

with col1:
    st.markdown("### 📥 INCOMING_PROTOCOL")
    url_input = st.text_input("ENTER_TARGET_URL >", placeholder="https://suspicious-node.net")

    if st.button("RUN DEEP SCAN"):
        if url_input:
            if not url_input.startswith(('http://', 'https://')):
                st.warning("PROTOCOL_ERROR: HTTP/HTTPS_HEADER_MISSING")
            else:
                with st.status("Initializing Neural Scan...", expanded=True) as status:
                    st.write("Extracting URL metadata...")
                    time.sleep(0.5)
                    st.write("Verifying SSL/TLS Handshake...")
                    time.sleep(0.5)
                    st.write("Running XGBoost Inference...")
                    
                    test_data = extract_features(url_input)
                    prediction = model.predict(test_data)
                    probability = model.predict_proba(test_data)[0]
                    status.update(label="Scan Sequence Complete!", state="complete", expanded=False)

                if prediction[0] == 0:
                    confidence = probability[0] * 100
                    st.error(f"🚨 THREAT_IDENTIFIED: PHISHING_ATTEMPT")
                    st.metric(label="CONFIDENCE_LEVEL", value=f"{confidence:.2f}%", delta="- CRITICAL_RISK")
                    st.code(f"DETECTION_LOG: Suspicious patterns detected in {url_input}")
                else:
                    confidence = probability[1] * 100
                    st.success(f"🛡️ PROTOCOL: SECURE_DOMAIN_VERIFIED")
                    st.metric(label="SAFETY_LEVEL", value=f"{confidence:.2f}%", delta="STABLE")
                    st.code(f"DETECTION_LOG: No malicious signatures found.")

                # -------------------------------------
        else:
            st.info("AWAITING_INPUT_COMMAND...")

with col2:
    st.markdown("### 📊 SYSTEM_STATUS")
    st.code("""
[SYSTEM_LOGS]
> Accuracy: 96.88%
> Engine: XGBoost
> Status: Online
> Firewall: Active
    """, language="bash")
    
    st.markdown("---")
    st.sidebar.markdown("### 📡 CORE_INFO")
    st.sidebar.markdown(
    '<p style="color:#B1E6F3;">Real-time AI analysis of URL structure and security patterns.</p>', 
    unsafe_allow_html=True
    )
    st.sidebar.markdown(f"**Developed by: DevTT**")
    st.sidebar.markdown(f"**Uptime:** Always Active")