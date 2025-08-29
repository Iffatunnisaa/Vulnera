from fastapi import FastAPI, UploadFile, File
from fastapi.responses import StreamingResponse
import pandas as pd
import numpy as np
import joblib
import io

# =========================
# Inisialisasi FastAPI
# =========================
app = FastAPI()

# =========================
# Load trained models
# =========================
rf_model = joblib.load("../model/random_forest_model.pkl")
xgb_model = joblib.load("../model/xgboost_model.pkl")

# =============================
# Fungsi Feature Extraction
# =============================
def categorize_port(port):
    if port <= 1023:
        return "well_known"
    elif 1023 < port <= 49151:
        return "registered"
    else:
        return "dynamic"

def detect_bot_user_agent(ua):
    if pd.isna(ua): return 0
    bot_keywords = ['bot', 'crawler', 'spider', 'scraper', 'curl', 'wget', 'sqlmap',
                   'python-requests', 'libwww', 'java/', 'apache-httpclient']
    return int(any(keyword in ua.lower() for keyword in bot_keywords))

def detect_suspicious_user_agent(ua):
    if pd.isna(ua): return 0
    suspicious_patterns = ['<script', 'union', 'select', 'drop', 'insert',
                          'delete', '../', 'etc/passwd', 'cmd.exe', 'null']
    return int(any(pattern in ua.lower() for pattern in suspicious_patterns))

def extract_browser_type(ua):
    if pd.isna(ua): return 'Other'
    ua_lower = ua.lower()
    if 'chrome' in ua_lower and 'edge' not in ua_lower:
        return 'Chrome'
    elif 'firefox' in ua_lower:
        return 'Firefox'
    elif 'safari' in ua_lower and 'chrome' not in ua_lower:
        return 'Safari'
    elif 'edge' in ua_lower:
        return 'Edge'
    elif any(bot_word in ua_lower for bot_word in ['bot', 'crawler', 'spider']):
        return 'Bot'
    elif any(tool in ua_lower for tool in ['curl', 'wget', 'python', 'sqlmap', 'sql']):
        return 'Tool'
    else:
        return 'Other'

def detect_suspicious_url_keywords(url):
    if pd.isna(url): return 0
    url_lower = url.lower()
    suspicious_keywords = [
        'union', 'select', 'drop', 'insert', 'delete', 'update', 'from', 'where',
        '../', '..\\', '/etc/', '/passwd', '/shadow',
        'script', 'eval', 'exec', 'system', 'cmd.exe',
        'admin', 'login', 'wp-admin', 'phpmyadmin',
        '.php', '.asp', '.jsp', '.cgi'
    ]
    return int(any(keyword in url_lower for keyword in suspicious_keywords))

def extract_file_extension(url):
    try:
        if pd.isna(url): return 'none'
        path = url.split('?')[0].split('#')[0]
        if '.' in path and '/' in path:
            filename = path.split('/')[-1]
            if '.' in filename:
                ext = filename.split('.')[-1].lower()
                if len(ext) <= 5 and ext.isalnum():
                    return ext
        return 'none'
    except:
        return 'none'

def categorize_file_extension(extension):
    image_extensions = ['jpg', 'jpeg', 'png', 'gif', 'svg', 'bmp', 'tiff', 'webp']
    script_extensions = ['js', 'php', 'asp', 'html', 'css']
    document_extensions = ['pdf', 'txt', 'doc', 'docx', 'xls', 'xlsx']
    sql_extensions = ['sql']

    if extension is None or extension == '' or extension == 'none':
        return 'None'
    if extension in image_extensions:
        return 'Image'
    elif extension in script_extensions:
        return 'Script/Web Dynamic'
    elif extension in document_extensions:
        return 'Document/Text'
    elif extension in sql_extensions:
        return 'Database/SQL'
    else:
        return 'Other'

def categorize_status_code(code):
    try:
        code = int(code)
        if 200 <= code < 300:
            return 'Success'
        elif 300 <= code < 400:
            return 'Redirect'
        elif 400 <= code < 500:
            return 'Client_Error'
        elif 500 <= code < 600:
            return 'Server_Error'
        else:
            return 'Other'
    except:
        return 'Unknown'

def categorize_status_message(status_message):
    if status_message == "OK":
        return "Successful"
    elif status_message in ["Moved Permanently", "Found"]:
        return "Redirection"
    elif status_message in ["Bad Request", "Method Not Allowed", "Forbidden", "Not Found"]:
        return "Client Error"
    elif status_message in ["Internal Server Error", "Not Implemented", "Too Many Requests"]:
        return "Server Error"
    else:
        return "Other"

# =============================
# Preprocessing Pipeline
# =============================
def preprocess_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    # Drop NA & Duplicates
    df.dropna(inplace=True)
    df.drop_duplicates(inplace=True)
    
    #  2025 17:54:27.610347909 WIB
    
    # Buang kolom pertama
    df = df.iloc[:, 0:]

    # Buang kolom http.host
    df.drop(columns='http.host', inplace=True)

    # Rename kolom
    df.rename(columns={
        'frame.time':'timestamp',   
        'ip.src':'src_ip',   
        'tcp.srcport':'src_port',   
        'ip.dst':'dst_ip',
        'tcp.dstport':'dst_port',
        'http.request.method':'request_http_method',
        'http.request.uri':'request_http_request',
        'http.request.version':'request_http_protocol',
        'http.user_agent':'request_user_agent',
        'http.response.version':'response_http_protocol',
        'http.response.code':'response_http_status_code',
        'http.response.phrase':'response_http_status_message',
        'http.content_length':'response_content_length',
    }, inplace=True)
    
    if 'src_port' in df.columns:
        df['src_port_category'] = df['src_port'].apply(categorize_port)

    if 'request_http_method' in df.columns:
        main_methods = ["GET", "POST", "PUT"]
        df["request_http_method"] = df["request_http_method"].apply(
            lambda x: x if x in main_methods else "OTHER"
        )

    if 'request_user_agent' in df.columns:
        df['ua_length'] = df['request_user_agent'].astype(str).str.len()
        df['ua_is_bot'] = df['request_user_agent'].apply(detect_bot_user_agent)
        df['ua_is_suspicious'] = df['request_user_agent'].apply(detect_suspicious_user_agent)
        df['ua_browser_type'] = df['request_user_agent'].apply(extract_browser_type)

    if 'request_http_request' in df.columns:
        df['url_length'] = df['request_http_request'].astype(str).str.len()
        df['url_param_count'] = (df['request_http_request'].str.count('&') +
                                 df['request_http_request'].str.count('='))
        df['url_has_query'] = df['request_http_request'].str.contains('\?', regex=True).astype(int)
        df['url_depth'] = df['request_http_request'].str.count('/')
        df['url_has_suspicious_keywords'] = df['request_http_request'].apply(detect_suspicious_url_keywords)
        df['url_file_extension'] = df['request_http_request'].apply(extract_file_extension)
        df['file_extension_category'] = df['url_file_extension'].apply(categorize_file_extension)

    if 'response_http_status_code' in df.columns:
        df['status_code_category'] = df['response_http_status_code'].apply(categorize_status_code)
        df['is_error_response'] = (df['response_http_status_code'] >= 400).astype(int)

    if 'response_http_status_message' in df.columns:
        df['response_status_category'] = df['response_http_status_message'].apply(categorize_status_message)

    return df

# =============================
# Endpoint FastAPI
# =============================
@app.post("/predict-csv/")
async def predict_csv(file: UploadFile = File(...)):
    if not file.filename.endswith(".csv"):
        return {"error": "File harus dalam format CSV"}
    
    # Baca CSV
    contents = await file.read()
    df = pd.read_csv(io.BytesIO(contents))

    # Preprocessing & feature extraction
    df_processed = preprocess_dataframe(df.copy())

    # Buang kolom yang tidak dipakai model
    columns_to_drop = [
        'timestamp', 'src_ip', 'dst_ip', 'dst_port', 'request_http_request', 
        'request_user_agent', 'request_host', 'datetime', 'day', 'hour', 
        'response_http_status_code', 'response_http_status_message',
        'url_file_extension'
    ]
    df_model = df_processed.drop(columns=[c for c in columns_to_drop if c in df_processed.columns])

    # Prediksi
    rf_preds = rf_model.predict(df_model)
    rf_class_names = ['Normal', 'Anomali']
    rf_labels = [rf_class_names[p] for p in rf_preds]

    final_preds = []
    for i, rf_label in enumerate(rf_labels):
        if rf_label == "Normal":
            final_preds.append("Normal")
        else:
            xgb_prob = xgb_model.predict_proba(df_model.iloc[[i]])[0]
            xgb_pred = np.argmax(xgb_prob)
            xgb_class_names = ['Normal', 'Protocol Manipulation', 'SQL Injection', 'Dictionary-based Password Attack']
            xgb_label = xgb_class_names[xgb_pred]
            final_preds.append("SQL Injection" if xgb_label == "Normal" else xgb_label)

    # Tambahkan hasil ke DataFrame asli
    df_processed["predicted_label"] = final_preds

    # Return CSV hasil
    output = io.StringIO()
    df_processed.to_csv(output, index=False)
    output.seek(0)

    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=predicted_{file.filename}"}
    )
