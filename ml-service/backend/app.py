import io
import os
import json
import joblib
import pandas as pd
import numpy as np
import tensorflow as tf
from fastapi import FastAPI, File, UploadFile
from fastapi.responses import StreamingResponse
import category_encoders as ce
from transformers import BertModel, BertTokenizer, TFBertModel


# =================
# MEMUAT ARTIFACTS 
# =================
# Definisikan path dan variabel global
ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "..", "model", "artifacts")
MODEL_DIR = os.path.join(os.path.dirname(__file__), "..", "model", "final_model_tf")
MODEL_NAME = "google-bert/bert-base-uncased" 
MAX_LEN = 64

# Debug: Print the artifacts directory path
print(f"Artifacts directory: {ARTIFACTS_DIR}")
print(f"Artifacts directory exists: {os.path.exists(ARTIFACTS_DIR)}")

# Check if artifacts directory exists
if not os.path.exists(ARTIFACTS_DIR):
    raise FileNotFoundError(f"Artifacts directory not found: {ARTIFACTS_DIR}")

# Muat model Keras
model = tf.saved_model.load(MODEL_DIR)

# Muat tokenizer
print("Memuat tokenizer...")
tokenizer_path = os.path.join(ARTIFACTS_DIR, "tokenizer")
print(f"Tokenizer path: {tokenizer_path}")
print(f"Tokenizer directory exists: {os.path.exists(tokenizer_path)}")
tokenizer = BertTokenizer.from_pretrained(tokenizer_path)

# Muat scaler dan encoder
print("Memuat scaler dan encoder...")
scaler_path = os.path.join(ARTIFACTS_DIR, "scaler.joblib")
encoder_path = os.path.join(ARTIFACTS_DIR, "target_encoder.joblib")
print(f"Scaler path: {scaler_path}")
print(f"Encoder path: {encoder_path}")
print(f"Scaler file exists: {os.path.exists(scaler_path)}")
print(f"Encoder file exists: {os.path.exists(encoder_path)}")
scaler = joblib.load(scaler_path)
encoder = joblib.load(encoder_path)

# Muat pemetaan label
print("Memuat pemetaan label...")
label_mappings_path = os.path.join(ARTIFACTS_DIR, "label_mappings.json")
print(f"Label mappings path: {label_mappings_path}")
print(f"Label mappings file exists: {os.path.exists(label_mappings_path)}")
with open(label_mappings_path, 'r') as f:
    label_mappings = json.load(f)
id2label = label_mappings['id2label']

# Definisikan kembali daftar fitur yang digunakan saat training
numeric_features = [
    "src_port", "response_http_status_code", "response_content_length",
    "ua_length", "url_length", "url_param_count", "url_depth"
]
categorical_features = [
    "request_http_method", "request_http_protocol", "response_http_protocol",
    "src_port_category", "ua_browser_type", "file_extension_category",
    "status_code_category", "response_status_category"
]
text_features = ["request_http_request", "request_user_agent", "response_http_status_message"]

print("Semua artifacts berhasil dimuat. Aplikasi siap menerima permintaan.")
# Inisialisasi Aplikasi FastAPI Anda
app = FastAPI()

# =============================
# Fungsi Feature Extraction
# =============================
def categorize_port(port):
    try:
        port = int(port)
    except:
        return "unknown"
    if port <= 1023:
        return "well_known"
    elif 1023 < port <= 49151:
        return "registered"
    else:
        return "dynamic"

def detect_bot_user_agent(ua):
    if pd.isna(ua):
        return 0
    bot_keywords = ['bot','crawler','spider','scraper','curl','wget', 'fuzz faster'
                    'python-requests','libwww','java/','apache-httpclient']
    return int(any(keyword in ua.lower() for keyword in bot_keywords))

def detect_suspicious_user_agent(ua):
    if pd.isna(ua):
        return 0
    suspicious_patterns = ['<script','union','select','drop','insert',
                           'delete','../','etc/passwd','cmd.exe','null']
    return int(any(pattern in ua.lower() for pattern in suspicious_patterns))

def extract_browser_type(ua):
    if pd.isna(ua):
        return "Other"
    ua_lower = ua.lower()
    if 'chrome' in ua_lower and 'edge' not in ua_lower:
        return 'Chrome'
    elif 'firefox' in ua_lower:
        return 'Firefox'
    elif 'safari' in ua_lower and 'chrome' not in ua_lower:
        return 'Safari'
    elif 'edge' in ua_lower:
        return 'Edge'
    elif any(bot_word in ua_lower for bot_word in ['bot','crawler','spider']):
        return 'Bot'
    elif any(tool in ua_lower for tool in ['curl','wget','python', 'sqlmap', 'fuzz faster', 'hydra']):
        return 'Tool'
    else:
        return 'Other'

def detect_suspicious_url_keywords(url):
    if pd.isna(url):
        return 0
    url_lower = url.lower()
    suspicious_keywords = [
        'union','select','drop','insert','delete','update','from','where',
        '../','..\\','/etc/','/passwd','/shadow',
        'script','eval','exec','system','cmd.exe',
        'admin','login','wp-admin','phpmyadmin',
        '.php','.asp','.jsp','.cgi'
    ]
    return int(any(keyword in url_lower for keyword in suspicious_keywords))

def extract_file_extension(url):
    if pd.isna(url):
        return 'none'
    try:
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
    image_extensions = ['jpg','jpeg','png','gif','svg','bmp','tiff','webp']
    script_extensions = ['js','php','asp','html','css']
    document_extensions = ['pdf','txt','doc','docx','xls','xlsx']
    sql_extensions = ['sql', 'sqlmap']

    if not extension or extension == 'none':
        return 'None'
    ext = extension.lower()
    if ext in image_extensions:
        return 'Image'
    elif ext in script_extensions:
        return 'Script/Web Dynamic'
    elif ext in document_extensions:
        return 'Document/Text'
    elif ext in sql_extensions:
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
    elif status_message in ["Moved Permanently","Found"]:
        return "Redirection"
    elif status_message in ["Bad Request","Method Not Allowed","Forbidden","Not Found"]:
        return "Client Error"
    elif status_message in ["Internal Server Error","Not Implemented","Too Many Requests"]:
        return "Server Error"
    else:
        return "Other"

# =============================
# Preprocess DataFrame (versi inline)
# =============================
def extract_features(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    
    # Impute numeric dengan mode
    for col in df.select_dtypes(include=["number"]).columns:
        df[col] = df[col].fillna(df[col].mode()[0])

    # Impute categorical dengan 'unknown'
    for col in df.select_dtypes(include=["object"]).columns:
        df[col] = df[col].fillna("unknown")

    df.dropna(how="all", inplace=True)
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
    
    # Process timestamp-related columns
    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=False)
        df['hour'] = df['timestamp'].dt.hour
        df['day'] = df['timestamp'].dt.day
        df['weekday'] = df['timestamp'].dt.day_name()
        df['month'] = df['timestamp'].dt.month_name()

    # Process 'src_port' column
    if 'src_port' in df.columns:
        df['src_port_category'] = df['src_port'].apply(categorize_port)

    # Process 'request_user_agent' column
    if 'request_user_agent' in df.columns:
        df['ua_length'] = df['request_user_agent'].astype(str).str.len()
        df['ua_is_bot'] = df['request_user_agent'].apply(detect_bot_user_agent)
        df['ua_is_suspicious'] = df['request_user_agent'].apply(detect_suspicious_user_agent)
        df['ua_browser_type'] = df['request_user_agent'].apply(extract_browser_type)

    # Process 'request_http_request' column (URL-related features)
    if 'request_http_request' in df.columns:
        df['url_length'] = df['request_http_request'].astype(str).str.len()
        df['url_param_count'] = (df['request_http_request'].astype(str).str.count('&') +
                                 df['request_http_request'].astype(str).str.count('='))
        df['url_has_query'] = df['request_http_request'].astype(str).str.contains(r'\?', regex=True).astype(int)
        df['url_depth'] = df['request_http_request'].astype(str).str.count('/')
        df['url_has_suspicious_keywords'] = df['request_http_request'].apply(detect_suspicious_url_keywords)
        df['url_file_extension'] = df['request_http_request'].apply(extract_file_extension)
        df['file_extension_category'] = df['url_file_extension'].apply(categorize_file_extension)

    # Process 'response_http_status_code' column
    if 'response_http_status_code' in df.columns:
        df['response_http_status_code'] = pd.to_numeric(df['response_http_status_code'], errors='coerce').fillna(0).astype(int)
        df['status_code_category'] = df['response_http_status_code'].apply(categorize_status_code)
        df['is_error_response'] = (df['response_http_status_code'] >= 400).astype(int)
        df['is_server_error'] = (df['response_http_status_code'] >= 500).astype(int)
        df['is_client_error'] = ((df['response_http_status_code'] >= 400) &
                                 (df['response_http_status_code'] < 500)).astype(int)

    # Process 'response_http_status_message' column
    if 'response_http_status_message' in df.columns:
        df['response_status_category'] = df['response_http_status_message'].apply(categorize_status_message)

    # Process 'request_http_method' column
    if 'request_http_method' in df.columns:
        main_methods = ["GET","POST","PUT"]
        df['request_http_method'] = df['request_http_method'].apply(
            lambda x: x if x in main_methods else "OTHER"
        )

    df.drop_duplicates(inplace=True)
    
    # Return DataFrame with extracted features
    return df

# =============================
# Endpoint FastAPI
# =============================
@app.post("/predict-csv/")
async def predict_csv(file: UploadFile = File(...)):
    if not file.filename.endswith(".csv"):
        return {"error": "File harus dalam format CSV"}
    
    contents = await file.read()
    df = pd.read_csv(io.BytesIO(contents))

    df_processed = extract_features(df) 

    # df_model adalah DataFrame yang siap untuk pra-pemrosesan model
    df_model = df_processed.copy()

    # Gabungkan kolom teks
    print("Menggabungkan fitur teks...")
    X_text_new = df_model[text_features].fillna('').apply(lambda x: ' '.join(x), axis=1).tolist()

    # Encoding fitur kategorikal menggunakan encoder yang sudah di-load
    print("Melakukan encoding pada fitur kategorikal...")
    df_model[categorical_features] = encoder.transform(df_model[categorical_features])

    # Scaling fitur numerik & kategorikal menggunakan scaler yang sudah di-load
    print("Melakukan scaling pada fitur numerik...")
    features_to_scale = numeric_features + categorical_features
    X_numcat_new_scaled = scaler.transform(df_model[features_to_scale])
    
    # Ganti NaN/inf jika ada setelah transformasi
    X_numcat_new_scaled = np.nan_to_num(X_numcat_new_scaled)

    # Tokenisasi teks
    print("Melakukan tokenisasi teks...")
    new_encodings = tokenizer(
        X_text_new,
        truncation=True,
        padding="max_length",
        max_length=MAX_LEN,
        return_tensors="np"
    )

    # Membuat Prediksi
    print("Membuat prediksi...")
    infer = model.signatures['serving_default']  # Access the serving signature
    model_inputs = {
        'input_ids': tf.convert_to_tensor(new_encodings['input_ids'], dtype=tf.int32),
        'attention_mask': tf.convert_to_tensor(new_encodings['attention_mask'], dtype=tf.int32),
        'numcat_input': tf.convert_to_tensor(X_numcat_new_scaled, dtype=tf.float32)
    }
    predictions = infer(**model_inputs)
    # Extract the output tensor (adjust key based on your model's output signature)
    predictions = predictions['output_0']  

    # Post-processing Hasil Prediksi
    # Ambil ID kelas dengan probabilitas tertinggi
    print("Mengambil ID kelas dengan probabilitas tertinggi...")
    predicted_ids = np.argmax(predictions, axis=-1)
    
    # Konversi ID kembali ke label asli
    print("Mengkonversi ID kembali ke label asli...")
    predicted_labels = [id2label[str(id)] for id in predicted_ids]
    
    # Tambahkan hasil prediksi ke DataFrame output
    df_processed["predicted_label"] = predicted_labels

    print("Mengirim hasil prediksi...")

    output = io.StringIO()
    df_processed.to_csv(output, index=False)
    output.seek(0)

    print("Mengirimkan hasil prediksi...")
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=predicted_{file.filename}"}
    )