# Vulnera - Vulnerability Detection System

Vulnera adalah sistem deteksi kerentanan berbasis machine learning yang dirancang untuk menganalisis traffic jaringan dan mengidentifikasi potensi serangan cyber. Sistem ini menggunakan model hybrid yang menggabungkan BERT (Bidirectional Encoder Representations from Transformers) dengan TensorFlow untuk mendeteksi anomali dan serangan dalam data jaringan.

## 🏗️ Struktur Project

```
Vulnera/
├── app.js                          # Entry point aplikasi Express.js
├── package.json                    # Dependencies dan konfigurasi Node.js
├── config/                         # Konfigurasi aplikasi
│   ├── database.js                # Konfigurasi database
│   ├── environment.js             # Konfigurasi environment variables
│   ├── index.js                   # Konfigurasi utama
│   ├── mlBackend.js               # Konfigurasi ML backend
│   ├── multer.js                  # Konfigurasi file upload
│   ├── security.js                # Konfigurasi keamanan
│   └── server.js                  # Konfigurasi server
├── controllers/                    # Business logic
│   ├── authController.js          # Kontroler autentikasi
│   └── uploadController.js        # Kontroler upload dan analisis CSV
├── middleware/                     # Middleware Express.js
│   └── auth.js                    # Middleware autentikasi
├── routes/                         # Routing aplikasi
│   ├── adminRoutes.js             # Route untuk admin
│   ├── authRoutes.js              # Route autentikasi
│   └── pageRoutes.js              # Route halaman utama
├── utils/                          # Utility functions
│   └── db.js                      # Koneksi dan model database
├── views/                          # Template EJS
│   ├── admin/                     # Halaman admin
│   ├── layouts/                    # Layout utama
│   ├── homepage.ejs               # Halaman utama
│   ├── login.ejs                  # Halaman login
│   └── register.ejs               # Halaman registrasi
├── public/                         # Static files
│   ├── css/                       # Stylesheet
│   ├── js/                        # JavaScript client-side
│   ├── img/                       # Gambar
│   └── uploads/                   # File upload temporary
├── ml-service/                     # Machine Learning Service
│   ├── backend/                    # FastAPI backend
│   │   ├── app.py                 # API ML service
│   │   ├── requirements.txt       # Python dependencies
│   │   └── env/                   # Python virtual environment
│   ├── gemini.js                  # Gemini AI integration
│   └── model/                      # Model ML yang sudah dilatih
│       ├── artifacts/             # Model artifacts
│       │   ├── label_mappings.json
│       │   ├── scaler.joblib
│       │   ├── target_encoder.joblib
│       │   └── tokenizer/         # BERT tokenizer
│       ├── final_model_tf/        # TensorFlow saved model
│       └── download_model.sh      # Script download model
└── data.json                      # Sample data
```

## ✨ Fitur Utama

### 🔐 Sistem Autentikasi
- Registrasi dan login user
- Session management dengan Express.js
- Role-based access control (Admin/User)
- Password hashing dengan bcrypt

### 📊 Upload dan Analisis CSV
- Upload file CSV melalui interface web
- Validasi file (format, ukuran, ekstensi)
- Integrasi dengan ML backend untuk analisis
- Penyimpanan hasil analisis ke MongoDB

### 🤖 Machine Learning Integration
- **Hybrid BERT-TensorFlow Model**: Deteksi anomali dan klasifikasi serangan cyber
- **BERT Tokenizer**: Pemrosesan teks untuk analisis User-Agent dan URL
- **Feature Engineering**: Ekstraksi fitur otomatis dari data jaringan
- **Real-time Prediction**: Prediksi real-time dengan confidence score
- **Multi-modal Processing**: Kombinasi fitur numerik, kategorikal, dan teks

### 📈 Dashboard Analytics
- Visualisasi data serangan vs normal traffic
- Distribusi HTTP methods dan status codes
- Persentase serangan terdeteksi
- Monitoring real-time traffic jaringan

### 🎨 User Interface
- Responsive design dengan Bootstrap dan Tailwind CSS
- Admin panel untuk manajemen data
- User dashboard untuk monitoring
- Flash messages untuk feedback

## 🚀 Setup dan Instalasi

### Prerequisites
- Node.js (v16 atau lebih baru)
- Python 3.8+
- MongoDB
- npm atau yarn

### 1. Clone Repository
```bash
git clone <repository-url>
cd Vulnera
```

### 2. Install Dependencies Node.js
```bash
npm install
```

### 3. Install Dependencies Python

**Linux/macOS**

```bash
cd ml-service/backend
python -m venv env
source env/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell/Command Prompt)**

```powershell
cd ml-service\backend
python -m venv env
.\env\Scripts\activate
pip install -r requirements.txt
```

### 4. Download Model
```bash
cd ml-service/model
./download_model.sh
```

### 5. Setup Environment Variables
```bash
cp .env.example .env
```

### 6. Setup Database
```bash
# Start MongoDB service
sudo systemctl start mongodb

# Atau gunakan MongoDB Atlas untuk cloud database
```

### 7. Start Services

#### Start ML Backend (Python FastAPI)
```bash
cd ml-service/backend
uvicorn app:app --reload --port 8000
```

#### Start Web Application (Node.js)
```bash
# Development mode
npm run dev

# Production mode
npm start
```

### 8. Akses Aplikasi
- Web App: http://localhost:3000
- ML API: http://localhost:8000
- API Docs: http://localhost:8000/docs

## 🔧 Cara Kerja

### 1. Flow Upload dan Analisis
```
User Upload CSV → Validasi File → Kirim ke ML Backend → 
Feature Extraction → Model Prediction → Simpan ke MongoDB → 
Tampilkan Dashboard
```

### 2. Machine Learning Pipeline
- **Feature Extraction**: Ekstraksi fitur dari data jaringan
  - Port categorization (well-known, registered, dynamic)
  - Bot detection dari User-Agent
  - Suspicious pattern detection
  - Browser type classification
  - URL security analysis
  - File extension categorization
  - HTTP status code analysis
  - URL depth dan parameter counting

- **Model Prediction**: 
  - Hybrid BERT-TensorFlow model untuk deteksi anomali dan klasifikasi
  - BERT tokenizer untuk pemrosesan teks (User-Agent, URL, HTTP messages)
  - Multi-modal input processing (numerik, kategorikal, teks)
  - Output: predicted_label + confidence_score

### 3. Data Flow
```
CSV Input → Pandas DataFrame → Feature Engineering → 
ML Models → Prediction Results → MongoDB Storage → 
Dashboard Visualization
```

## 📦 Dependencies

### Backend Dependencies
- **Express.js**: Web framework
- **MongoDB + Mongoose**: Database dan ODM
- **Multer**: File upload handling
- **Express-session**: Session management
- **Bcrypt**: Password hashing
- **EJS**: Template engine
- **Axios**: HTTP client untuk ML API
- **Connect-mongo**: MongoDB session store
- **Express-validator**: Input validation
- **Joi**: Schema validation
- **CSV-parser**: CSV file processing

### Frontend Dependencies
- **Bootstrap**: CSS framework
- **Tailwind CSS**: Utility-first CSS
- **Chart.js**: Data visualization

### Machine Learning Dependencies
- **FastAPI**: Python web framework
- **Pandas**: Data manipulation
- **NumPy**: Numerical computing
- **TensorFlow**: Deep learning framework
- **Transformers**: BERT model dan tokenizer
- **Scikit-learn**: ML algorithms
- **Joblib**: Model serialization
- **Category-encoders**: Categorical feature encoding
- **Imbalanced-learn**: Handling imbalanced datasets

### Development Dependencies
- **Nodemon**: Auto-restart development server
- **PostCSS**: CSS processing
- **Autoprefixer**: CSS vendor prefixes

## 🛠️ Konfigurasi

### Database Configuration
```javascript
// config/database.js
const { Users, Dataset } = require("../utils/db.js");
```

### ML Backend Configuration
```javascript
// config/mlBackend.js
const ML_BACKEND_URL = process.env.ML_BACKEND_URL || 'http://localhost:8000';
```

### File Upload Configuration
```javascript
// config/multer.js
const upload = multer({
  dest: 'public/uploads/',
  fileFilter: (req, file, cb) => {
    // Validasi file CSV
  }
});
```

## 📊 API Endpoints

### Web Application
- `GET /` - Landing page
- `GET /login` - Login page
- `GET /register` - Registration page
- `GET /admin/dashboard` - Admin dashboard
- `GET /admin/uploadcsv` - CSV upload page

### Machine Learning API
- `POST /predict-csv/` - CSV prediction endpoint
- `GET /health/` - Health check endpoint
- `GET /status/` - Status check endpoint

## 🔒 Security Features

- Password hashing dengan bcrypt
- Session-based authentication
- Input validation dan sanitization
- File upload security
- CSRF protection
- Rate limiting (dapat ditambahkan)

## 🚨 Troubleshooting

### Common Issues
1. **MongoDB Connection Error**: Pastikan MongoDB service berjalan
2. **ML Backend Error**: Cek apakah FastAPI service berjalan di port 8000
3. **File Upload Error**: Pastikan folder uploads memiliki permission write
4. **Model Loading Error**: Pastikan model artifacts ada di folder ml-service/model/artifacts/
5. **BERT Tokenizer Error**: Pastikan tokenizer sudah didownload di ml-service/model/artifacts/tokenizer/
6. **TensorFlow Model Error**: Pastikan model TensorFlow ada di ml-service/model/final_model_tf/

### Debug Mode
```bash
# Enable debug logging
DEBUG=* npm run dev

# Check ML backend logs
cd ml-service/backend
uvicorn app:app --reload --log-level debug
```

## 📝 License

ISC License

## 👥 Contributing

1. Fork repository
2. Buat feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push ke branch (`git push origin feature/AmazingFeature`)
5. Buat Pull Request

## 📞 Support

Untuk pertanyaan dan dukungan, silakan buat issue di repository atau hubungi tim development.

---

**Vulnera** - Protecting networks through intelligent vulnerability detection 🛡️
