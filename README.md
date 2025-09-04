# Vulnera - Vulnerability Detection System

Vulnera adalah sistem deteksi kerentanan berbasis machine learning yang dirancang untuk menganalisis traffic jaringan dan mengidentifikasi potensi serangan cyber. Sistem ini menggunakan algoritma Random Forest dan XGBoost untuk mendeteksi anomali dan serangan dalam data jaringan.

## 🏗️ Struktur Project

```
Vulnera/
├── app.js                          # Entry point aplikasi Express.js
├── package.json                    # Dependencies dan konfigurasi Node.js
├── config/                         # Konfigurasi aplikasi
│   ├── database.js                # Konfigurasi database
│   ├── environment.js             # Konfigurasi environment variables
│   ├── mlBackend.js               # Konfigurasi ML backend
│   └── multer.js                  # Konfigurasi file upload
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
└── ml-service/                     # Machine Learning Service
    ├── backend/                    # FastAPI backend
    │   └── app.py                 # API ML service
    └── model/                      # Model ML yang sudah dilatih
        ├── random_forest_model.pkl # Model Random Forest
        └── xgboost_model.pkl      # Model XGBoost
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
- **Random Forest Model**: Deteksi anomali traffic jaringan
- **XGBoost Model**: Klasifikasi serangan cyber
- Feature extraction otomatis dari data jaringan
- Prediksi real-time dengan confidence score

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
```bash
cd ml-service/backend
pip install -r requirements.txt
```

### 4. Setup Environment Variables
Buat file `.env` di root directory:
```env
MONGODB_URL=mongodb://localhost:27017/vulnera
ML_BACKEND_URL=http://localhost:8000
SESSION_SECRET=your_session_secret_here
PORT=3000
```

### 5. Setup Database
```bash
# Start MongoDB service
sudo systemctl start mongod

# Atau gunakan MongoDB Atlas untuk cloud database
```

### 6. Start Services

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

### 7. Akses Aplikasi
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

- **Model Prediction**: 
  - Random Forest untuk deteksi anomali
  - XGBoost untuk klasifikasi serangan
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

### Frontend Dependencies
- **Bootstrap**: CSS framework
- **Tailwind CSS**: Utility-first CSS
- **Chart.js**: Data visualization

### Machine Learning Dependencies
- **FastAPI**: Python web framework
- **Pandas**: Data manipulation
- **NumPy**: Numerical computing
- **Scikit-learn**: ML algorithms
- **Joblib**: Model serialization

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
- `POST /predict` - CSV prediction endpoint
- `GET /health` - Health check endpoint

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
4. **Model Loading Error**: Pastikan file .pkl ada di folder model/

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
