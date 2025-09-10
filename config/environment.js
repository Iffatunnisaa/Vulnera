// Konfigurasi environment untuk aplikasi
require('dotenv').config();

const environment = {
  // Database Configuration
  mongodb: {
    url: process.env.MONGODB_URL
  },

  // Server Configuration
  server: {
    port: process.env.PORT || 3000,
    sessionSecret: process.env.SESSION_SECRET || 'rahasia'
  },

  // ML Backend Configuration
  mlBackend: {
    url: process.env.ML_BACKEND_URL || 'http://localhost:8000',
    timeout: parseInt(process.env.ML_BACKEND_TIMEOUT) || 300000, // 5 menit
    maxRetries: parseInt(process.env.ML_BACKEND_MAX_RETRIES) || 3,
    retryDelay: parseInt(process.env.ML_BACKEND_RETRY_DELAY) || 1000
  },

  // File Upload Configuration
  upload: {
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 52428800, // 50MB
    uploadPath: process.env.UPLOAD_PATH || 'public/uploads',
    allowedFormats: ['.csv']
  },

  // Security Configuration
  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS) || 10
  }
};

// Validasi konfigurasi
function validateConfig() {
  const required = ['mongodb.url', 'server.port', 'mlBackend.url'];
  
  for (const key of required) {
    const value = key.split('.').reduce((obj, k) => obj?.[k], environment);
    if (!value) {
      console.warn(`Warning: ${key} is not set, using default value`);
    }
  }
}

// Log konfigurasi
function logConfig() {
  console.log('=== Environment Configuration ===');
  console.log(`Server Port: ${environment.server.port}`);
  console.log(`MongoDB URL: ${environment.mongodb.url}`);
  console.log(`ML Backend URL: ${environment.mlBackend.url}`);
  console.log(`Upload Max Size: ${environment.upload.maxFileSize / (1024 * 1024)}MB`);
  console.log('================================');
}

// Initialize config
validateConfig();
logConfig();

module.exports = environment;
