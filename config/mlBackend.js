// ML Backend Configuration
require('dotenv').config();

const mlBackendConfig = {
  // URL backend ML
  baseURL: process.env.ML_BACKEND_URL || 'http://localhost:8000',
  
  // Endpoints
  endpoints: {
    predictCSV: '/predict-csv/',
    health: '/health/',
    status: '/status/'
  },
  
  // Request configuration
  request: {
    timeout: parseInt(process.env.ML_BACKEND_TIMEOUT) || 300000, // 5 menit
    maxRetries: parseInt(process.env.ML_BACKEND_MAX_RETRIES) || 3,
    retryDelay: parseInt(process.env.ML_BACKEND_RETRY_DELAY) || 1000, // 1 detik
    headers: {
      'User-Agent': 'Vulnera-WebApp/1.0.0',
      'Accept': 'text/csv, application/json',
      'Content-Type': 'multipart/form-data'
    }
  },
  
  // File upload configuration
  upload: {
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 50 * 1024 * 1024, // 50MB
    supportedFormats: ['.csv'],
    supportedMimeTypes: ['text/csv']
  },
  
  // Health check configuration
  healthCheck: {
    interval: 30000, // 30 seconds
    timeout: 5000, // 5 seconds
    enabled: true
  }
};

// Fungsi untuk mendapatkan full URL endpoint
function getFullEndpoint(endpoint) {
  return `${mlBackendConfig.baseURL}${endpoint}`;
}

// Fungsi untuk validasi file
function validateFile(file) {
  // Cek ukuran file
  if (file.size > mlBackendConfig.upload.maxFileSize) {
    return {
      valid: false,
      error: `File terlalu besar. Maksimal ${mlBackendConfig.upload.maxFileSize / (1024 * 1024)}MB`
    };
  }
  
  // Cek format file
  const fileExtension = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
  if (!mlBackendConfig.upload.supportedFormats.includes(fileExtension)) {
    return {
      valid: false,
      error: `Format file tidak didukung. Gunakan: ${mlBackendConfig.upload.supportedFormats.join(', ')}`
    };
  }
  
  // Cek MIME type
  if (!mlBackendConfig.upload.supportedMimeTypes.includes(file.mimetype)) {
    return {
      valid: false,
      error: `Tipe file tidak didukung. Gunakan: ${mlBackendConfig.upload.supportedMimeTypes.join(', ')}`
    };
  }
  
  return { valid: true };
}

// Fungsi untuk retry request
async function retryRequest(requestFn, maxRetries = mlBackendConfig.request.maxRetries) {
  let lastError;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await requestFn();
    } catch (error) {
      lastError = error;
      console.log(`Attempt ${attempt} failed:`, error.message);
      
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, mlBackendConfig.request.retryDelay * attempt));
      }
    }
  }
  
  throw lastError;
}

// Validation function
function validateMLBackendConfig() {
  const required = ['baseURL', 'request.timeout', 'request.maxRetries'];
  
  for (const key of required) {
    const value = key.split('.').reduce((obj, k) => obj?.[k], mlBackendConfig);
    if (!value) {
      console.warn(`Warning: mlBackend.${key} is not set, using default value`);
    }
  }
}

// Initialize validation
validateMLBackendConfig();

module.exports = {
  mlBackendConfig,
  getFullEndpoint,
  validateFile,
  retryRequest
};
