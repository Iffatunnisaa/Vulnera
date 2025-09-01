// Konfigurasi untuk backend ML
const mlBackendConfig = {
  // URL backend ML
  baseURL: process.env.ML_BACKEND_URL || 'http://localhost:8000',
  
  // Endpoint untuk prediksi CSV
  predictCSVEndpoint: '/predict-csv/',
  
  // Timeout untuk request (dalam milliseconds)
  timeout: 300000, // 5 menit
  
  // Retry configuration
  maxRetries: 3,
  retryDelay: 1000, // 1 detik
  
  // File upload configuration
  maxFileSize: 50 * 1024 * 1024, // 50MB
  
  // Supported file types
  supportedFormats: ['.csv'],
  
  // Headers untuk request
  headers: {
    'User-Agent': 'Vulnera-WebApp/1.0.0',
    'Accept': 'text/csv, application/json',
  }
};

// Fungsi untuk mendapatkan full URL endpoint
function getFullEndpoint(endpoint) {
  return `${mlBackendConfig.baseURL}${endpoint}`;
}

// Fungsi untuk validasi file
function validateFile(file) {
  // Cek ukuran file
  if (file.size > mlBackendConfig.maxFileSize) {
    return {
      valid: false,
      error: `File terlalu besar. Maksimal ${mlBackendConfig.maxFileSize / (1024 * 1024)}MB`
    };
  }
  
  // Cek format file
  const fileExtension = file.originalname.toLowerCase().substring(file.originalname.lastIndexOf('.'));
  if (!mlBackendConfig.supportedFormats.includes(fileExtension)) {
    return {
      valid: false,
      error: `Format file tidak didukung. Gunakan: ${mlBackendConfig.supportedFormats.join(', ')}`
    };
  }
  
  return { valid: true };
}

// Fungsi untuk retry request
async function retryRequest(requestFn, maxRetries = mlBackendConfig.maxRetries) {
  let lastError;
  
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await requestFn();
    } catch (error) {
      lastError = error;
      console.log(`Attempt ${attempt} failed:`, error.message);
      
      if (attempt < maxRetries) {
        await new Promise(resolve => setTimeout(resolve, mlBackendConfig.retryDelay * attempt));
      }
    }
  }
  
  throw lastError;
}

module.exports = {
  mlBackendConfig,
  getFullEndpoint,
  validateFile,
  retryRequest
};
