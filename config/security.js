// Security Configuration
require('dotenv').config();

const securityConfig = {
  // Password hashing
  bcrypt: {
    rounds: parseInt(process.env.BCRYPT_ROUNDS) || 10
  },
  
  // JWT Configuration (for future use)
  jwt: {
    secret: process.env.JWT_SECRET || 'your-jwt-secret-key-here',
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    issuer: 'vulnera-app',
    audience: 'vulnera-users'
  },
  
  // Rate limiting
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.'
  },
  
  // Security headers
  headers: {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains'
  },
  
  // File upload security
  upload: {
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 52428800, // 50MB
    allowedMimeTypes: ['text/csv'],
    allowedExtensions: ['.csv'],
    uploadPath: process.env.UPLOAD_PATH || 'public/uploads'
  }
};

// Validation function
function validateSecurityConfig() {
  const required = ['bcrypt.rounds'];
  
  for (const key of required) {
    const value = key.split('.').reduce((obj, k) => obj?.[k], securityConfig);
    if (!value) {
      console.warn(`Warning: security.${key} is not set, using default value`);
    }
  }
}

// Initialize validation
validateSecurityConfig();

module.exports = securityConfig;
