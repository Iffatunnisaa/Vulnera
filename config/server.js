// Server Configuration
require('dotenv').config();

const serverConfig = {
  // Environment
  env: process.env.NODE_ENV || 'development',
  
  // Server settings
  port: parseInt(process.env.PORT) || 3000,
  host: process.env.HOST || 'localhost',
  
  // Session configuration
  session: {
    secret: process.env.SESSION_SECRET || 'rahasia',
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
  },
  
  // CORS configuration
  cors: {
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
    credentials: true
  },
  
  // Logging configuration
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    file: process.env.LOG_FILE || 'logs/app.log'
  }
};

// Validation function
function validateServerConfig() {
  const required = ['port', 'session.secret'];
  
  for (const key of required) {
    const value = key.split('.').reduce((obj, k) => obj?.[k], serverConfig);
    if (!value) {
      console.warn(`Warning: server.${key} is not set, using default value`);
    }
  }
}

// Initialize validation
validateServerConfig();

module.exports = serverConfig;
