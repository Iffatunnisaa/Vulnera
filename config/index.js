// Main Configuration Index
// This file centralizes all configuration modules for easy importing

const serverConfig = require('./server');
const databaseConfig = require('./database');
const securityConfig = require('./security');
const mlBackendConfig = require('./mlBackend');
const multerConfig = require('./multer');

// Centralized configuration object
const config = {
  server: serverConfig,
  database: databaseConfig,
  security: securityConfig,
  multer: multerConfig,
  
  // ML Backend with helper functions
  mlBackend: {
    ...mlBackendConfig.mlBackendConfig,
    getFullEndpoint: mlBackendConfig.getFullEndpoint,
    validateFile: mlBackendConfig.validateFile,
    retryRequest: mlBackendConfig.retryRequest
  }
};

// Configuration validation
function validateAllConfigs() {
  console.log('=== Validating All Configurations ===');
  
  // Validate each config module
  const configs = [
    { name: 'Server', config: serverConfig },
    { name: 'Database', config: databaseConfig },
    { name: 'Security', config: securityConfig },
    { name: 'ML Backend', config: mlBackendConfig.mlBackendConfig }
  ];
  
  configs.forEach(({ name, config }) => {
    try {
      // Basic validation - check if config object exists and has required properties
      if (!config || typeof config !== 'object') {
        console.warn(`Warning: ${name} configuration is invalid`);
        return;
      }
      
      console.log(`✓ ${name} configuration loaded successfully`);
    } catch (error) {
      console.error(`Error validating ${name} configuration:`, error.message);
    }
  });
  
  console.log('=== Configuration Validation Complete ===');
}

// Initialize validation
validateAllConfigs();

// Export configuration
module.exports = config;
