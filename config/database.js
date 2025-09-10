// Database Configuration
require('dotenv').config();
const { Users, Dataset } = require("../utils/db.js");

const databaseConfig = {
  // MongoDB connection
  mongodb: {
    url: process.env.MONGODB_URL || 'mongodb://localhost:27017/vulnera',
    options: {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000,
      socketTimeoutMS: 45000,
      bufferMaxEntries: 0,
      bufferCommands: false
    }
  },
  
  // Database models
  models: {
    Users,
    Dataset
  },
  
  // Connection retry settings
  retry: {
    maxRetries: 3,
    retryDelay: 1000
  }
};

// Validation function
function validateDatabaseConfig() {
  if (!databaseConfig.mongodb.url) {
    console.warn('Warning: MONGODB_URL is not set, using default value');
  }
}

// Initialize validation
validateDatabaseConfig();

module.exports = databaseConfig;
