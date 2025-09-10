# Configuration Documentation

This directory contains all configuration files for the Vulnera application, organized in a structured and maintainable way.

## File Structure

```
config/
├── index.js          # Main configuration index - exports all configs
├── server.js         # Server and application configuration
├── database.js       # Database connection and model configuration
├── environment.js    # Environment variables configuration
├── security.js       # Security settings and file upload configuration
├── mlBackend.js      # ML backend service configuration
├── multer.js         # File upload middleware configuration
├── config.md         # This documentation file
└── README.md         # Configuration README
```

## Configuration Files

### 1. `index.js` - Main Configuration Index
Centralizes all configuration modules for easy importing. This is the main entry point for all configuration.

**Usage:**
```javascript
const config = require('./config');
// Access any configuration: config.server.port, config.database.mongodb.url, etc.
```

### 2. `server.js` - Server Configuration
Contains server-related settings including:
- Environment settings (development/production)
- Port and host configuration
- Session configuration
- CORS settings
- Logging configuration

### 3. `database.js` - Database Configuration
Contains database-related settings including:
- MongoDB connection URL and options
- Database models
- Connection retry settings

### 4. `environment.js` - Environment Configuration
Contains environment variables configuration including:
- Environment variable loading and validation
- Default values for development
- Environment-specific settings
- Configuration validation helpers

### 5. `security.js` - Security Configuration
Contains security-related settings including:
- Password hashing (bcrypt) configuration
- JWT configuration (for future use)
- Rate limiting settings
- Security headers
- File upload security settings

### 6. `mlBackend.js` - ML Backend Configuration
Contains ML backend service settings including:
- Backend URL and endpoints
- Request timeout and retry settings
- File upload configuration for ML service
- Health check configuration
- Helper functions for ML service integration

### 7. `multer.js` - File Upload Configuration
Contains file upload middleware settings including:
- Storage configuration
- File filtering
- Error handling
- File size and type validation

## Environment Variables

All configuration values can be overridden using environment variables. See `.env.example` for a complete list of available environment variables.

### Required Environment Variables
- `MONGODB_URL` - MongoDB connection string
- `SESSION_SECRET` - Secret key for session management

### Optional Environment Variables
- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Environment (development/production)
- `ML_BACKEND_URL` - ML backend service URL
- `MAX_FILE_SIZE` - Maximum file upload size
- And many more... (see `.env.example`)

## Usage Examples

### Basic Usage
```javascript
const config = require('./config');

// Access server configuration
const port = config.server.port;
const sessionSecret = config.server.session.secret;

// Access database configuration
const mongoUrl = config.database.mongodb.url;

// Access ML backend configuration
const mlUrl = config.mlBackend.baseURL;
```

### Using ML Backend Helpers
```javascript
const config = require('./config');

// Get full endpoint URL
const predictUrl = config.mlBackend.getFullEndpoint('/predict-csv/');

// Validate uploaded file
const validation = config.mlBackend.validateFile(uploadedFile);
if (!validation.valid) {
  console.error(validation.error);
}

// Retry request with exponential backoff
const result = await config.mlBackend.retryRequest(async () => {
  return await makeMLRequest();
});
```

### Using Environment Configuration
```javascript
const config = require('./config');

// Access environment-specific settings
const isDevelopment = config.environment.NODE_ENV === 'development';
const isProduction = config.environment.NODE_ENV === 'production';

// Access environment variables
const mongoUrl = config.environment.MONGODB_URL;
const sessionSecret = config.environment.SESSION_SECRET;
```

### Using Multer Configuration
```javascript
const config = require('./config');

// Use multer upload middleware
app.post('/upload', config.multer.upload.single('file'), config.multer.handleMulterError, (req, res) => {
  // Handle uploaded file
});
```

## Configuration Validation

All configuration files include validation functions that:
- Check for required configuration values
- Warn about missing or invalid configurations
- Provide default values where appropriate
- Log configuration status on startup

## Best Practices

1. **Always use the centralized config**: Import from `./config` instead of individual files
2. **Use environment variables**: Override default values using `.env` file
3. **Validate configurations**: Check the console output for configuration warnings
4. **Document new configurations**: Add new environment variables to `.env.example`
5. **Keep secrets secure**: Never commit `.env` file to version control

## Adding New Configuration

1. Add new environment variables to `.env.example`
2. Create or update the appropriate configuration file
3. Add validation for the new configuration
4. Export the new configuration in `index.js`
5. Update the centralized configuration object
6. Update this documentation

## Troubleshooting

### Configuration Not Loading
- Check if `.env` file exists and contains required variables
- Verify environment variable names match exactly
- Check console output for validation warnings

### File Upload Issues
- Verify `UPLOAD_PATH` environment variable is set correctly
- Check file size limits in `security.js`
- Ensure upload directory exists and is writable

### Database Connection Issues
- Verify `MONGODB_URL` is correct
- Check MongoDB server is running
- Review connection options in `database.js`

### Environment Configuration Issues
- Check if `environment.js` is properly loaded
- Verify environment variables are set correctly
- Review environment-specific settings
