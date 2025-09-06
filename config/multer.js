const multer = require("multer");
const path = require("path");
const securityConfig = require("./security");

// Konfigurasi Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, securityConfig.upload.uploadPath); // folder simpan CSV
  },
  filename: (req, file, cb) => {
    // Generate unique filename with timestamp
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  }
});

// File filter function
const fileFilter = (req, file, cb) => {
  // Check MIME type
  if (!securityConfig.upload.allowedMimeTypes.includes(file.mimetype)) {
    return cb(new Error(`Hanya file ${securityConfig.upload.allowedMimeTypes.join(', ')} yang diizinkan!`));
  }
  
  // Check file extension
  const fileExtension = path.extname(file.originalname).toLowerCase();
  if (!securityConfig.upload.allowedExtensions.includes(fileExtension)) {
    return cb(new Error(`Hanya file ${securityConfig.upload.allowedExtensions.join(', ')} yang diizinkan!`));
  }
  
  cb(null, true);
};

// Multer configuration
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: securityConfig.upload.maxFileSize,
    files: 1 // Only allow one file at a time
  }
});

// Error handling middleware for multer
const handleMulterError = (err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        error: `File terlalu besar. Maksimal ${securityConfig.upload.maxFileSize / (1024 * 1024)}MB`
      });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(400).json({
        error: 'Hanya satu file yang diizinkan per upload'
      });
    }
  }
  
  if (err) {
    return res.status(400).json({
      error: err.message
    });
  }
  
  next();
};

module.exports = {
  upload,
  handleMulterError
};
