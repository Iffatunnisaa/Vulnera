// utils/logger.js
const winston = require('winston');

// Tentukan format log kita
const logFormat = winston.format.printf(({ level, message, timestamp, ...metadata }) => {
  // Format: [YYYY-MM-DD HH:mm:ss] LEVEL: Pesan
  return `[${timestamp}] ${level.toUpperCase()}: ${message}`;
});

// Buat instance logger baru
const logger = winston.createLogger({
  level: 'info', // Catat semua pesan dari level 'info' ke atas (info, warn, error)
  format: winston.format.combine(
    winston.format.timestamp({
      format: 'YYYY-MM-DD HH:mm:ss'
    }),
    logFormat
  ),
  transports: [
    // Transport 1: Tulis semua log ke file /var/log/vulnera/auth.log
    new winston.transports.File({ 
        filename: '/var/log/vulnera/auth.log',
        level: 'info' // Hanya catat 'info' dan 'error' ke file ini
    }),
    
    // Transport 2: Tampilkan juga semua log di konsol (terminal)
    // Ini berguna untuk debugging saat menjalankan 'npm run dev'
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(), // Beri warna pada level log di konsol
        logFormat
      )
    })
  ],
  exitOnError: false, // Jangan keluar jika terjadi error saat logging
});

module.exports = logger;
