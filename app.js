const express = require("express");
const path = require("path");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const flash = require("connect-flash");
const morgan = require("morgan");
const fs = require("fs");

// Import centralized configuration
const config = require("./config");

// Import routes
const pageRoutes = require("./routes/pageRoutes");
const authRoutes = require("./routes/authRoutes");
const adminRoutes = require("./routes/adminRoutes");

const app = express();
const port = config.server.port;

// Buat stream penulisan log. 'a' berarti append (tambahkan), tidak menimpa.
const accessLogStream = fs.createWriteStream(path.join('/var/log/vulnera', 'access.log'), { flags: 'a' });

// Setup middleware morgan untuk mencatat semua permintaan ke file
// Format 'combined' adalah format standar Apache yang sangat informatif.
app.use(morgan('combined', { stream: accessLogStream }));

// Middleware untuk parsing data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Setup cookie-parser
app.use(cookieParser());

// Setup session
app.use(
  session({
    secret: config.server.session.secret,
    resave: config.server.session.resave,
    saveUninitialized: config.server.session.saveUninitialized,
    cookie: config.server.session.cookie
  })
);

// Setup flash 
app.use(flash());

// Security headers
app.use((req, res, next) => {
  Object.entries(config.security.headers).forEach(([key, value]) => {
    res.setHeader(key, value);
  });
  next();
});

// Setup EJS
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public"));

// Middleware global untuk flash message
app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  res.locals.user = req.session.user;
  next();
});

// Routes
app.use("/", pageRoutes);
app.use("/", authRoutes);
app.use("/admin", adminRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).render("error", { 
    title: "Error",
    message: "Terjadi kesalahan pada server" 
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).render("error", { 
    title: "404 Not Found",
    message: "Halaman tidak ditemukan" 
  });
});

app.listen(port, () => {
  console.log('=== Vulnera Server Started ===');
  console.log(`Environment: ${config.server.env}`);
  console.log(`Server running at http://${config.server.host}:${port}`);
  console.log(`ML Backend URL: ${config.mlBackend.baseURL}`);
  console.log(`Database URL: ${config.database.mongodb.url}`);
  console.log('==============================');
});
