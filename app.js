const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const { Users } = require("./utils/db.js");
const { Dataset } = require("./utils/db.js");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const flash = require("connect-flash");
const ejs = require("ejs");

const app = express();
const port = 3000;

// Middleware untuk parsing data
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// setup cookie-parser
app.use(cookieParser());

// setup session
app.use(
  session({
    secret: "rahasia", // ganti dengan secret yang lebih kuat
    resave: false,
    saveUninitialized: true,
  })
);

// setup flash (HARUS setelah session)
app.use(flash());

// setup EJS
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public"));

// middleware global untuk flash message
app.use((req, res, next) => {
  res.locals.success_msg = req.flash("success_msg");
  res.locals.error_msg = req.flash("error_msg");
  res.locals.user = req.session.user;
  next();
});

const multer = require("multer");
const csv = require("csv-parser");
const fs = require("fs");
const { MongoClient } = require("mongodb");

// Konfigurasi Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "public/uploads/"); // folder simpan CSV
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname)); // nama unik
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    if (file.mimetype !== "text/csv") {
      return cb(new Error("Hanya file CSV yang diizinkan!"));
    }
    cb(null, true);
  }
});

// Route untuk halaman upload
app.get("/uploadcsv", isAuth, (req, res) => {
  res.render("admin/uploadcsv", { title: "Upload CSV" });
});

// Route untuk proses upload CSV
app.post("/upload", upload.single("csvFile"), isAuth, (req, res) => {
  try {
    const results = [];

    fs.createReadStream(req.file.path)
      .pipe(csv())
      .on("data", (data) => results.push(data))
      .on("end", async () => {
        try {
          // Simpan ke MongoDB pakai mongoose model
          await Dataset.insertMany(results);

          req.flash("success_msg", "CSV berhasil diupload dan disimpan ke MongoDB!");
          res.redirect("/uploadcsv");
        } catch (err) {
          console.error(err);
          req.flash("error_msg", "Gagal menyimpan ke database");
          res.redirect("/uploadcsv");
        }
      });
  } catch (err) {
    console.error(err);
    req.flash("error_msg", "Terjadi kesalahan saat upload");
    res.redirect("/uploadcsv");
  }
});


// contoh route
app.get("/", (req, res) => {
  res.render("landing", { title: "Vulnera" });
});

app.get("/flash", (req, res) => {
  req.flash("success_msg", "Berhasil login!");
  res.redirect("/");
});

app.get("/login", (req, res) => {
  res.render("login", {
    title: "Masuk",
    messages: req.flash()
  });
});

app.get("/register", (req, res) => {
  res.render("register", {
    title: "Daftar",
    messages: req.flash()
  });
});

app.post("/register", async (req, res) => {
  try {
    const data = {
      name: req.body.name,
      email: req.body.email,
      phone: req.body.phone,
      password: req.body.password,
    };

    // Cek apakah user sudah ada
    const existingUser = await Users.findOne({ email: data.email });
    if (existingUser) {
      req.flash("error", "Email sudah digunakan. Gunakan email lain!");
      return res.redirect("/register");
    }

    // Hash password
    const saltRounds = 10;
    data.password = await bcrypt.hash(data.password, saltRounds);

    // Simpan data ke database (cukup sekali)
    const userdata = await Users.insertOne(data);
    console.log("User registered:", userdata);

    // Flash + redirect
    req.flash("success", "Akun telah dibuat! Silakan login.");
    return res.redirect("/login");

  } catch (err) {
    console.error(err);
    req.flash("error", "Terjadi kesalahan. Silakan coba lagi.");
    return res.redirect("/register");
  }
});

function isAuth(req, res, next) {
  if (req.session.isAuth) {
    next();
  } else {
    req.flash("error", "Silakan login terlebih dahulu.");
    res.redirect("/login");
  }
}

app.get("/homepage", isAuth, (req, res) => {
  res.render("homepage", {
    title: "Vulnera | Homepage",
    messages: req.flash()
  });
});

// Login user
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Cek dulu kalau akun admin super
    if (email === "admin@gmail.com" && password === "admin123") {
      req.session.user = { name: "Super Admin", email: email, role: "admin" };
      req.session.isAuth = true;
      return res.redirect("admin/home");
    }

    // Kalau bukan admin, cek database users
    const check = await Users.findOne({ email: email });
    if (!check) {
      req.flash("error", "Email tidak ditemukan");
      return res.redirect("/login");
    }

    const isPasswordMatch = await bcrypt.compare(password, check.password);
    if (isPasswordMatch) {
      req.session.user = check; // Simpan user dari DB
      req.session.isAuth = true;
      return res.redirect("/homepage");
    } else {
      req.flash("error", "Password salah!");
      return res.redirect("/login");
    }
  } catch (err) {
    console.error(err);
    req.flash("error", "Terjadi kesalahan!");
    return res.redirect("/login");
  }
});

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === "admin") {
    return next();
  }
  req.flash("error", "Akses ditolak! Hanya admin yang boleh masuk.");
  res.redirect("/login");
}

app.get("/admin/home", isAdmin, (req, res) => {
  res.render("admin/home", { title: "Dashboard Admin" });
});

app.get("/api/dashboard-data", async (req, res) => {
  try {
    const allData = await Dataset.find({});

    // --- Olah data ---
    // Total Request
    const totalRequest = allData.length;

    // Hitung total serangan (anggap "400, 404, 500" = serangan)
    const attackCodes = ["400", "404", "500"];
    const totalAttack = allData.filter(d => attackCodes.includes(String(d.http?.response?.code))).length;

    // Persentase serangan
    const attackPercentage = totalRequest > 0 ? ((totalAttack / totalRequest) * 100).toFixed(2) : 0;

    // Distribusi HTTP Methods
    const methodCount = {};
    allData.forEach(d => {
      const method = d["http.request.method"];
      if (method) methodCount[method] = (methodCount[method] || 0) + 1;
    });

    // Distribusi status code
    const statusCount = {};
    allData.forEach(d => {
      const code = String(d["http.response.code"]);
      if (code) statusCount[code] = (statusCount[code] || 0) + 1;
    });

    // Distribusi src_port
    const srcPortCount = {};
    allData.forEach(d => {
      const port = d["tcp.srcport"];
      if (port) srcPortCount[port] = (srcPortCount[port] || 0) + 1;
    });

    // --- Kirim hasil ---
    res.json({
      totalRequest,
      totalAttack,
      attackPercentage,
      methodCount,
      statusCount,
      srcPortCount
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
      return res.redirect("/homepage");
    }
    res.clearCookie("connect.sid"); // hapus cookie session
    res.redirect("/"); // arahkan ke landing page
  });
});


app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
