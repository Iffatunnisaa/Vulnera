const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const { Users } = require("./utils/db.js");
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

app.get("/homepage", (req, res) => {
  res.render("homepage", {
    title: "Vulnera | Homepage",
    messages: req.flash()
  });
});

// Login user
app.post("/login", async (req, res) => {
  try {
    const check = await Users.findOne({ email: req.body.email });
    if (!check) {
      req.flash("error", "email cannot found");
      return res.redirect("/login");
    }

    const isPasswordMatch = await bcrypt.compare(
      req.body.password,
      check.password
    );
    if (isPasswordMatch) {
      req.session.user = check; // Simpan seluruh objek pengguna ke sesi
      req.session.isAuth = true;
      return res.redirect("/homepage");

    } else {
      req.flash("error", "wrong password!");
      return res.redirect("/login");
    }
  } catch {
    req.flash("error", "wrong details!");
    return res.redirect("/login");
  }
});

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
