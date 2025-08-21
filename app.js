const express = require("express");
const path = require("path");
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

app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});
