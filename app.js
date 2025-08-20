const express = require("express");
const app = express();
const path = require("path");

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

app.get("/login", (req, res) => {
  res.render("login", { error: "Username atau password salah" });
});

app.listen(3000, () => console.log("Server running on http://localhost:3000"));

app.get("/landing", (req, res) => {
  res.render("landing", { error: null }); // sesuaikan nama file ejs
});
