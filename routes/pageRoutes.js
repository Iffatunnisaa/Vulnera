const express = require("express");
const router = express.Router();
const { isAuth } = require("../middleware/auth");

// Landing page
router.get("/", (req, res) => {
  res.render("landing", { title: "Vulnera" });
});

// Flash message test
router.get("/flash", (req, res) => {
  req.flash("success_msg", "Berhasil login!");
  res.redirect("/");
});

// Homepage (protected)
router.get("/homepage", isAuth, (req, res) => {
  res.render("homepage", {
    title: "Vulnera | Homepage",
    messages: req.flash()
  });
});

// Redirect /uploadcsv ke /admin/uploadcsv
router.get("/uploadcsv", (req, res) => {
  res.redirect("/admin/uploadcsv");
});

module.exports = router;
