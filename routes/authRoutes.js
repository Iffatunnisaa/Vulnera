const express = require("express");
const router = express.Router();
const authController = require("../controllers/authController");
const { isAuth } = require("../middleware/auth");

// GET routes
router.get("/login", (req, res) => {
  res.render("login", {
    title: "Masuk",
    messages: req.flash()
  });
});

router.get("/register", (req, res) => {
  res.render("register", {
    title: "Daftar",
    messages: req.flash()
  });
});

router.get("/logout", isAuth, authController.logout);

// POST routes
router.post("/register", authController.register);
router.post("/login", authController.login);

module.exports = router;
