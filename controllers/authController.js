const bcrypt = require("bcrypt");
const { Users } = require("../utils/db.js");
const logger = require('../utils/logger');

const authController = {
  // Register user
  async register(req, res) {
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

      // Simpan data ke database
      const userdata = await Users.insertOne(data);
      console.log("User registered:", userdata);

      // Flash + redirect
      req.flash("success", "Akun telah dibuat! Silakan login.");
      return res.redirect("/login");

    } catch (err) {
      logger.error(`Server error during registration: ${err.message}`);
      console.error(err);
      req.flash("error", "Terjadi kesalahan. Silakan coba lagi.");
      return res.redirect("/register");
    }
  },

  // Login user
  async login(req, res) {
    const { email, password } = req.body;
    const attackerIp = req.ip; // <-- LOGGING: Dapatkan alamat IP penyerang dari request

    try {
      // Cek dulu kalau akun admin super
      if (email === "admin@gmail.com" && password === "admin123") {
	logger.info(`Successful super admin login for user '${email}', from IP ${attackerIp}`);
        req.session.user = { name: "Super Admin", email: email, role: "admin" };
        req.session.isAuth = true;
        return res.redirect("admin/home");
      }

      // Kalau bukan admin, cek database users
      const check = await Users.findOne({ email: email });
      if (!check) {
	logger.warn(`Failed login attempt: User '${email}' not found, from IP ${attackerIp}`);
        req.flash("error", "Email tidak ditemukan");
        return res.redirect("/login");
      }

      const isPasswordMatch = await bcrypt.compare(password, check.password);
      if (isPasswordMatch) {
	logger.info(`Successful login for user '${email}', from IP ${attackerIp}`);
        req.session.user = check; // Simpan user dari DB
        req.session.isAuth = true;
        return res.redirect("/homepage");
      } else {
	logger.warn(`Failed login attempt: Incorrect password for user '${email}', from IP ${attackerIp}`);
        req.flash("error", "Password salah!");
        return res.redirect("/login");
      }
    } catch (err) {
      logger.error(`Server error during login for user '${email}', from IP ${attackerIp}: ${err.message}`);
      console.error(err);
      req.flash("error", "Terjadi kesalahan!");
      return res.redirect("/login");
    }
  },

  // Logout user
  logout(req, res) {
    req.session.destroy((err) => {
      if (err) {
        console.log(err);
        return res.redirect("/homepage");
      }
      res.clearCookie("connect.sid"); // hapus cookie session
      res.redirect("/"); // arahkan ke landing page
    });
  }
};

module.exports = authController;
