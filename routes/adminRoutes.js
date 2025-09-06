const express = require("express");
const router = express.Router();
const { isAdmin } = require("../middleware/auth");
const uploadController = require("../controllers/uploadController");
const { upload, handleMulterError } = require("../config/multer");

// Admin dashboard
router.get("/home", isAdmin, (req, res) => {
  res.render("admin/home", { title: "Dashboard Admin" });
});

// Upload CSV routes
router.get("/uploadcsv", isAdmin, (req, res) => {
  res.render("admin/uploadcsv", { title: "Upload CSV" });
});

router.post("/upload", isAdmin, upload.single("csvFile"), handleMulterError, uploadController.uploadCSV);

// API routes
router.get("/api/dashboard-data", isAdmin, uploadController.getDashboardData);

module.exports = router;
