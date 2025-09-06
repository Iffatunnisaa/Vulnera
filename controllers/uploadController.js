const csv = require("csv-parser");
const fs = require("fs");
const config = require("../config");
const axios = require("axios");

const uploadController = {
  // Upload CSV dengan prediksi ML
  async uploadCSV(req, res) {
    try {
      console.log("=== Memulai proses upload CSV ===");
      
      // Validasi file
      const fileValidation = config.mlBackend.validateFile(req.file);
      if (!fileValidation.valid) {
        console.log("File validation failed:", fileValidation.error);
        req.flash("error_msg", fileValidation.error);
        return res.redirect("/admin/uploadcsv");
      }

      console.log("File validation passed, mulai proses ML...");

      // 1. Kirim file ke backend ML untuk prediksi
      const mlPredictionResult = await sendToMLBackend(req.file.path);
      
      if (!mlPredictionResult.success) {
        console.error("ML backend failed:", mlPredictionResult.error);
        req.flash("error_msg", `Gagal memproses dengan ML: ${mlPredictionResult.error}`);
        return res.redirect("/admin/uploadcsv");
      }

      console.log("ML backend berhasil, membaca hasil prediksi...");

      // 2. Baca hasil prediksi dari ML
      const predictedResults = await readPredictedCSV(mlPredictionResult.filePath);
      
      if (!predictedResults || predictedResults.length === 0) {
        console.error("No prediction results found");
        req.flash("error_msg", "Tidak ada hasil prediksi dari ML backend");
        return res.redirect("/admin/uploadcsv");
      }

      console.log(`Berhasil membaca ${predictedResults.length} baris hasil prediksi`);

      // 3. Simpan hasil prediksi ke MongoDB
      console.log("Menyimpan ke MongoDB...");
      const savedData = await config.database.models.Dataset.insertMany(predictedResults);
      console.log(`Berhasil menyimpan ${savedData.length} baris ke MongoDB`);

      // 4. Hapus file temporary
      cleanupTempFiles(req.file.path, mlPredictionResult.filePath);

      console.log("=== Proses upload CSV selesai ===");

      req.flash("success_msg", `CSV berhasil diupload, diproses dengan ML (${predictedResults.length} baris), dan disimpan ke MongoDB!`);
      res.redirect("/admin/uploadcsv");

    } catch (err) {
      console.error("Error dalam uploadCSV:", err);
      req.flash("error_msg", `Terjadi kesalahan: ${err.message}`);
      res.redirect("/admin/uploadcsv");
    }
  },

  // Get dashboard data
  async getDashboardData(req, res) {
    try {
      const allData = await config.database.models.Dataset.find({}).sort({ _id: -1 }).limit(1000);

      console.log("=== Dashboard Data Debug ===");
      console.log("Total records found:", allData.length);

      if (allData.length > 0) {
        console.log("Sample record keys:", Object.keys(allData[0]));
        console.log("Sample record:", JSON.stringify(allData[0], null, 2));
      }

      // --- Olah data ---
      const totalRequest = allData.length;

      const totalAttack = allData.filter(d => d.predicted_label && d.predicted_label !== "Normal").length;

      const attackPercentage = totalRequest > 0 ? ((totalAttack / totalRequest) * 100).toFixed(2) : 0;

      // Distribusi HTTP Methods (langsung pakai request_http_method)
      const methodCount = {};
      allData.forEach(d => {
        const method = d.request_http_method;
        if (method) {
          methodCount[method] = (methodCount[method] || 0) + 1;
        }
      });

      // Distribusi Status Code (langsung pakai response_http_status_code)
      const statusCount = {};
      allData.forEach(d => {
        const code = d.response_http_status_code;
        if (code) {
          statusCount[code] = (statusCount[code] || 0) + 1;
        }
      });

      // Distribusi Source Port
      const srcPortCount = {};
      allData.forEach(d => {
        const port = d.src_port;
        if (port) {
          srcPortCount[port] = (srcPortCount[port] || 0) + 1;
        }
      });

      // Distribusi Prediksi
      const predictionCount = {};
      allData.forEach(d => {
        const prediction = d.predicted_label || "Unknown";
        predictionCount[prediction] = (predictionCount[prediction] || 0) + 1;
      });

      // Data untuk tabel (10 terbaru)
      const recentData = allData.slice(0, 10).map(item => ({
        timestamp: item.timestamp || 'N/A',
        src_ip: item.src_ip || 'N/A',
        src_port: item.src_port || 'N/A',
        request_http_method: item.request_http_method || 'N/A',
        response_http_status_code: item.response_http_status_code || 'N/A',
        predicted_label: item.predicted_label || 'Unknown'
      }));

      // Statistik tambahan: Top Source IPs
      const topSourceIPs = {};
      allData.forEach(d => {
        const ip = d.src_ip;
        if (ip) {
          topSourceIPs[ip] = (topSourceIPs[ip] || 0) + 1;
        }
      });

      const topIPs = Object.entries(topSourceIPs)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
        .map(([ip, count]) => ({ ip, count }));

      console.log("Method count:", methodCount);
      console.log("Status count:", statusCount);
      console.log("Port count:", srcPortCount);
      console.log("Prediction count:", predictionCount);
      console.log("Top IPs:", topIPs);
      console.log("=== End Debug ===");

      res.json({
        totalRequest,
        totalAttack,
        attackPercentage,
        methodCount,
        statusCount,
        srcPortCount,
        predictionCount,
        recentData,
        topIPs,
        lastUpdated: new Date().toISOString(),
        dataSource: 'MongoDB Dataset Collection',
        totalRecords: allData.length,
        debug: {
          sampleKeys: allData.length > 0 ? Object.keys(allData[0]) : [],
          methodCountKeys: Object.keys(methodCount),
          statusCountKeys: Object.keys(statusCount),
          portCountKeys: Object.keys(srcPortCount)
        }
      });
    } catch (err) {
      console.error("Error dalam getDashboardData:", err);
      res.status(500).json({ error: err.message });
    }
  }  
};

// ===== HELPER FUNCTIONS =====

// Kirim file ke backend ML
async function sendToMLBackend(filePath) {
  try {
    console.log("Mengirim file ke backend ML...");
    console.log("ML Backend URL:", config.mlBackend.baseURL);
    
    // Baca file CSV
    const fileBuffer = fs.readFileSync(filePath);
    console.log(`File size: ${fileBuffer.length} bytes`);
    
    // Buat FormData untuk multipart/form-data
    const FormData = require('form-data');
    const form = new FormData();
    form.append('file', fileBuffer, {
      filename: 'upload.csv',
      contentType: 'text/csv'
    });

    // Kirim ke backend ML dengan retry mechanism
    const response = await config.mlBackend.retryRequest(async () => {
      console.log("Mengirim request ke ML backend...");
      return axios.post(`${config.mlBackend.baseURL}${config.mlBackend.endpoints.predictCSV}`, form, {
        headers: {
          ...form.getHeaders(),
          ...config.mlBackend.request.headers
        },
        responseType: 'stream',
        timeout: config.mlBackend.request.timeout
      });
    });

    console.log("Response dari ML backend berhasil, menyimpan hasil...");

    // Simpan hasil prediksi ke file temporary
    const tempFilePath = `${config.security.upload.uploadPath}/predicted_${Date.now()}.csv`;
    
    // Pastikan direktori upload ada
    const uploadDir = config.security.upload.uploadPath;
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    
    const writer = fs.createWriteStream(tempFilePath);
    
    response.data.pipe(writer);

    return new Promise((resolve, reject) => {
      writer.on('finish', () => {
        console.log("File hasil prediksi ML berhasil disimpan:", tempFilePath);
        resolve({
          success: true,
          filePath: tempFilePath
        });
      });
      
      writer.on('error', (err) => {
        console.error("Error menyimpan file hasil prediksi:", err);
        reject(err);
      });
    });

  } catch (error) {
    console.error("Error mengirim ke backend ML:", error);
    
    // Error handling yang lebih detail
    let errorMessage = "Unknown error";
    if (error.code === 'ECONNREFUSED') {
      errorMessage = "Backend ML tidak dapat diakses. Pastikan FastAPI berjalan di port 8000";
    } else if (error.code === 'ETIMEDOUT') {
      errorMessage = "Request timeout. File mungkin terlalu besar atau ML backend lambat";
    } else if (error.response) {
      errorMessage = `ML Backend error: ${error.response.status} - ${error.response.statusText}`;
    } else if (error.message) {
      errorMessage = error.message;
    }
    
    return {
      success: false,
      error: errorMessage
    };
  }
}

// Baca hasil prediksi CSV
async function readPredictedCSV(filePath) {
  return new Promise((resolve, reject) => {
    const results = [];
    
    fs.createReadStream(filePath)
      .pipe(csv())
      .on("data", (data) => results.push(data))
      .on("end", () => {
        console.log(`Berhasil membaca ${results.length} baris hasil prediksi`);
        resolve(results);
      })
      .on("error", (err) => {
        console.error("Error membaca file hasil prediksi:", err);
        reject(err);
      });
  });
}

// Bersihkan file temporary
function cleanupTempFiles(originalFilePath, predictedFilePath) {
  try {
    // Hapus file original upload
    if (fs.existsSync(originalFilePath)) {
      fs.unlinkSync(originalFilePath);
      console.log("File original berhasil dihapus:", originalFilePath);
    }
    
    // Hapus file hasil prediksi temporary
    if (fs.existsSync(predictedFilePath)) {
      fs.unlinkSync(predictedFilePath);
      console.log("File hasil prediksi temporary berhasil dihapus:", predictedFilePath);
    }
  } catch (error) {
    console.error("Error membersihkan file temporary:", error);
  }
}

module.exports = uploadController;
