# Troubleshooting Guide - Vulnera Dashboard

## 🚨 Error: "Canvas is already in use. Chart with ID 'X' must be destroyed before the canvas can be reused"

### **Penyebab:**
Error ini terjadi ketika Chart.js mencoba menggunakan canvas yang sudah memiliki chart sebelumnya. Ini biasanya terjadi karena:
1. Chart tidak di-destroy dengan benar sebelum membuat yang baru
2. Multiple chart instances pada canvas yang sama
3. Auto-refresh yang tidak menangani chart destruction dengan benar

### **Solusi yang Telah Diterapkan:**

#### 1. **Chart Destruction yang Proper**
```javascript
// Destroy existing chart sebelum membuat yang baru
if (charts.trafficPie) {
  charts.trafficPie.destroy();
}

// Buat chart baru
charts.trafficPie = new Chart(ctx, { ... });
```

#### 2. **Function destroyAllCharts()**
```javascript
function destroyAllCharts() {
  Object.values(charts).forEach(chart => {
    if (chart && typeof chart.destroy === 'function') {
      try {
        chart.destroy();
      } catch (err) {
        console.warn('Error destroying chart:', err);
      }
    }
  });
  charts = {};
}
```

#### 3. **Error Handling pada Setiap Chart Creation**
```javascript
function createTrafficPieChart(data) {
  try {
    const ctx = document.getElementById('trafficPie');
    if (!ctx) {
      console.warn('Canvas trafficPie not found');
      return;
    }
    
    if (charts.trafficPie) {
      charts.trafficPie.destroy();
    }
    
    // Create chart...
    
  } catch (error) {
    console.error('Error creating traffic pie chart:', error);
  }
}
```

### **Struktur File yang Baru:**

#### **`views/admin/home.ejs`**
- Hanya berisi HTML dan CSS
- Referensi ke file JavaScript eksternal
- Tidak ada script inline yang bisa menyebabkan konflik

#### **`public/js/dashboard.js`**
- Semua logic JavaScript untuk dashboard
- Chart management yang proper
- Error handling yang comprehensive
- Auto-refresh dengan chart destruction

### **Cara Testing Dashboard:**

#### 1. **Refresh Manual**
- Klik tombol "🔄 Refresh Data"
- Monitor console untuk error
- Pastikan charts ter-update dengan benar

#### 2. **Auto-refresh**
- Dashboard auto-refresh setiap 30 detik
- Charts akan di-destroy dan re-create
- Monitor console untuk error

#### 3. **Error Handling**
- Jika ada error, akan muncul pesan error
- Tombol "Coba Lagi" untuk retry
- Console log untuk debugging

### **Debugging Tips:**

#### 1. **Check Console**
```javascript
// Buka Developer Tools (F12)
// Lihat Console tab untuk error messages
```

#### 2. **Check Network Tab**
```javascript
// Pastikan API call ke /admin/api/dashboard-data berhasil
// Status code harus 200
```

#### 3. **Check Chart.js Version**
```html
<!-- Pastikan Chart.js versi terbaru -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
```

### **Jika Masih Ada Error:**

#### 1. **Clear Browser Cache**
- Hard refresh (Ctrl+F5)
- Clear browser cache dan cookies

#### 2. **Check File Paths**
```html
<!-- Pastikan path ke dashboard.js benar -->
<script src="/js/dashboard.js"></script>
```

#### 3. **Check MongoDB Connection**
```javascript
// Pastikan database terhubung
// Check console untuk database errors
```

#### 4. **Check ML Backend**
```javascript
// Pastikan FastAPI berjalan di port 8000
// Check console untuk ML backend errors
```

### **Prevention Measures:**

#### 1. **Proper Chart Management**
- Selalu destroy chart sebelum membuat yang baru
- Gunakan try-catch untuk error handling
- Validate canvas elements sebelum digunakan

#### 2. **Memory Management**
- Cleanup charts saat tidak digunakan
- Avoid memory leaks dengan proper destruction
- Monitor memory usage di browser

#### 3. **Error Boundaries**
- Graceful degradation jika chart gagal
- User-friendly error messages
- Fallback UI jika ada masalah

### **Performance Optimization:**

#### 1. **Chart Rendering**
- Limit data points untuk chart besar
- Use appropriate chart types
- Optimize chart options

#### 2. **Data Loading**
- Pagination untuk data besar
- Lazy loading untuk charts
- Debounce refresh requests

### **Monitoring Dashboard:**

#### 1. **Health Check**
- API endpoint availability
- Database connection status
- ML backend status

#### 2. **Performance Metrics**
- Chart rendering time
- Data loading time
- Memory usage

#### 3. **Error Tracking**
- Chart creation failures
- API call failures
- Database query errors

---

## 🔧 **Quick Fix Commands:**

### **Restart Application:**
```bash
# Stop current process
Ctrl+C

# Start again
npm run dev
```

### **Check Logs:**
```bash
# Monitor console output
# Look for error messages
# Check network requests
```

### **Test API Endpoint:**
```bash
# Test dashboard API
curl http://localhost:3000/admin/api/dashboard-data
```

---

**Note:** Jika masalah masih berlanjut, silakan buka issue dengan detail error message dan screenshot console error.
