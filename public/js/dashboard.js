// Dashboard JavaScript untuk Vulnera Admin
let charts = {};
let dashboardData = null;

// Load dashboard data
async function loadDashboard() {
  try {
    // Show loading
    document.getElementById('loadingState').style.display = 'flex';
    document.getElementById('errorState').style.display = 'none';
    document.getElementById('dashboardContent').style.display = 'none';

    const response = await fetch("/admin/api/dashboard-data");
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const data = await response.json();
    dashboardData = data;
    
    // Hide loading and show content
    document.getElementById('loadingState').style.display = 'none';
    document.getElementById('dashboardContent').style.display = 'block';
    
    // Update dashboard
    updateDashboard(data);
    updateLastUpdate();
    
  } catch (error) {
    console.error('Error loading dashboard:', error);
    document.getElementById('loadingState').style.display = 'none';
    document.getElementById('errorState').style.display = 'block';
    document.getElementById('errorMessage').textContent = error.message;
  }
}

// Destroy all existing charts
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

// Update dashboard with data
function updateDashboard(data) {
  try {
    console.log("=== Dashboard Update Debug ===");
    console.log("Received data:", data);
    console.log("Method count:", data.methodCount);
    console.log("Status count:", data.statusCount);
    console.log("Port count:", data.srcPortCount);
    console.log("Prediction count:", data.predictionCount);
    console.log("Debug info:", data.debug);
    console.log("=== End Debug ===");
    
    // Destroy existing charts first
    destroyAllCharts();
    
    // Update summary numbers
    document.getElementById("totalRequest").textContent = data.totalRequest || 0;
    document.getElementById("totalAttack").textContent = data.totalAttack || 0;
    document.getElementById("attackPercentage").textContent = (data.attackPercentage || 0) + "%";
    document.getElementById("mlProcessed").textContent = data.totalRequest || 0;

    // Create charts with error handling
    createTrafficPieChart(data);
    createPredictionPieChart(data);
    createHttpMethodChart(data);
    createHttpStatusChart(data);
    createSrcPortChart(data);
    createAttackTypeChart(data);
    createRequestTrendChart(data);
    createIpAddressChart(data);
    
    // Update data table
    updateDataTable(data);

    // Update recommendations
    updateRecommendations(data);
  
    
  } catch (error) {
    console.error('Error updating dashboard:', error);
    document.getElementById('errorState').style.display = 'block';
    document.getElementById('errorMessage').textContent = `Error updating dashboard: ${error.message}`;
  }
}

// Traffic Distribution Pie Chart
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
    
    const normalCount = data.totalRequest - data.totalAttack;
    charts.trafficPie = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ['Normal Traffic', 'Attack Traffic'],
        datasets: [{
          data: [normalCount, data.totalAttack],
          backgroundColor: ['#10B981', '#EF4444'],
          borderWidth: 2,
          borderColor: '#1F2937'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#DCF2F1' }
          }
        }
      }
    });
  } catch (error) {
    console.error('Error creating traffic pie chart:', error);
  }
}

// ML Prediction Distribution
function createPredictionPieChart(data) {
  try {
    const ctx = document.getElementById('predictionPie');
    if (!ctx) {
      console.warn('Canvas predictionPie not found');
      return;
    }
    
    if (charts.predictionPie) {
      charts.predictionPie.destroy();
    }
    
    const predictionData = data.predictionCount || {};
    const labels = Object.keys(predictionData);
    const values = Object.values(predictionData);
    
    if (labels.length === 0) {
      ctx.style.display = 'none';
      return;
    }
    
    ctx.style.display = 'block';
    charts.predictionPie = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: labels,
        datasets: [{
          data: values,
          backgroundColor: ['#10B981', '#F59E0B', '#EF4444', '#8B5CF6', '#06B6D4'],
          borderWidth: 2,
          borderColor: '#1F2937'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#DCF2F1' }
          }
        }
      }
    });
  } catch (error) {
    console.error('Error creating prediction pie chart:', error);
  }
}

// HTTP Methods Chart
function createHttpMethodChart(data) {
  try {
    const ctx = document.getElementById('httpMethodChart');
    if (!ctx) {
      console.warn('Canvas httpMethodChart not found');
      return;
    }
    
    if (charts.httpMethod) {
      charts.httpMethod.destroy();
    }
    
    const methodData = data.methodCount || {};
    if (Object.keys(methodData).length === 0) {
      ctx.style.display = 'none';
      return;
    }
    
    ctx.style.display = 'block';
    charts.httpMethod = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: Object.keys(methodData),
        datasets: [{
          label: 'Jumlah Request',
          data: Object.values(methodData),
          backgroundColor: '#F59E0B',
          borderRadius: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { backgroundColor: '#1F2937' }
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: { color: '#374151' },
            ticks: { color: '#DCF2F1' }
          },
          x: {
            grid: { color: '#374151' },
            ticks: { color: '#DCF2F1' }
          }
        }
      }
    });
  } catch (error) {
    console.error('Error creating HTTP method chart:', error);
  }
}

// HTTP Status Codes Chart
function createHttpStatusChart(data) {
  try {
    const ctx = document.getElementById('httpStatusChart');
    if (!ctx) {
      console.warn('Canvas httpStatusChart not found');
      return;
    }
    
    if (charts.httpStatus) {
      charts.httpStatus.destroy();
    }
    
    const statusData = data.statusCount || {};
    if (Object.keys(statusData).length === 0) {
      ctx.style.display = 'none';
      return;
    }
    
    ctx.style.display = 'block';
    charts.httpStatus = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: Object.keys(statusData),
        datasets: [{
          label: 'Jumlah',
          data: Object.values(statusData),
          backgroundColor: ['#10B981', '#F59E0B', '#EF4444', '#8B5CF6'],
          borderRadius: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { backgroundColor: '#1F2937' }
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: { color: '#374151' },
            ticks: { color: '#DCF2F1' }
          },
          x: {
            grid: { color: '#374151' },
            ticks: { color: '#DCF2F1' }
          }
        }
      }
    });
  } catch (error) {
    console.error('Error creating HTTP status chart:', error);
  }
}

// Source Port Chart
function createSrcPortChart(data) {
  try {
    const ctx = document.getElementById('srcPortChart');
    if (!ctx) {
      console.warn('Canvas srcPortChart not found');
      return;
    }
    
    if (charts.srcPort) {
      charts.srcPort.destroy();
    }
    
    const portData = data.srcPortCount || {};
    const topPorts = Object.entries(portData)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10);
    
    if (topPorts.length === 0) {
      ctx.style.display = 'none';
      return;
    }
    
    ctx.style.display = 'block';
    charts.srcPort = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: topPorts.map(([port]) => port),
        datasets: [{
          label: 'Jumlah Request',
          data: topPorts.map(([,count]) => count),
          backgroundColor: '#06B6D4',
          borderRadius: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        plugins: {
          legend: { display: false },
          tooltip: { backgroundColor: '#1F2937' }
        },
        scales: {
          x: {
            beginAtZero: true,
            grid: { color: '#374151' },
            ticks: { color: '#DCF2F1' }
          },
          y: {
            grid: { color: '#374151' },
            ticks: { color: '#DCF2F1' }
          }
        }
      }
    });
  } catch (error) {
    console.error('Error creating source port chart:', error);
  }
}

// Attack Types Chart
function createAttackTypeChart(data) {
  try {
    const ctx = document.getElementById('attackTypeChart');
    if (!ctx) {
      console.warn('Canvas attackTypeChart not found');
      return;
    }
    
    if (charts.attackType) {
      charts.attackType.destroy();
    }
    
    const predictionData = data.predictionCount || {};
    const attackTypes = Object.entries(predictionData)
      .filter(([label]) => label !== 'Normal')
      .sort(([,a], [,b]) => b - a);
    
    if (attackTypes.length === 0) {
      ctx.style.display = 'none';
      return;
    }
    
    ctx.style.display = 'block';
    charts.attackType = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: attackTypes.map(([type]) => type),
        datasets: [{
          label: 'Jumlah Serangan',
          data: attackTypes.map(([,count]) => count),
          backgroundColor: '#EF4444',
          borderRadius: 8
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: { 
            backgroundColor: '#1F2937',
            callbacks: {
              title: (items) => items[0].label // tampilkan label full di tooltip
            }
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: { color: '#374151' },
            ticks: { color: '#DCF2F1' }
          },
          x: {
            grid: { color: '#374151' },
            ticks: { 
              color: '#DCF2F1',
              autoSkip: true,
              maxRotation: 60, // rotasi agar tidak tabrakan
              minRotation: 45,
              callback: function(value, index) {
                const label = this.getLabelForValue(value);
                return label.length > 12 ? label.slice(0, 12) + '…' : label;
              }
            }
          }
        }
      }
    });
  } catch (error) {
    console.error('Error creating attack type chart:', error);
  }
}


// Request Trend Chart
function createRequestTrendChart(data) {
  try {
    // kalau data object, cek apakah punya recentData
    if (!Array.isArray(data)) {
      if (data && Array.isArray(data.recentData)) {
        data = data.recentData;
      } else {
        console.warn("RequestTrendChart expects array but got:", data);
        return;
      }
    }

    const ctx = document.getElementById('requestTrendChart');
    if (!ctx) {
      console.warn('Canvas requestTrendChart not found');
      return;
    }

    if (charts.requestTrend) {
      charts.requestTrend.destroy();
    }

    // === Group by hour ===
    const grouped = {};
    data.forEach(item => {
      const hour = item.hour || new Date(item.timestamp).getHours().toString().padStart(2, '0');
      if (!grouped[hour]) {
        grouped[hour] = { Normal: 0, Attack: 0 };
      }
      if (item.predicted_label === 'Normal') {
        grouped[hour].Normal++;
      } else {
        grouped[hour].Attack++;
      }
    });

    const labels = Object.keys(grouped).sort((a, b) => Number(a) - Number(b));
    const normalData = labels.map(hour => grouped[hour].Normal);
    const attackData = labels.map(hour => grouped[hour].Attack);

    charts.requestTrend = new Chart(ctx, {
      type: 'line',
      data: {
        labels,
        datasets: [
          {
            label: 'Normal Traffic',
            data: normalData,
            borderColor: '#10B981',
            backgroundColor: 'rgba(16, 185, 129, 0.1)',
            tension: 0.4,
            fill: true
          },
          {
            label: 'Attack Traffic',
            data: attackData,
            borderColor: '#EF4444',
            backgroundColor: 'rgba(239, 68, 68, 0.1)',
            tension: 0.4,
            fill: true
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'top',
            labels: { color: '#DCF2F1' }
          },
          tooltip: { backgroundColor: '#1F2937' }
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: { color: '#374151' },
            ticks: { color: '#DCF2F1' }
          },
          x: {
            grid: { color: '#374151' },
            ticks: { color: '#DCF2F1' }
          }
        }
      }
    });
  } catch (error) {
    console.error('Error creating request trend chart:', error);
  }
}



// IP Address Chart
function createIpAddressChart(data) {
  try {
    const ctx = document.getElementById('ipAddressChart');
    if (!ctx) {
      console.warn('Canvas ipAddressChart not found');
      return;
    }
    
    if (charts.ipAddress) {
      charts.ipAddress.destroy();
    }
    
    // Gunakan data real dari database
    const ipData = data.topIPs || [];
    
    if (ipData.length === 0) {
      ctx.style.display = 'none';
      return;
    }
    
    ctx.style.display = 'block';
    charts.ipAddress = new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels: ipData.map(item => item.ip),
        datasets: [{
          data: ipData.map(item => item.count),
          backgroundColor: ['#8B5CF6', '#06B6D4', '#F59E0B', '#EF4444', '#10B981'],
          borderWidth: 2,
          borderColor: '#1F2937'
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'bottom',
            labels: { color: '#DCF2F1' }
          }
        }
      }
    });
  } catch (error) {
    console.error('Error creating IP address chart:', error);
  }
}

// ======= Pagination State =======
let currentPage = 1;
let rowsPerPage = 10;
let fullData = [];

// ======= Update Data Table =======
function updateDataTable(data) {
  try {
    const tableBody = document.getElementById('dataTableBody');
    if (!tableBody) return;

    fullData = data.recentData || [];
    currentPage = 1; // reset ke halaman pertama setiap kali data baru masuk

    renderTable();
    renderPagination();
  } catch (error) {
    console.error('Error updating data table:', error);
  }
}

// ======= Render Table =======
function renderTable() {
  const tableBody = document.getElementById('dataTableBody');
  if (!tableBody) return;

  if (!fullData || fullData.length === 0) {
    tableBody.innerHTML =
      '<tr><td colspan="5" class="text-center py-4 text-gray-400">Tidak ada data tersedia</td></tr>';
    return;
  }

  const start = (currentPage - 1) * rowsPerPage;
  const end = start + rowsPerPage;
  const pageData = fullData.slice(start, end);

  const tableRows = pageData
    .map(
      (item) => `
      <tr class="border-b border-gray-600 hover:bg-gray-700">
        <td class="py-2 px-4">${item.timestamp || 'N/A'}</td>
        <td class="py-2 px-4">${item.src_ip || 'N/A'}</td>
        <td class="py-2 px-4">${item['request_http_method'] || 'N/A'}</td>
        <td class="py-2 px-4">${item['response_http_status_code'] || 'N/A'}</td>
        <td class="py-2 px-4">
          <span class="px-2 py-1 rounded-full text-xs ${
            item.predicted_label === 'Normal'
              ? 'bg-green-600'
              : 'bg-red-600'
          }">
            ${item.predicted_label || 'Unknown'}
          </span>
        </td>
      </tr>
    `
    )
    .join('');

  tableBody.innerHTML = tableRows;
}

// ======= Render Pagination Controls =======
function renderPagination() {
  const paginationDiv = document.getElementById('paginationControls');
  if (!paginationDiv) return;

  const totalPages = Math.ceil(fullData.length / rowsPerPage);

  if (totalPages <= 1) {
    paginationDiv.innerHTML = '';
    return;
  }

  let buttons = '';
  for (let i = 1; i <= totalPages; i++) {
    buttons += `
      <button 
        class="px-3 py-1 rounded ${
          i === currentPage
            ? 'bg-blue-600 text-white'
            : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
        }"
        onclick="goToPage(${i})"
      >
        ${i}
      </button>
    `;
  }

  paginationDiv.innerHTML = buttons;
}

// ======= Change Page =======
function goToPage(page) {
  currentPage = page;
  renderTable();
  renderPagination();
}


// Update recommendations using API
async function updateRecommendations(data) {
  try {
    const response = await fetch("/admin/api/gemini-recommendations", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify(data)
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const recommendations = await response.text();
    const recoDiv = document.getElementById("recommendations");
    if (recoDiv) {
      // Parse markdown to HTML
      const htmlContent = marked.parse(recommendations);
      
      recoDiv.innerHTML = `
        <div class="p-6 rounded-xl shadow-lg" style="background: linear-gradient(135deg, #263159, #365486);">
          <h3 class="text-lg font-semibold text-yellow-400 mb-4">📌 Saran & Rekomendasi</h3>
          <div class="markdown-content">
            ${htmlContent}
          </div>
        </div>
      `;
    }
  } catch (error) {
    console.error('Error getting recommendations:', error);
    const recoDiv = document.getElementById("recommendations");
    if (recoDiv) {
      recoDiv.innerHTML = `
        <div class="p-6 rounded-xl shadow-lg" style="background: linear-gradient(135deg, #263159, #365486);">
          <h3 class="text-lg font-semibold text-yellow-400 mb-4">📌 Saran & Rekomendasi</h3>
          <div class="markdown-content">
            <p class="text-red-400">Gagal memuat rekomendasi: ${error.message}</p>
          </div>
        </div>
      `;
    }
  }
}

// Update last update timestamp
function updateLastUpdate() {
  try {
    const now = new Date();
    const timeString = now.toLocaleTimeString('id-ID');
    const dateString = now.toLocaleDateString('id-ID');
    const lastUpdateElement = document.getElementById('lastUpdate');
    if (lastUpdateElement) {
      lastUpdateElement.textContent = `Terakhir update: ${dateString} ${timeString}`;
    }
  } catch (error) {
    console.error('Error updating last update timestamp:', error);
  }
}

// Initialize dashboard when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
  // Set up refresh button
  const refreshBtn = document.getElementById('refreshBtn');
  if (refreshBtn) {
    refreshBtn.addEventListener('click', loadDashboard);
  }
  
  // Set up download PDF button
  const downloadPdfBtn = document.getElementById('downloadPdfBtn');
  if (downloadPdfBtn) {
    downloadPdfBtn.addEventListener('click', generatePDF);
  }
  
  // Initial load
  loadDashboard();
  
  // Auto-refresh every 30 seconds
  // setInterval(loadDashboard, 30000);
});

// PDF Generation Functions
async function generatePDF() {
  try {
    // Show loading state
    const downloadBtn = document.getElementById('downloadPdfBtn');
    const originalText = downloadBtn.innerHTML;
    downloadBtn.innerHTML = '⏳ Generating PDF...';
    downloadBtn.disabled = true;

    // Get recommendations for PDF
    let recommendations = 'Loading recommendations...';
    try {
      const response = await fetch("/admin/api/gemini-recommendations", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify(dashboardData)
      });
      
      if (response.ok) {
        const recommendationsText = await response.text();
        // Convert markdown to HTML for PDF
        recommendations = marked.parse(recommendationsText);
      }
    } catch (error) {
      console.warn('Could not load recommendations for PDF:', error);
      recommendations = 'Recommendations not available';
    }

    // Create PDF content
    const pdfContent = createPDFContent(recommendations);
    
    // Create a temporary div for PDF content
    const tempDiv = document.createElement('div');
    tempDiv.innerHTML = pdfContent;
    tempDiv.className = 'pdf-content';
    tempDiv.style.position = 'absolute';
    tempDiv.style.left = '-9999px';
    tempDiv.style.top = '0';
    tempDiv.style.width = '800px';
    document.body.appendChild(tempDiv);

    // Generate PDF using html2canvas and jsPDF
    const canvas = await html2canvas(tempDiv, {
      scale: 2,
      useCORS: true,
      allowTaint: true,
      backgroundColor: '#ffffff'
    });

    // Remove temporary div
    document.body.removeChild(tempDiv);

    // Create PDF
    const { jsPDF } = window.jspdf;
    const pdf = new jsPDF('p', 'mm', 'a4');
    
    const imgData = canvas.toDataURL('image/png');
    const imgWidth = 210; // A4 width in mm
    const pageHeight = 295; // A4 height in mm
    const imgHeight = (canvas.height * imgWidth) / canvas.width;
    let heightLeft = imgHeight;

    let position = 0;

    // Add first page
    pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
    heightLeft -= pageHeight;

    // Add additional pages if needed
    while (heightLeft >= 0) {
      position = heightLeft - imgHeight;
      pdf.addPage();
      pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
      heightLeft -= pageHeight;
    }

    // Download PDF
    const fileName = `Vulnera_Report_${new Date().toISOString().split('T')[0]}.pdf`;
    pdf.save(fileName);

    // Reset button
    downloadBtn.innerHTML = originalText;
    downloadBtn.disabled = false;

  } catch (error) {
    console.error('Error generating PDF:', error);
    alert('Error generating PDF: ' + error.message);
    
    // Reset button
    const downloadBtn = document.getElementById('downloadPdfBtn');
    downloadBtn.innerHTML = '📄 Download PDF';
    downloadBtn.disabled = false;
  }
}

function createPDFContent(recommendations = 'Recommendations not available') {
  if (!dashboardData) {
    return '<div class="pdf-content"><h1>No data available</h1></div>';
  }

  const data = dashboardData;
  const currentDate = new Date().toLocaleDateString('id-ID');
  const currentTime = new Date().toLocaleTimeString('id-ID');

  return `
    <div class="pdf-content">
      <div class="pdf-header">
        <h1>Vulnera Security Report</h1>
        <p>Generated on ${currentDate} at ${currentTime}</p>
      </div>

      <div class="pdf-section">
        <h2>Executive Summary</h2>
        <div class="pdf-summary">
          <div class="pdf-summary-item">
            <div class="pdf-summary-value">${data.totalRequest || 0}</div>
            <div class="pdf-summary-label">Total Requests</div>
          </div>
          <div class="pdf-summary-item">
            <div class="pdf-summary-value">${data.totalAttack || 0}</div>
            <div class="pdf-summary-label">Total Attacks</div>
          </div>
          <div class="pdf-summary-item">
            <div class="pdf-summary-value">${data.attackPercentage || 0}%</div>
            <div class="pdf-summary-label">Attack Percentage</div>
          </div>
          <div class="pdf-summary-item">
            <div class="pdf-summary-value">${data.totalRequest || 0}</div>
            <div class="pdf-summary-label">ML Processed</div>
          </div>
        </div>
      </div>

      <div class="pdf-section">
        <h2>HTTP Methods Distribution</h2>
        <table class="pdf-table">
          <thead>
            <tr>
              <th>Method</th>
              <th>Count</th>
              <th>Percentage</th>
            </tr>
          </thead>
          <tbody>
            ${Object.entries(data.methodCount || {}).map(([method, count]) => {
              const percentage = data.totalRequest > 0 ? ((count / data.totalRequest) * 100).toFixed(2) : 0;
              return `<tr><td>${method}</td><td>${count}</td><td>${percentage}%</td></tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>

      <div class="pdf-section">
        <h2>HTTP Status Codes</h2>
        <table class="pdf-table">
          <thead>
            <tr>
              <th>Status Code</th>
              <th>Count</th>
              <th>Percentage</th>
            </tr>
          </thead>
          <tbody>
            ${Object.entries(data.statusCount || {}).map(([status, count]) => {
              const percentage = data.totalRequest > 0 ? ((count / data.totalRequest) * 100).toFixed(2) : 0;
              return `<tr><td>${status}</td><td>${count}</td><td>${percentage}%</td></tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>

      <div class="pdf-section">
        <h2>Attack Types Distribution</h2>
        <table class="pdf-table">
          <thead>
            <tr>
              <th>Attack Type</th>
              <th>Count</th>
              <th>Percentage</th>
            </tr>
          </thead>
          <tbody>
            ${Object.entries(data.predictionCount || {}).map(([type, count]) => {
              const percentage = data.totalRequest > 0 ? ((count / data.totalRequest) * 100).toFixed(2) : 0;
              return `<tr><td>${type}</td><td>${count}</td><td>${percentage}%</td></tr>`;
            }).join('')}
          </tbody>
        </table>
      </div>

      <div class="pdf-section">
        <h2>Top Source Ports</h2>
        <table class="pdf-table">
          <thead>
            <tr>
              <th>Port</th>
              <th>Count</th>
              <th>Percentage</th>
            </tr>
          </thead>
          <tbody>
            ${Object.entries(data.srcPortCount || {})
              .sort(([,a], [,b]) => b - a)
              .slice(0, 10)
              .map(([port, count]) => {
                const percentage = data.totalRequest > 0 ? ((count / data.totalRequest) * 100).toFixed(2) : 0;
                return `<tr><td>${port}</td><td>${count}</td><td>${percentage}%</td></tr>`;
              }).join('')}
          </tbody>
        </table>
      </div>

      <div class="pdf-section">
        <h2>Top Source IPs</h2>
        <table class="pdf-table">
          <thead>
            <tr>
              <th>IP Address</th>
              <th>Request Count</th>
            </tr>
          </thead>
          <tbody>
            ${(data.topIPs || []).map(ip => 
              `<tr><td>${ip.ip}</td><td>${ip.count}</td></tr>`
            ).join('')}
          </tbody>
        </table>
      </div>

      <div class="pdf-section">
        <h2>Recent Activity</h2>
        <table class="pdf-table">
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Source IP</th>
              <th>Method</th>
              <th>Status</th>
              <th>Prediction</th>
            </tr>
          </thead>
          <tbody>
            ${(data.recentData || []).slice(0, 20).map(item => 
              `<tr>
                <td>${item.timestamp || 'N/A'}</td>
                <td>${item.src_ip || 'N/A'}</td>
                <td>${item.request_http_method || 'N/A'}</td>
                <td>${item.response_http_status_code || 'N/A'}</td>
                <td>${item.predicted_label || 'Unknown'}</td>
              </tr>`
            ).join('')}
          </tbody>
        </table>
      </div>

      <div class="pdf-section">
        <h2>Security Recommendations</h2>
        <div class="pdf-recommendations" style="line-height: 1.6; color: #333;">
          ${recommendations}
        </div>
      </div>
    </div>
  `;
}

// Export functions for global access
window.loadDashboard = loadDashboard;
window.refreshDashboard = loadDashboard;
window.generatePDF = generatePDF;
