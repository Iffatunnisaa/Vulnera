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

// Update data table
function updateDataTable(data) {
  try {
    const tableBody = document.getElementById('dataTableBody');
    if (!tableBody) {
      console.warn('Table body not found');
      return;
    }
    
    if (!data.recentData || data.recentData.length === 0) {
      tableBody.innerHTML = '<tr><td colspan="5" class="text-center py-4 text-gray-400">Tidak ada data tersedia</td></tr>';
      return;
    }
    
    const tableRows = data.recentData.slice(0, 10).map(item => `
      <tr class="border-b border-gray-600 hover:bg-gray-700">
        <td class="py-2 px-4">${item.timestamp || 'N/A'}</td>
        <td class="py-2 px-4">${item.src_ip || 'N/A'}</td>
        <td class="py-2 px-4">${item['http.request.method'] || 'N/A'}</td>
        <td class="py-2 px-4">${item['http.response.code'] || 'N/A'}</td>
        <td class="py-2 px-4">
          <span class="px-2 py-1 rounded-full text-xs ${
            item.predicted_label === 'Normal' ? 'bg-green-600' : 'bg-red-600'
          }">
            ${item.predicted_label || 'Unknown'}
          </span>
        </td>
      </tr>
    `).join('');
    
    tableBody.innerHTML = tableRows;
  } catch (error) {
    console.error('Error updating data table:', error);
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
  
  // Initial load
  loadDashboard();
  
  // Auto-refresh every 30 seconds
  // setInterval(loadDashboard, 30000);
});

// Export functions for global access
window.loadDashboard = loadDashboard;
window.refreshDashboard = loadDashboard;
