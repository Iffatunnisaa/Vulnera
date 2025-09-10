require('dotenv').config();

async function getGeminiRecommendations(data) {
  const prompt = `
  Anda adalah analis keamanan siber. Berdasarkan data berikut, buat saran singkat dengan gaya *executive summary* untuk laporan profesional:

  - Total request: ${data.totalRequest}
  - Total attack: ${data.totalAttack}
  - Attack percentage: ${data.attackPercentage}%
  - Distribusi metode HTTP: ${JSON.stringify(data.methodCount)}
  - Status code: ${JSON.stringify(data.statusCount)}
  - Serangan terdeteksi: ${JSON.stringify(data.predictionCount)}
  - Port sumber terbanyak: ${JSON.stringify(data.srcPortCount)}

  Output HARUS ringkas, tajam, dan profesional dengan format Markdown berikut:
  ## Ringkasan Situasi
  [Deskripsi singkat situasi keamanan]

  ## Risiko Utama
  - [Daftar risiko yang teridentifikasi]

  ## Rekomendasi Teknis
  - [Daftar rekomendasi langkah teknis]
  - [Daftar rekomendasi monitoring]
  - [Daftar rekomendasi pencegahan]

  ## Prioritas Aksi
  1. [Aksi prioritas tinggi]
  2. [Aksi prioritas sedang]
  3. [Aksi prioritas rendah]

  Gunakan format Markdown yang rapi dengan heading, bullet points, dan emphasis yang sesuai.
  `;
  
  const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
  const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      contents: [{ parts: [{ text: prompt }] }]
    })
  });

  const result = await response.json();
  return result.candidates?.[0]?.content?.parts?.[0]?.text || "Tidak ada rekomendasi.";
}

module.exports = getGeminiRecommendations;
