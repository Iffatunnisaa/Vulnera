// Dashboard Visualisasi (Dummy Data)
router.get('/dashboard', (req, res) => {
  const summary = {
    total_rows: 200,
    attacks_detected: 45,
    normal_traffic: 155
  };

  // data per jenis serangan (contoh dummy)
  const attack_types = ["DoS", "Phishing", "SQL Injection", "XSS"];
  const attack_counts = [20, 10, 8, 7];

  res.render('dashboard', { summary, attack_types, attack_counts });
});
