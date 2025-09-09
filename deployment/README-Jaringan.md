# Dokumentasi Infrastruktur, Keamanan, dan Simulasi Serangan

Dokumen ini menjelaskan semua komponen yang terkait dengan penyiapan lingkungan server, implementasi keamanan, dan skrip untuk simulasi serangan pada aplikasi **Vulnera**.

## Ringkasan Kontribusi

Pekerjaan yang didokumentasikan di sini mencakup tiga area utama:
1.  **Infrastruktur Server:** Konfigurasi VM Ubuntu Server untuk menjalankan aplikasi Vulnera dan semua layanannya.
2.  **Simulasi & Pengumpulan Data:** Pembuatan skrip otomatis untuk mensimulasikan berbagai serangan siber dan mengumpulkan lalu lintas jaringan sebagai dataset.
3.  **Keamanan & Pencegahan:** Implementasi sistem pencegahan intrusi otomatis menggunakan Fail2Ban untuk melindungi aplikasi dari serangan Brute Force.

## 1. Direktori `simulation_scripts/`

Folder ini berisi skrip utama yang digunakan untuk menghasilkan dataset serangan.

### `master_simulation_v3.sh`

Ini adalah skrip master yang mengotomatiskan seluruh proses simulasi serangan dan pengumpulan data.

**Fitur Utama:**
*   **Otomatisasi Penuh:** Menjalankan 5 skenario serangan berbeda secara berurutan.
*   **Penangkapan Lalu Lintas:** Secara otomatis memulai dan menghentikan `tshark` untuk menangkap lalu lintas mentah (`.pcap`) untuk setiap skenario.
*   **Pemrosesan Data:** Mengonversi file `.pcap` menjadi format `.csv` yang siap digunakan, dengan struktur kolom yang telah ditentukan.
*   **Penamaan Dinamis:** Menghasilkan file output dengan timestamp unik untuk menghindari penimpaan data.

**Cara Menjalankan:**
1.  **Navigasi** ke direktori `simulation_scripts/`.
2.  **Edit Skrip:** Buka skrip dan perbarui variabel `TARGET_IP` dan `COOKIE` di bagian atas sesuai dengan lingkungan target.
3.  **Buat Skrip Dapat Dieksekusi:** Jalankan `chmod +x master_simulation_v3.sh` (hanya perlu sekali).
4.  **Jalankan:** `./master_simulation_v3.sh`.

## 2. Direktori `deployment/fail2ban/`

Folder ini berisi file konfigurasi yang sudah jadi untuk menerapkan sistem pencegahan intrusi (Intrusion Prevention System - IPS) menggunakan **Fail2Ban**.

### Tujuan Konfigurasi
Konfigurasi ini dirancang untuk melindungi aplikasi "Vulnera" dari serangan spesifik dengan memonitor file log aplikasi.

### File Konfigurasi

*   `jail.local`: File konfigurasi utama yang mendefinisikan "penjara" (jails) yang akan aktif. File ini berisi dua jail:
    *   **`[vulnera-auth]`**: Khusus untuk memonitor log autentikasi (`auth.log`) dan melindungi dari serangan **Brute Force**.
    *   **`[vulnera-badbots]`**: Untuk memonitor log akses umum (`access.log`) dan melindungi dari anomali lain seperti **NoSQL Injection**, **Fuzzing**, dan **serangan berbasis header**.
*   `filter.d/vulnera-auth.conf`: Berisi aturan `failregex` untuk mengenali pola percobaan login yang gagal di `auth.log`.
*   `filter.d/vulnera-generic.conf`: Berisi kumpulan aturan `failregex` untuk mengenali berbagai pola serangan umum di `access.log`.

### **Cara Menerapkan Konfigurasi (Prosedur Deployment)**

Untuk mengaktifkan sistem pencegahan ini di server Ubuntu baru, ikuti langkah-langkah berikut:

1.  **Pastikan Fail2Ban Terinstal:**
    ```bash
    sudo apt update
    sudo apt install fail2ban
    ```

2.  **Salin File Konfigurasi ke Lokasi yang Benar:**
    Dari dalam direktori `deployment/fail2ban/`, jalankan perintah berikut:
    ```bash
    # Salin file jail utama
    sudo cp ./jail.local /etc/fail2ban/

    # Salin file filter
    sudo cp ./filter.d/vulnera-auth.conf /etc/fail2ban/filter.d/
    sudo cp ./filter.d/vulnera-generic.conf /etc/fail2ban/filter.d/
    ```

3.  **Pastikan Aplikasi Menghasilkan Log:**
    *   Konfigurasi ini bergantung pada aplikasi "Vulnera" yang sudah dikonfigurasi untuk menulis log ke:
        *   `/var/log/vulnera/auth.log` (untuk log autentikasi via **Winston**)
        *   `/var/log/vulnera/access.log` (untuk log akses via **Morgan**)
    *   Pastikan direktori `/var/log/vulnera` ada dan memiliki izin tulis yang benar.

4.  **Restart Layanan Fail2Ban:**
    Setelah menyalin file, terapkan konfigurasi baru dengan me-restart layanan.
    ```bash
    sudo systemctl restart fail2ban
    ```

5.  **Verifikasi Status:**
    Periksa apakah kedua jail sudah aktif dan berjalan.
    ```bash
    sudo fail2ban-client status
    ```
    Anda seharusnya akan melihat `vulnera-auth` dan `vulnera-badbots` di dalam daftar jail yang aktif.

---
