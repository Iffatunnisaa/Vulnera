#!/bin/bash

# --- Ambil argumen ---
FILE_ID="1E0E1541f2-ciTqvG9ZCnGIRxIaJtn7LK"
FILE_NAME="final_model_tf.zip"

# --- Validasi input ---
if [ -z "$FILE_ID" ] || [ -z "$FILE_NAME" ]; then
  echo "Error: Argumen tidak lengkap."
  echo "Usage: $0 FILE_ID OUTPUT_FILENAME"
  exit 1
fi

# --- Cek dependensi gdown ---
if ! command -v gdown &> /dev/null; then
    echo "Error: 'gdown' tidak ditemukan. Silakan install dengan 'pip install gdown'"
    exit 1
fi

# --- Unduh file ---
echo "Mulai mengunduh dari Google Drive..."
gdown "${FILE_ID}" -O "${FILE_NAME}"

# --- Proses file jika unduhan berhasil ---
if [ $? -eq 0 ]; then
    echo "Unduhan berhasil!"
    echo "---------------------------------"
    
    # Dapatkan nama direktori dari nama file
    DIR_NAME="${FILE_NAME%.*}"

    # Cek jenis file dan ekstrak
    echo "Mengekstrak file ${FILE_NAME}..."
    case "$FILE_NAME" in
        *.zip)
            unzip -q "$FILE_NAME" # -q untuk mode senyap (quiet)
            ;;
        *.tar.gz)
            tar -xzf "$FILE_NAME"
            ;;
        *)
            echo "Jenis file tidak didukung untuk ekstraksi otomatis. Selesai."
            exit 0
            ;;
    esac
    
    # Hapus file arsip setelah diekstrak untuk menghemat ruang
    rm "$FILE_NAME"
    echo "Arsip ${FILE_NAME} telah dihapus."

    # Cek apakah ada folder ganda
    # Ini adalah implementasi cerdas dari ide Anda!
    if [ -d "$DIR_NAME/$DIR_NAME" ]; then
        # Pindahkan semua isi dari folder dalam ke folder luar
        mv "$DIR_NAME/$DIR_NAME"/* "$DIR_NAME/"
        # Hapus folder dalam yang sekarang kosong
        rmdir "$DIR_NAME/$DIR_NAME"
    fi
    
    echo "---------------------------------"
    echo "Proses selesai. Model siap digunakan di folder: ${DIR_NAME}"

else
    echo "❌ Unduhan gagal."
fi