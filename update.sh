#!/bin/bash

# URL sumber update
YOGZ_VPN="https://raw.githubusercontent.com/waru88/v3/main/menu/"
ZIP_FILE="menu.zip"
DOWNLOAD_URL="${YOGZ_VPN}${ZIP_FILE}"

# Proses update
echo "Mengunduh file update dari ${DOWNLOAD_URL}..."
wget -q ${DOWNLOAD_URL} -O ${ZIP_FILE}

if [ $? -eq 0 ]; then
    echo "Berhasil mengunduh ${ZIP_FILE}."

    echo "Ekstrak file..."
    unzip -o ${ZIP_FILE} >/dev/null

    echo "Set permission dan pindahkan file..."
    chmod +x *
    mv -f * /usr/bin/ 2>/dev/null

    echo "Bersihkan file sementara..."
    rm -f ${ZIP_FILE}

    echo "Update selesai!"

    # Jalankan menu
    echo "Menjalankan menu..."
    menu
else
    echo "Gagal mengunduh file. Cek koneksi atau URL."
fi

# Kembali ke home directory
cd