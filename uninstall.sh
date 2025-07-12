#!/bin/bash

echo "🧹 Menghapus Bot VPN dari VPS..."

# Nama folder tempat bot disimpan
BOT_DIR="/root/cybervpn"

# Hapus folder bot
if [ -d "$BOT_DIR" ]; then
    rm -rf "$BOT_DIR"
    echo "✅ Folder bot berhasil dihapus: $BOT_DIR"
else
    echo "⚠️ Folder bot tidak ditemukan: $BOT_DIR"
fi

# Hentikan proses bot jika jalan pakai nohup
pkill -f "python3.*main.py" && echo "✅ Bot dihentikan." || echo "⚠️ Tidak ada proses bot aktif ditemukan."

# Hapus file nohup log jika ada
rm -f nohup.out && echo "🧹 Log nohup dihapus."

echo "✅ Bot berhasil di-uninstall."
