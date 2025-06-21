#!/bin/bash

# Direktori bot di VPS
BOT_DIR="/root/VVIP/bot"

# Masuk ke direktori bot
cd $BOT_DIR || exit

# Tarik update terbaru dari GitHub
echo "🔄 Menarik update dari GitHub..."
git pull origin main

# Pastikan semua permission benar
chmod +x *.py

# Hentikan bot yang sedang berjalan (jika pakai screen atau tmux)
echo "🛑 Menghentikan bot lama..."
pkill -f bot.py

# Jalankan ulang bot
echo "🚀 Menjalankan ulang bot..."
nohup python3 bot.py > log.txt 2>&1 &

echo "✅ Update selesai dan bot sudah dijalankan ulang!"
