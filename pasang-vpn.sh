#!/bin/bash
# ==========================================
# VPN BRIDGE INSTALLER FOR TELEBOT (PRO VERSION)
# ==========================================

clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[1;97;101m          VPN BRIDGE INSTALLER            \e[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""

# --- AUTO DETECT BOT DIRECTORY ---
echo "⏳ Mencari folder bot Anda..."
BOT_DIR=""

if [ -f "bot.js" ]; then
    BOT_DIR=$(pwd)
else
    SEARCH_DIR=$(find /root -name "bot.js" -maxdepth 3 2>/dev/null | head -n 1)
    if [ -n "$SEARCH_DIR" ]; then
        BOT_DIR=$(dirname "$SEARCH_DIR")
    fi
fi

if [ -z "$BOT_DIR" ]; then
    echo -e "\033[1;31m❌ ERROR: File bot.js tidak ditemukan!\033[0m"
    read -p "Masukkan path folder bot Anda manual (Contoh: /root/telebot): " BOT_DIR_MANUAL
    if [ -d "$BOT_DIR_MANUAL" ] && [ -f "$BOT_DIR_MANUAL/bot.js" ]; then
        BOT_DIR=$BOT_DIR_MANUAL
    else
        echo "❌ Folder tetap tidak ditemukan. Batalkan."
        exit 1
    fi
fi

cd "$BOT_DIR"
echo -e "\033[1;32m✅ Folder ditemukan: $BOT_DIR\033[0m"
echo -e ""

# 1. Input Data
if [ -z "$IP_VPN" ]; then
    read -p "Masukkan IP VPS VPN Anda: " IP_VPN
fi
if [ -z "$API_KEY" ]; then
    read -p "Masukkan API KEY (Default: VALL-PREMIUM-KEY-99): " API_KEY
fi
API_KEY=${API_KEY:-VALL-PREMIUM-KEY-99}

# 3. Download the JS Installer
echo "⏳ Mengunduh mesin instalasi..."
wget -qO final_installer.js https://raw.githubusercontent.com/xyzval/VVIP/main/final_installer.js

# 4. Install Library
echo "⏳ Memasang library axios..."
npm install axios --save >/dev/null 2>&1

# 5. Jalankan Instalasi via Node.js secara langsung
export IP_VPN=$IP_VPN
export API_KEY=$API_KEY
node final_installer.js
rm final_installer.js

echo -e "\033[1;32m✅ INTEGRASI BERHASIL! Menghidupkan ulang bot...\033[0m"
pm2 restart all
rm pasang-vpn.sh 2>/dev/null
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "         PROSES SELESAI, CEK BOT ANDA!       "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
