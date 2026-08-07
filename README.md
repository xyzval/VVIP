# VALLSTORE VPN TUNNELING - Auto Installer
Supported OS: Ubuntu 20.04/22.04/24.04, Debian 11/12/13
Architecture: x86_64 only

## 🚀 Instalasi Cepat (VPS VPN)
Jalankan perintah ini di VPS murni Anda:
```bash
wget -q https://raw.githubusercontent.com/xyzval/VVIP/main/setup-main.sh && chmod +x setup-main.sh && ./setup-main.sh
```

---

## 🤖 Integrasi Bot Jualan (VPS BOT)
Jika Anda ingin menghubungkan Bot Telegram lain ke server VPN ini secara otomatis:
```bash
wget -qO pasang-vpn.sh https://raw.githubusercontent.com/xyzval/VVIP/main/pasang-vpn.sh && bash pasang-vpn.sh
```

---

## 🔌 Dokumentasi API Node (Untuk Developer)
Sistem ini mendukung integrasi ke banyak Bot Telegram/WhatsApp atau Website menggunakan API Key. Semua pengaturan tombol dan harga dikendalikan langsung dari VPS VPN.

### 🔑 Informasi Kunci
- **Base URL:** `http://IP-VPS-ANDA:8000`
- **API Key:** `VALL-PREMIUM-KEY-99` (Permanen)
- **Header Wajib:** `x-api-key: VALL-PREMIUM-KEY-99`

### 🛠️ Endpoints

#### 1. Mengambil Daftar Produk (GET)
- **URL:** `/products`
- **Method:** `GET`
- **Deskripsi:** Mengambil daftar tombol, harga, dan durasi secara real-time.

#### 2. Membuat Akun VPN (POST)
- **URL:** `/create`
- **Method:** `POST`
- **Body (JSON):**
```json
{
  "user": "nama_pembeli",
  "proto": "vmess", 
  "duration": "30"
}
```

---

## 🛠️ Cara Ubah Harga & Produk (Pusat Kendali)
1. Masuk ke VPS VPN Anda.
2. Edit file: `nano /root/vpn-api/index.js`
3. Ubah bagian `const products` (misal harga: 4000).
4. Restart API agar semua Bot terupdate: `pm2 restart vpn-node-api`

---
**Official Repository by xyzval**
