# VALLSTORE VPN TUNNELING - Auto Installer
Supported OS: Ubuntu 20.04/22.04/24.04, Debian 11/12/13
Architecture: x86_64 only

## 🚀 Instalasi Cepat
Jalankan perintah ini di VPS murni Anda:
```bash
wget -q https://raw.githubusercontent.com/xyzval/VVIP/main/setup-main.sh && chmod +x setup-main.sh && ./setup-main.sh
```

---

## 🔌 Dokumentasi API Node (Untuk Integrasi Bot Lain)
Sistem ini mendukung integrasi ke banyak Bot Telegram/WhatsApp atau Website menggunakan API Key. Semua pengaturan tombol dan harga dikendalikan langsung dari VPS VPN.

### 🔑 Informasi Kunci
- **Base URL:** `http://IP-VPS-ANDA:8000`
- **API Key:** `VALL-PREMIUM-KEY-99` (Permanen)
- **Header Wajib:** `x-api-key: VALL-PREMIUM-KEY-99`

### 🛠️ Endpoints

#### 1. Mengambil Daftar Produk (GET)
Digunakan untuk menampilkan tombol dan harga secara dinamis di bot.
- **URL:** `/products`
- **Method:** `GET`
- **Response:**
```json
{
  "success": true,
  "server_name": "VPN SERVER SG-1",
  "payment_expiry": 15,
  "data": [
    { "id": "vmess", "name": "🛍️ VMESS (30 Hari)", "price": 4000, "duration": 30 },
    { "id": "vless", "name": "🛍️ VLESS (30 Hari)", "price": 4000, "duration": 30 }
  ]
}
```

#### 2. Membuat Akun VPN (POST)
Digunakan setelah user melakukan pembayaran.
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
- **Response:** Akan mengembalikan detail akun lengkap (Link TLS, Non-TLS, GRPC, dll).

---

## 🛠️ Cara Ubah Harga & Produk
1. Masuk ke VPS VPN Anda.
2. Edit file: `nano /root/vpn-api/index.js`
3. Ubah bagian `const products`.
4. Restart API: `pm2 restart vpn-node-api`

---
**Official Repository by xyzval**
