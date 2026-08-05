# 📖 Panduan Integrasi Bot VPN (Dynamic API)

Gunakan panduan ini untuk menghubungkan Bot Telegram lain ke VPS VPN Anda. Dengan kode ini, bot akan menampilkan tombol VPN secara otomatis hanya jika server VPN menyala.

## 🛠️ Persiapan
Pastikan bot tujuan menggunakan library `telegraf` dan sudah terinstall `axios`.
```bash
npm install axios
```

---

## 📝 Potongan Kode (Copy-Paste)

### 1. Bagian Atas (Inisialisasi)
Letakkan di bagian awal file `bot.js` Anda:
```javascript
const axios = require("axios");
const waitingVPN = {}; // Menampung status pembelian user
```

### 2. Bagian Menu Utama (Auto-Detect Tombol)
Cari fungsi yang mengatur tombol menu utama (biasanya `mainKeyboard`), lalu masukkan logika ini di dalamnya:
```javascript
// Gantilah IP di bawah dengan IP VPS VPN Anda
const vpnApiUrl = "http://104.207.93.176:8000"; 
const vpnApiKey = "VALL-PREMIUM-KEY-99";

try {
    const res = await axios.get(`${vpnApiUrl}/products`, {
        headers: { "x-api-key": vpnApiKey },
        timeout: 2000
    });
    if (res.data && res.data.success) {
        // Tambahkan tombol ke daftar keyboard bot Anda
        keyboard.push([{ text: "🛡️ Beli Akun VPN", callback_data: "buy_vpn" }]);
    }
} catch (e) {
    // Tombol otomatis hilang jika VPS VPN mati/API dihapus
}
```

### 3. Bagian Penangkap Input (Username)
Cari bagian `bot.on("text", ...)` dan masukkan kode ini sebelum pengecekan perintah (isCmd):
```javascript
if (waitingVPN[ctx.from.id]) {
    const proto = waitingVPN[ctx.from.id];
    const user = ctx.message.text.trim();
    delete waitingVPN[ctx.from.id];

    if (!/^[a-zA-Z0-9]+$/.test(user)) return ctx.reply("❌ Username tidak valid.");

    // Lanjutkan ke proses pembayaran asli bot Anda...
    // Setelah lunas, panggil API /create di VPS VPN
}
```

---

## 🔑 Informasi Rahasia API
- **URL Pusat:** `http://104.207.93.176:8000`
- **API Key:** `VALL-PREMIUM-KEY-99`

---
**Official Integration Guide for xyzval VVIP Project**
