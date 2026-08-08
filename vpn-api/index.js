const express = require('express');
const { exec } = require('child_process');
const bodyParser = require('body-parser');
const app = express();
const port = 8000;

// API KEY UNTUK KEAMANAN
const SECRET_KEY = 'VALL-PREMIUM-KEY-99';

app.use(bodyParser.json());

// Middleware untuk cek API KEY
const auth = (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (apiKey === SECRET_KEY) {
        next();
    } else {
        res.status(401).json({ error: 'Unauthorized: API Key Salah' });
    }
};

// Endpoint untuk mengambil daftar produk
app.get('/products', auth, (req, res) => {
    const products = [
        { id: "vmess", name: "🛍️ VMESS (30 Hari)", price: 4000, duration: 30, type: "premium" },
        { id: "vless", name: "🛍️ VLESS (30 Hari)", price: 4000, duration: 30, type: "premium" },
        { id: "trojan", name: "🛍️ TROJAN (30 Hari)", price: 4000, duration: 30, type: "premium" },
        { id: "ssh", name: "🛍️ SSH WS (30 Hari)", price: 4000, duration: 30, type: "premium" },
        { id: "vmess_trial", name: "🎁 TRIAL VMESS (15m)", price: 0, duration: 1, type: "trial" },
        { id: "vless_trial", name: "🎁 TRIAL VLESS (15m)", price: 0, duration: 1, type: "trial" },
        { id: "trojan_trial", name: "🎁 TRIAL TROJAN (15m)", price: 0, duration: 1, type: "trial" },
        { id: "ssh_trial", name: "🎁 TRIAL SSH (15m)", price: 0, duration: 1, type: "trial" }
    ];

    res.json({
        success: true,
        server_name: "VPN SERVER SG-1",
        payment_expiry: 15,
        data: products
    });
});

app.post('/create', auth, (req, res) => {
    const { user, proto, duration } = req.body;
    
    // Fallback username jika kosong (untuk trial)
    const finalUser = user || "trial" + Math.floor(Math.random() * 10000);
    const finalProto = proto.replace('_trial', ''); // Handle trial ID

    if (!finalProto || !duration) {
        return res.status(400).json({ error: 'Data tidak lengkap' });
    }

    let cmd = '';
    if (finalProto === 'vmess') cmd = `(echo ${finalUser}; echo 2; echo 100; echo ${duration}; echo valls.cloud) | addws`;
    else if (finalProto === 'vless') cmd = `(echo ${finalUser}; echo 2; echo 100; echo ${duration}; echo valls.cloud) | addvless`;
    else if (finalProto === 'trojan') cmd = `(echo ${finalUser}; echo 2; echo 100; echo ${duration}; echo valls.cloud) | addtr`;
    else if (finalProto === 'ssh') cmd = `(echo ${finalUser}; echo ${finalUser}123; echo ${duration}) | addssh`;
    else return res.status(400).json({ error: 'Protokol tidak dikenal' });

    exec(cmd, (err, stdout, stderr) => {
        if (err) return res.status(500).json({ error: 'Gagal eksekusi script' });
        
        const lines = stdout.split('\n');
        let link = '';
        lines.forEach(l => {
            if (l.includes('vmess://') || l.includes('vless://') || l.includes('trojan://') || l.includes('SSH WS')) {
                link = l.trim();
            }
        });

        res.json({ success: true, protocol: finalProto, user: finalUser, link: link });
    });
});

app.listen(port, '0.0.0.0', () => {
    console.log('Node API running on port ' + port);
});
