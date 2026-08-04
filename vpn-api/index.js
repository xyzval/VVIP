const express = require('express');
const { exec } = require('child_process');
const bodyParser = require('body-parser');
const app = express();
const port = 8000;

// API KEY UNTUK KEAMANAN (SILAKAN SIMPAN INI)
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

app.post('/create', auth, (req, res) => {
    const { user, proto, duration } = req.body;
    
    if (!user || !proto || !duration) {
        return res.status(400).json({ error: 'Data tidak lengkap' });
    }

    let cmd = '';
    // Otomasi input ke script VPS
    if (proto === 'vmess') cmd = `(echo ${user}; echo 2; echo 100; echo ${duration}; echo valls.cloud) | addws`;
    else if (proto === 'vless') cmd = `(echo ${user}; echo 2; echo 100; echo ${duration}; echo valls.cloud) | addvless`;
    else if (proto === 'trojan') cmd = `(echo ${user}; echo 2; echo 100; echo ${duration}; echo valls.cloud) | addtr`;
    else if (proto === 'ssh') cmd = `(echo ${user}; echo ${user}123; echo ${duration}) | addssh`;

    exec(cmd, (err, stdout, stderr) => {
        if (err) return res.status(500).json({ error: 'Gagal eksekusi script' });
        
        // Cari link di output
        const lines = stdout.split('\n');
        let link = '';
        lines.forEach(l => {
            if (l.includes('vmess://') || l.includes('vless://') || l.includes('trojan://') || l.includes('SSH WS')) {
                link = l.trim();
            }
        });

        res.json({ success: true, protocol: proto, user: user, link: link });
    });
});

app.listen(port, '0.0.0.0', () => {
    console.log('Node API running on port ' + port);
});
