const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const app = express();
app.use(express.json());

const SECRET_KEY = 'VALL-PREMIUM-KEY-99';
const DOMAIN = fs.existsSync('/etc/xray/domain') ? fs.readFileSync('/etc/xray/domain', 'utf8').trim() : 'localhost';

const auth = (req, res, next) => {
    if (req.headers['x-api-key'] === SECRET_KEY) next();
    else res.status(401).json({ error: 'Unauthorized' });
};

app.get('/products', auth, (req, res) => {
    res.json({
        success: true,
        server_name: '🇸🇬 SG-VVIP PREMIUM SERVER',
        payment_expiry: 15,
        data: [
            { id: 'vmess', name: '🛍️ VMESS PREMIUM', price: 4000, duration: 30, type: 'premium' },
            { id: 'vless', name: '🛍️ VLESS PREMIUM', price: 4000, duration: 30, type: 'premium' },
            { id: 'trojan', name: '🛍️ TROJAN PREMIUM', price: 4000, duration: 30, type: 'premium' },
            { id: 'ssh', name: '🛍️ SSH WS PREMIUM', price: 4000, duration: 30, type: 'premium' },
            { id: 'vmess_trial', name: '⚡ TRIAL VMESS', price: 0, duration: 1, type: 'trial' },
            { id: 'vless_trial', name: '⚡ TRIAL VLESS', price: 0, duration: 1, type: 'trial' },
            { id: 'trojan_trial', name: '⚡ TRIAL TROJAN', price: 0, duration: 1, type: 'trial' },
            { id: 'ssh_trial', name: '⚡ TRIAL SSH', price: 0, duration: 1, type: 'trial' }
        ]
    });
});

app.post('/create', auth, (req, res) => {
    let { user, proto, duration, iplimit } = req.body;
    const isTrial = proto.endsWith('_trial');
    const actualProto = isTrial ? proto.replace('_trial', '') : proto;
    if (isTrial && !user) user = 'trial' + Math.floor(1000 + Math.random() * 9000);
    
    const finalIpLimit = iplimit || "2";

    let cmd = '';
    if (actualProto === 'vmess') cmd = `(echo "${user}"; echo "${finalIpLimit}"; echo "0"; echo "${duration}"; echo "${DOMAIN}") | addws`;
    else if (actualProto === 'vless') cmd = `(echo "${user}"; echo "${finalIpLimit}"; echo "0"; echo "${duration}"; echo "${DOMAIN}") | addvless`;
    else if (actualProto === 'trojan') cmd = `(echo "${user}"; echo "${finalIpLimit}"; echo "0"; echo "${duration}"; echo "${DOMAIN}") | addtr`;
    else if (actualProto === 'ssh') cmd = `(echo "${user}"; echo "${user}123"; echo "${duration}") | addssh`;

    exec(cmd, (err, stdout) => {
        if (err) return res.status(500).json({ error: 'Failed' });
        const clean = stdout.replace(/\x1B\[[0-9;]*[a-zA-Z]/g, '');
        const parts = clean.split("◇━━━━━━━━━━━━━━━━━◇");
        let result = parts.length > 2 ? "◇━━━━━━━━━━━━━━━━━◇" + parts.slice(2).join("◇━━━━━━━━━━━━━━━━━◇") : clean;
        
        if (isTrial) {
            exec(`echo "/usr/local/sbin/hapus-trial ${user} ${actualProto}" | at now + 15 minutes`);
            result = result.replace(/Aktif Selama\s+:\s+\d+\s+Hari/g, 'Aktif Selama     : 15 Menit');
            result += "\n\n⚠️ AKUN INI ADALAH TRIAL 15 MENIT\nAKUN AKAN DIHAPUS OTOMATIS.";
        }

        res.json({ success: true, link: result.trim(), user: user });
    });
});

app.listen(8000, '0.0.0.0', () => console.log('Premium API Node Active with Dynamic IP Limit'));
