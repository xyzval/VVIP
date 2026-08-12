#!/bin/bash
# ==========================================
# VPN BRIDGE INSTALLER FOR TELEBOT (ULTRA)
# ==========================================

clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[1;97;101m          VPN BRIDGE INSTALLER            \e[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""

# --- AUTO DETECT BOT DIRECTORY ---
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
    BOT_DIR="/root/telebot"
fi

cd "$BOT_DIR" || exit 1

# 1. Input Data
if [ -z "$IP_VPN" ]; then
    read -rp "Masukkan IP VPS VPN Anda: " IP_VPN
fi

if [ -z "$IP_VPN" ]; then 
    echo -e "\033[1;31m❌ ERROR: IP VPN tidak boleh kosong!\033[0m"
    exit 1
fi

# Ensure IP_VPN is exported for Python
export IP_VPN=$IP_VPN
API_KEY="VALL-PREMIUM-KEY-99"

# 2. Backup bot.js
cp bot.js bot.js.bak 2>/dev/null

# 3. Install Library
echo "⏳ Memasang library axios..."
npm install axios --save >/dev/null 2>&1

# 4. Injeksi Kode menggunakan Python (ULTRA ROBUST)
echo "⏳ Menyuntikkan fitur VPN ke bot.js..."
python3 - <<'EOF'
import os
import re

ip_vpn = os.getenv("IP_VPN", "104.207.93.176")
api_key = "VALL-PREMIUM-KEY-99"

with open('bot.js', 'r') as f:
    code = f.read()

# CLEANUP
code = code.replace('\nconst waitingVPN = {};\n', '\n')
code = code.replace('const waitingVPN = {};', '')
code = re.sub(r'// --- VPN INTEGRATION START ---.*?// --- VPN INTEGRATION END ---', '', code, flags=re.DOTALL)

# 1. State
if 'const waitingVPN = {};' not in code:
    code = code.replace('const orders = {};', 'const orders = {};\nconst waitingVPN = {};')

# 2. Keyboard
kb_func = """const mainKeyboard = (ctx) => {
    const keyboard = [
        [
            { text: "📱 Beli Apps Premium",  callback_data: "buy_apps"  },
            { text: "🌊 Beli Akun Alibaba", callback_data: "buy_alibaba" }
        ],
        [
            { text: "💻 Beli VPS Dedicated",  callback_data: "buy_vps" }
        ],
        [
            { text: "🛡️ Beli Akun VPN", callback_data: "buy_vpn" }
        ],
        [
            { text: "📜 Syarat & Ketentuan", callback_data: "snk_menu" }
        ]
    ];
    if (isOwner(ctx)) {
        keyboard.push([{ text: "🕊️ Owner Menu", callback_data: "owner_menu" }]);
    }
    return { inline_keyboard: keyboard };
};"""
code = re.sub(r'const mainKeyboard = \(ctx\) => \{.*?return \{ inline_keyboard: keyboard \};\s+\};', kb_func, code, flags=re.DOTALL)

# 3. Actions
new_actions = """
    // --- VPN INTEGRATION START ---
    bot.action("buy_vpn", async (ctx) => {
        try { await ctx.answerCbQuery().catch(() => {}); } catch (e) {}
        ctx.reply("⏳ *Sedang menghubungkan ke server...*", { parse_mode: "Markdown" });
        try {
            const res = await axios.get("http://""" + ip_vpn + """:8000/products", {
                headers: { "x-api-key": "VALL-PREMIUM-KEY-99" }, timeout: 10000
            });
            if (res.data && res.data.success) {
                const products = res.data.data;
                const globalExp = res.data.payment_expiry || 15;
                const keyboard = [];
                keyboard.push([{ text: "─────[ PAKET PREMIUM ]─────", callback_data: "none" }]);
                products.filter(p => p.type === 'premium').forEach(p => {
                    keyboard.push([{ text: p.name + " - Rp" + toRupiah(p.price), callback_data: "vpn_order|" + p.id + "|" + p.price + "|" + p.duration + "|" + globalExp }]);
                });
                keyboard.push([{ text: "─────[ TRIAL GRATIS ]─────", callback_data: "none" }]);
                const trialRow = [];
                products.filter(p => p.type === 'trial').forEach((p) => {
                    trialRow.push({ text: p.name.replace('⚡ ', ''), callback_data: "vpn_order|" + p.id + "|" + p.price + "|" + p.duration + "|" + globalExp });
                    if (trialRow.length === 2) { keyboard.push([...trialRow]); trialRow.length = 0; }
                });
                if (trialRow.length > 0) keyboard.push([...trialRow]);
                keyboard.push([{ text: "🔄 Kembali ke Menu", callback_data: "back_menu" }]);
                
                const header = `<code>╔════════════════════════╗</code>\\n` +
                               `<code>    🛡️ PREMIUM VPN SERVER 🛡️ </code>\\n` +
                               `<code>╚════════════════════════╝</code>\\n` +
                               `📡 <b>Server:</b> <code>${res.data.server_name}</code>\\n` +
                               `📍 <b>Region:</b> <code>Singapore 🇸🇬</code>\\n` +
                               `⚡ <b>Latency:</b> <code>15ms - 40ms</code>\\n` +
                               `🟢 <b>Status:</b> <code>Online / High Speed</code>\\n` +
                               `<code>━━━━━━━━━━━━━━━━━━━━━━━━</code>\\n` +
                               `<i>Silakan pilih paket VPN di bawah ini:</i>`;
                return ctx.reply(header, { parse_mode: "HTML", reply_markup: { inline_keyboard: keyboard } });
            }
        } catch (err) { return ctx.reply("❌ Server VPN sedang maintenance."); }
    });

    bot.action(/vpn_order\\|(.+)/, async (ctx) => {
        try { await ctx.answerCbQuery().catch(() => {}); } catch (e) {}
        const parts = ctx.match[1].split("|");
        const proto = parts[0];
        const price = parseInt(parts[1]);
        const duration = parts[2];
        const payExp = parts[3];
        const fromId = ctx.from.id;
        if (proto === "none") return;
        if (price === 0) {
            ctx.reply("⏳ *Sedang menyiapkan akun TRIAL 15 Menit...*", { parse_mode: "Markdown" });
            try {
                const res = await axios.post("http://""" + ip_vpn + """:8000/create", { proto, duration: "1" }, { headers: { "x-api-key": "VALL-PREMIUM-KEY-99" }, timeout: 60000 });
                if (res.data && res.data.success) {
                    return ctx.reply("✅ *AKUN TRIAL BERHASIL!*\\n━━━━━━━━━━━━━━━━━━\\n👤 *User:* `" + res.data.user + "`\\n⏰ *Aktif:* 15 Menit\\n━━━━━━━━━━━━━━━━━━\\n<pre>" + res.data.link + "</pre>", { parse_mode: "HTML" });
                }
            } catch (err) { return ctx.reply("❌ Gagal membuat trial."); }
            return;
        }
        waitingVPN[fromId] = { proto, price, duration, payExp };
        return ctx.reply("✍️ *Silakan masukkan Username yang Anda inginkan:*", { parse_mode: "Markdown" });
    });

    bot.action(/vpn_ip\\|(.+)/, async (ctx) => {
        try { await ctx.answerCbQuery().catch(() => {}); } catch (e) {}
        const fromId = ctx.from.id;
        const data = waitingVPN[fromId];
        if (!data) return ctx.reply("❌ Sesi berakhir. Silakan order ulang.");
        const parts = ctx.match[1].split("|");
        const ipLimit = parts[0];
        const finalPrice = parseInt(parts[1]);
        data.iplimit = ipLimit;
        data.price = finalPrice;
        const payKeyboard = [
            [{ text: "💳 Otomatis (QRIS)", callback_data: "vpn_pay_auto|" + data.proto + "|" + data.user + "|" + finalPrice + "|" + data.duration + "|" + data.payExp + "|" + ipLimit }],
            [{ text: "🏦 Manual", callback_data: "vpn_pay_manual|" + data.proto + "|" + data.user + "|" + finalPrice + "|" + data.duration + "|" + data.payExp + "|" + ipLimit }]
        ];
        const confirmMsg = "🛒 *DETAIL PESANAN VPN*\\n━━━━━━━━━━━━━━━━━━\\n📦 *Produk:* `VPN " + data.proto.toUpperCase() + " PREMIUM`\\n👤 *User:* `" + data.user + "`\\n📱 *Limit:* `" + ipLimit + " IP/Device`\\n📅 *Durasi:* `" + data.duration + " Hari`\\n💰 *Total:* *Rp" + toRupiah(finalPrice) + "*\\n━━━━━━━━━━━━━━━━━━\\nSilakan pilih metode pembayaran di bawah:";
        return ctx.editMessageText(confirmMsg, { parse_mode: "Markdown", reply_markup: { inline_keyboard: payKeyboard } });
    });

    bot.action(/vpn_pay_(auto|manual)\\|(.+)/, async (ctx) => {
        try { await ctx.answerCbQuery().catch(() => {}); } catch (e) {}
        const method = ctx.match[1];
        const parts = ctx.match[2].split("|");
        const proto = parts[0];
        const user = parts[1];
        const price = parseInt(parts[2]);
        const duration = parts[3];
        const payExpMin = parseInt(parts[4]) || 15;
        const ipLimit = parts[5] || "2";
        const fromId = ctx.from.id;
        const name = "VPN " + proto.toUpperCase() + " (" + ipLimit + " IP) - " + user;
        const pType = method === "auto" ? config.paymentGateway : "manual";
        try {
            const pay = await createPayment(pType, price, config, { customerName: ctx.from.first_name, description: name });
            orders[fromId] = { type: "vpn_premium", proto, username: user, duration, iplimit: ipLimit, name, amount: pay.amount || price, fee: pay.fee || 0, orderId: pay.orderId, paymentType: pType, chatId: ctx.chat.id, expireAt: Date.now() + payExpMin * 60 * 1000 };
            delete waitingVPN[fromId];
            if (method === "auto") {
                const caption = "✨ *TAGIHAN PEMBAYARAN VPN* ✨\\n━━━━━━━━━━━━━━━━━━\\n📦 *Produk:* `" + name + "`\\n💰 *Total:* *Rp" + toRupiah(pay.amount || price) + "*\\n⏰ *Masa Berlaku:* " + payExpMin + " Menit\\n━━━━━━━━━━━━━━━━━━\\nSistem akan mengirimkan detail akun secara otomatis setelah lunas.";
                const qrMsg = await ctx.replyWithPhoto(pay.qris, { caption, parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "❌ Batalkan", callback_data: "cancel_order" }]] } });
                orders[fromId].qrMessageId = qrMsg.message_id;
            } else {
                await ctx.reply("🏦 *PEMBAYARAN MANUAL*\\n\\nSilakan transfer ke:\\nDANA: 083153170199\\n\\nKirim bukti transfer ke Admin @WendiVpn", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "❌ Batalkan", callback_data: "cancel_order" }]] } });
            }
            startCheck(fromId, ctx);
        } catch (e) { ctx.reply("❌ Gagal membuat tagihan."); }
    });
    // --- VPN INTEGRATION END ---"""
code = code.replace('// ===== CALLBACK QUERIES =====', '// ===== CALLBACK QUERIES =====\n' + new_actions)

# 4. Input Handler
input_logic = """if (!isCmd && !waitingVPN[fromId]) return;
        if (waitingVPN[fromId]) {
            const data = waitingVPN[fromId];
            const user = (ctx.message.text || "").trim();
            if (!/^[a-zA-Z0-9]+$/.test(user)) return ctx.reply("❌ Username tidak valid. Gunakan huruf & angka saja.");
            waitingVPN[fromId].user = user;
            const ipKeyboard = [
                [{ text: "📱 1 IP/DEVICE (Rp4.000)", callback_data: "vpn_ip|1|4000" }],
                [{ text: "📱 2 IP/DEVICE (Rp6.000)", callback_data: "vpn_ip|2|6000" }],
                [{ text: "📱 4 IP/DEVICE (Rp8.000)", callback_data: "vpn_ip|4|8000" }],
                [{ text: "❌ Batalkan", callback_data: "back_menu" }]
            ];
            return ctx.reply("🛡️ *PILIH LIMIT IP/DEVICE*\\n━━━━━━━━━━━━━━━━━━\\nSetiap akun akan dibatasi jumlah login perangkatnya sesuai pilihan Anda.\\n\\nSilakan pilih:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: ipKeyboard } });
        }"""
code = code.replace('if (!isCmd) return;', input_logic)

# 5. Delivery
delivery = """if (o.type === "vpn_premium") {
                await ctx.telegram.sendMessage(o.chatId, "⏳ *Pembayaran Diterima!*\\nSedang membuat akun premium Anda...", { parse_mode: "Markdown" });
                try {
                    const res = await axios.post("http://""" + ip_vpn + """:8000/create", { user: o.username, proto: o.proto, duration: o.duration, iplimit: o.iplimit }, { headers: { "x-api-key": "VALL-PREMIUM-KEY-99" }, timeout: 60000 });
                    if (res.data && res.data.success) {
                        const finishMsg = "✅ *PESANAN SELESAI!*\\n━━━━━━━━━━━━━━━━━━\\nTerima kasih telah berlangganan! Berikut adalah detail akun Anda:\\n\\n<pre>" + res.data.link + "</pre>";
                        return ctx.telegram.sendMessage(o.chatId, finishMsg, { parse_mode: "HTML" });
                    }
                } catch (err) { return ctx.telegram.sendMessage(o.chatId, "❌ Gagal membuat akun. Hubungi admin."); }
            }"""
code = code.replace('if (o.type === "panel") {', delivery + '\n            if (o.type === "panel") {')

with open('bot.js', 'w') as f:
    f.write(code)
EOF

pm2 restart all 2>/dev/null || node bot.js
echo -e "\033[1;32m✅ INTEGRASI BERHASIL!\033[0m"
