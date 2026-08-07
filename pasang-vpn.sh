#!/bin/bash
# ==========================================
# VPN BRIDGE INSTALLER FOR TELEBOT (ULTIMATE FIX)
# ==========================================

clear
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\e[1;97;101m          VPN BRIDGE INSTALLER            \e[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e ""

# 1. AUTO DETECT BOT DIRECTORY
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
    read -p "Masukkan path folder bot Anda manual (Contoh: /root/telebot): " BOT_DIR
fi
cd "$BOT_DIR" || exit 1

# 2. Input Data
if [ -z "$IP_VPN" ]; then
    read -p "Masukkan IP VPS VPN Anda: " IP_VPN
fi
if [ -z "$IP_VPN" ]; then echo "❌ IP tidak boleh kosong!"; exit 1; fi
API_KEY="VALL-PREMIUM-KEY-99"

# 3. Backup
if [ ! -f "bot.js.bak" ]; then
    cp bot.js bot.js.bak
    echo -e "\033[1;32m✅ Backup bot.js.bak dibuat.\033[0m"
fi

# 4. Install Library
echo "⏳ Memasang library axios..."
npm install axios --save >/dev/null 2>&1

# 5. Jalankan Injeksi Kode langsung dengan Node
# Kita gunakan heredoc dengan kutip tunggal agar shell tidak merusak variabel JS
export IP_VPN=$IP_VPN
export API_KEY=$API_KEY

node - <<'EOF_NODE'
const fs = require('fs');
const code = fs.readFileSync('bot.js.bak', 'utf8');

const ip = process.env.IP_VPN;
const key = process.env.API_KEY;

let newCode = code;

// State
if (!newCode.includes('const waitingVPN = {};')) {
    newCode = newCode.replace('const orders = {};', 'const orders = {};\nconst waitingVPN = {};');
}

// Keyboard
const vpnLogic = `
    try {
        const res = await axios.get("http://${ip}:8000/products", {
            headers: { "x-api-key": "${key}" },
            timeout: 3000
        });
        if (res.data && res.data.success) {
            keyboard.splice(2, 0, [{ text: "🛡️ Beli Akun VPN", callback_data: "buy_vpn" }]);
        }
    } catch (e) {}
`;

const mainKeyboardFunc = `const mainKeyboard = async (ctx) => {
    const keyboard = [
        [{ text: "📱 Beli Apps Premium", callback_data: "buy_apps" }, { text: "🌊 Beli Akun Alibaba", callback_data: "buy_alibaba" }],
        [{ text: "💻 Beli VPS Dedicated", callback_data: "buy_vps" }],
        [{ text: "📜 Syarat & Ketentuan", callback_data: "snk_menu" }]
    ];
${vpnLogic}
    if (isOwner(ctx)) keyboard.push([{ text: "🕊️ Owner Menu", callback_data: "owner_menu" }]);
    return { inline_keyboard: keyboard };
};`;

newCode = newCode.replace(/const mainKeyboard = \(ctx\) => \{[\s\S]*?return \{ inline_keyboard: keyboard \};\s+\};/s, mainKeyboardFunc);
newCode = newCode.replace(/reply_markup: mainKeyboard\(ctx\)/g, 'reply_markup: await mainKeyboard(ctx)');

// Actions
const actions = `
    // --- VPN INTEGRATION START ---
    bot.action("buy_vpn", async (ctx) => {
        try { await ctx.answerCbQuery().catch(() => {}); } catch (e) {}
        ctx.reply("⏳ *Mengambil daftar produk dari server...*", { parse_mode: "Markdown" });
        try {
            const res = await axios.get("http://${ip}:8000/products", { headers: { "x-api-key": "${key}" }, timeout: 10000 });
            if (res.data && res.data.success) {
                const products = res.data.data;
                const globalExp = res.data.payment_expiry || 15;
                const keyboard = [];
                keyboard.push([{ text: "💎 --- PAKET PREMIUM (30 HARI) --- 💎", callback_data: "none" }]);
                products.filter(p => p.type === 'premium').forEach(p => {
                    keyboard.push([{ text: p.name + " - Rp" + toRupiah(p.price), callback_data: "vpn_order|" + p.id + "|" + p.price + "|" + p.duration + "|" + globalExp }]);
                });
                keyboard.push([{ text: "🎁 --- PAKET TRIAL (15 MENIT) --- 🎁", callback_data: "none" }]);
                const trialRow = [];
                products.filter(p => p.type === 'trial').forEach((p) => {
                    trialRow.push({ text: p.name.replace('🎁 TRIAL ', ''), callback_data: "vpn_order|" + p.id + "|" + p.price + "|" + p.duration + "|" + globalExp });
                    if (trialRow.length === 2) { keyboard.push([...trialRow]); trialRow.length = 0; }
                });
                if (trialRow.length > 0) keyboard.push([...trialRow]);
                keyboard.push([{ text: "🔄 Back To Menu", callback_data: "back_menu" }]);
                return ctx.reply("🛡️ *SERVER: " + res.data.server_name + "*\\nSilakan pilih paket VPN Anda:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: keyboard } });
            }
        } catch (err) { return ctx.reply("❌ Server VPN OFFLINE."); }
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
                const res = await axios.post("http://${ip}:8000/create", { proto, duration: "1" }, { headers: { "x-api-key": "${key}" }, timeout: 60000 });
                if (res.data && res.data.success) {
                    return ctx.reply("✅ *AKUN TRIAL BERHASIL!*\\n\\nUser: " + res.data.user + "\\n\\n<pre>" + res.data.link + "</pre>", { parse_mode: "HTML" });
                }
            } catch (err) { return ctx.reply("❌ Gagal membuat trial."); }
            return;
        }
        waitingVPN[fromId] = { proto, price, duration, payExp };
        return ctx.reply("✍️ *Silakan masukkan Username yang Anda inginkan:*", { parse_mode: "Markdown" });
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
        const fromId = ctx.from.id;
        const name = "VPN " + proto.toUpperCase() + " - " + user;
        const pType = method === "auto" ? config.paymentGateway : "manual";
        try {
            const pay = await createPayment(pType, price, config, { customerName: ctx.from.first_name, description: name });
            orders[fromId] = { type: "vpn_premium", proto, username: user, duration, name, amount: pay.amount || price, fee: pay.fee || 0, orderId: pay.orderId, paymentType: pType, chatId: ctx.chat.id, expireAt: Date.now() + payExpMin * 60 * 1000 };
            if (method === "auto") {
                const caption = "✨ *TAGIHAN PEMBAYARAN* ✨\\n\\n📦 *Produk:* " + name + "\\n💰 *Total:* *Rp" + toRupiah(pay.amount || price) + "*\\n\\n⏰ *Masa Berlaku:* " + payExpMin + " Menit\\nSistem akan mengirimkan detail akun secara otomatis setelah lunas.";
                const qrMsg = await ctx.replyWithPhoto(pay.qris, { caption, parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "❌ Batalkan Pesanan", callback_data: "cancel_order" }]] } });
                orders[fromId].qrMessageId = qrMsg.message_id;
            } else {
                await ctx.reply("🏦 *PEMBAYARAN MANUAL*\\n\\nSilakan transfer ke:\\nDANA: 083153170199\\n\\nKirim bukti transfer ke Admin @WendiVpn", { parse_mode: "Markdown", reply_markup: { inline_keyboard: [[{ text: "❌ Batalkan Pesanan", callback_data: "cancel_order" }]] } });
            }
            startCheck(fromId, ctx);
        } catch (e) { ctx.reply("❌ Gagal membuat tagihan."); }
    });
    // --- VPN INTEGRATION END ---
`;
newCode = newCode.replace('// ===== CALLBACK QUERIES =====', '// ===== CALLBACK QUERIES =====\n' + actions);

// Input Handler
const input = `
        if (waitingVPN[fromId]) {
            const data = waitingVPN[fromId];
            const user = (msg.text || "").trim();
            delete waitingVPN[fromId];
            if (!/^[a-zA-Z0-9]+$/.test(user)) return ctx.reply("❌ Username tidak valid.");
            const price = parseInt(data.price);
            const payKeyboard = [
                [{ text: "💳 Otomatis (QRIS)", callback_data: "vpn_pay_auto|" + data.proto + "|" + user + "|" + price + "|" + data.duration + "|" + data.payExp }],
                [{ text: "🏦 Manual", callback_data: "vpn_pay_manual|" + data.proto + "|" + user + "|" + price + "|" + data.duration + "|" + data.payExp }]
            ];
            return ctx.reply("🛒 *Konfirmasi Pesanan*\\n\\nProduk: *VPN " + data.proto.toUpperCase() + "*\\nUser: *" + user + "*\\nTotal: *Rp" + toRupiah(price) + "*\\n\\nSilakan pilih metode pembayaran:", { parse_mode: "Markdown", reply_markup: { inline_keyboard: payKeyboard } });
        }
`;
newCode = newCode.replace('if (!isCmd) return;', 'if (!isCmd && !waitingVPN[fromId]) return;' + input);

// Delivery
const delivery = `
            if (o.type === "vpn_premium") {
                await ctx.telegram.sendMessage(o.chatId, "⏳ *Pembayaran Diterima!*\\nSedang membuat akun Anda...", { parse_mode: "Markdown" });
                try {
                    const res = await axios.post("http://${ip}:8000/create", { user: o.username, proto: o.proto, duration: o.duration }, { headers: { "x-api-key": "${key}" }, timeout: 60000 });
                    if (res.data && res.data.success) {
                        return ctx.telegram.sendMessage(o.chatId, "✅ *PESANAN SELESAI!*\\n\\n<pre>" + res.data.link + "</pre>", { parse_mode: "HTML" });
                    }
                } catch (err) { return ctx.telegram.sendMessage(o.chatId, "❌ Gagal membuat akun."); }
            }
`;
newCode = newCode.replace('if (o.type === "panel") {', delivery + '            if (o.type === "panel") {');

fs.writeFileSync('bot.js', newCode);
console.log('Bot Rebuilt Successfully.');
EOF_NODE

pm2 restart all
rm pasang-vpn.sh 2>/dev/null
echo -e "\033[1;32m✅ SELESAI! SILAKAN CEK BOT ANDA.\033[0m"
