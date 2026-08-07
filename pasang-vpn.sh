#!/bin/bash
# ==========================================
# VPN BRIDGE INSTALLER FOR TELEBOT (FIXED V3)
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

# 3. Backup bot.js
cp bot.js bot.js.bak
echo -e "\033[1;32m✅ Backup bot.js.bak berhasil dibuat.\033[0m"

# 4. Install Library
echo "⏳ Memasang library axios..."
npm install axios --save >/dev/null 2>&1

# 5. Gunakan Python untuk menulis inject_vpn.js agar AMAN dari eror karakter
python3 - <<PYEOF
import os

ip_vpn = "$IP_VPN"
api_key = "$API_KEY"

# We avoid using backticks inside the injected code strings to prevent closure issues
js_code = r"""
const fs = require('fs');
const botPath = 'bot.js';
let code = fs.readFileSync(botPath, 'utf8');

const IP_VPN = \"""" + ip_vpn + r"""\";
const API_KEY = \"""" + api_key + r"""\";

if (!code.includes('const waitingVPN = {};')) {
    code = code.replace('const orders = {};', 'const orders = {};\\nconst waitingVPN = {};');
}

code = code.replace('const mainKeyboard = (ctx) => {', 'const mainKeyboard = async (ctx) => {');

const vpnLogic = '\\n' +
'    try {\\n' +
'        const res = await axios.get(\"http://' + IP_VPN + ':8000/products\", {\\n' +
'            headers: { \"x-api-key\": \"' + API_KEY + '\" },\\n' +
'            timeout: 2500\\n' +
'        });\\n' +
'        if (res.data && res.data.success) {\\n' +
'            keyboard.push([{ text: \"🛡️ Beli Akun VPN\", callback_data: \"buy_vpn\" }]);\\n' +
'        }\\n' +
'    } catch (e) {}\\n';

if (!code.includes('buy_vpn')) {
    code = code.replace('return { inline_keyboard: keyboard };', vpnLogic + '    return { inline_keyboard: keyboard };');
}

code = code.replace(/reply_markup: mainKeyboard\\(ctx\\)/g, 'reply_markup: await mainKeyboard(ctx)');

const vpnActions = '\\n' +
'    // --- VPN INTEGRATION START ---\\n' +
'    bot.action(\"buy_vpn\", async (ctx) => {\\n' +
'        try { await ctx.answerCbQuery().catch(() => {}); } catch (e) {}\\n' +
'        ctx.reply(\"⏳ *Mengambil daftar produk dari server...*\", { parse_mode: \"Markdown\" });\\n' +
'        try {\\n' +
'            const res = await axios.get(\"http://' + IP_VPN + ':8000/products\", {\\n' +
'                headers: { \"x-api-key\": \"' + API_KEY + '\" }, timeout: 10000\\n' +
'            });\\n' +
'            if (res.data && res.data.success) {\\n' +
'                const products = res.data.data;\\n' +
'                const globalExp = res.data.payment_expiry || 15;\\n' +
'                const keyboard = [];\\n' +
'                keyboard.push([{ text: \"💎 --- PAKET PREMIUM (30 HARI) --- 💎\", callback_data: \"none\" }]);\\n' +
'                products.filter(p => p.type === \"premium\").forEach(p => {\\n' +
'                    keyboard.push([{ text: p.name + \" - Rp\" + toRupiah(p.price), callback_data: \"vpn_order|\" + p.id + \"|\" + p.price + \"|\" + p.duration + \"|\" + globalExp }]);\\n' +
'                });\\n' +
'                keyboard.push([{ text: \"🎁 --- PAKET TRIAL (15 MENIT) --- 🎁\", callback_data: \"none\" }]);\\n' +
'                const trialRow = [];\\n' +
'                products.filter(p => p.type === \"trial\").forEach((p) => {\\n' +
'                    trialRow.push({ text: p.name.replace(\"🎁 TRIAL \", \"\"), callback_data: \"vpn_order|\" + p.id + \"|\" + p.price + \"|\" + p.duration + \"|\" + globalExp });\\n' +
'                    if (trialRow.length === 2) { keyboard.push([...trialRow]); trialRow.length = 0; }\\n' +
'                });\\n' +
'                if (trialRow.length > 0) keyboard.push([...trialRow]);\\n' +
'                keyboard.push([{ text: \"🔄 Back To Menu\", callback_data: \"back_menu\" }]);\\n' +
'                return ctx.reply(\"🛡️ *SERVER: \" + res.data.server_name + \"*\\\\nSilakan pilih paket VPN Anda:\", { parse_mode: \"Markdown\", reply_markup: { inline_keyboard: keyboard } });\\n' +
'            }\\n' +
'        } catch (err) { return ctx.reply(\"❌ Server VPN OFFLINE.\"); }\\n' +
'    });\\n' +
'\\n' +
'    bot.action(/vpn_order\\\\|(.+)/, async (ctx) => {\\n' +
'        try { await ctx.answerCbQuery().catch(() => {}); } catch (e) {}\\n' +
'        const parts = ctx.match[1].split(\"|\");\\n' +
'        const proto = parts[0];\\n' +
'        const price = parseInt(parts[1]);\\n' +
'        const duration = parts[2];\\n' +
'        const payExp = parts[3];\\n' +
'        const fromId = ctx.from.id;\\n' +
'        if (proto === \"none\") return;\\n' +
'        if (price === 0) {\\n' +
'            ctx.reply(\"⏳ *Sedang menyiapkan akun TRIAL 15 Menit...*\", { parse_mode: \"Markdown\" });\\n' +
'            try {\\n' +
'                const res = await axios.post(\"http://' + IP_VPN + ':8000/create\", { proto, duration: \"1\" }, { headers: { \"x-api-key\": \"' + API_KEY + '\" }, timeout: 60000 });\\n' +
'                if (res.data && res.data.success) {\\n' +
'                    return ctx.reply(\"✅ *AKUN TRIAL BERHASIL!*\\\\n\\\\nUser: `\" + res.data.user + \"`\\\\n\\\\n<pre>\" + res.data.link + \"</pre>\", { parse_mode: \"HTML\" });\\n' +
'                }\\n' +
'            } catch (err) { return ctx.reply(\"❌ Gagal membuat trial.\"); }\\n' +
'            return;\\n' +
'        }\\n' +
'        waitingVPN[fromId] = { proto, price, duration, payExp };\\n' +
'        return ctx.reply(\"✍️ *Silakan masukkan Username yang Anda inginkan:*\", { parse_mode: \"Markdown\" });\\n' +
'    });\\n' +
'\\n' +
'    bot.action(/vpn_pay_(auto|manual)\\\\|(.+)/, async (ctx) => {\\n' +
'        try { await ctx.answerCbQuery().catch(() => {}); } catch (e) {}\\n' +
'        const method = ctx.match[1];\\n' +
'        const parts = ctx.match[2].split(\"|\");\\n' +
'        const proto = parts[0];\\n' +
'        const user = parts[1];\\n' +
'        const price = parseInt(parts[2]);\\n' +
'        const duration = parts[3];\\n' +
'        const payExpMin = parseInt(parts[4]) || 15;\\n' +
'        const fromId = ctx.from.id;\\n' +
'        const name = \"VPN \" + proto.toUpperCase() + \" - \" + user;\\n' +
'        const pType = method === \"auto\" ? config.paymentGateway : \"manual\";\\n' +
'        try {\\n' +
'            const pay = await createPayment(pType, price, config, { customerName: ctx.from.first_name, description: name });\\n' +
'            orders[fromId] = { type: \"vpn_premium\", proto, username: user, duration, name, amount: pay.amount || price, fee: pay.fee || 0, orderId: pay.orderId, paymentType: pType, chatId: ctx.chat.id, expireAt: Date.now() + payExpMin * 60 * 1000 };\\n' +
'            if (method === \"auto\") {\\n' +
'                const caption = \"✨ *TAGIHAN PEMBAYARAN* ✨\\\\n\\\\n📦 *Produk:* \" + name + \"\\\\n💰 *Total:* *Rp\" + toRupiah(pay.amount || price) + \"*\\\\n\\\\n⏰ *Masa Berlaku:* \" + payExpMin + \" Menit\\\\nSistem akan mengirimkan detail akun secara otomatis setelah lunas.\";\\n' +
'                const qrMsg = await ctx.replyWithPhoto(pay.qris, { caption, parse_mode: \"Markdown\", reply_markup: { inline_keyboard: [[{ text: \"❌ Batalkan Pesanan\", callback_data: \"cancel_order\" }]] } });\\n' +
'                orders[fromId].qrMessageId = qrMsg.message_id;\\n' +
'            } else {\\n' +
'                await ctx.reply(\"🏦 *PEMBAYARAN MANUAL*\\\\n\\\\nSilakan transfer ke:\\\\nDANA: 083153170199\\\\n\\\\nKirim bukti transfer ke Admin @WendiVpn\", { parse_mode: \"Markdown\", reply_markup: { inline_keyboard: [[{ text: \"❌ Batalkan Pesanan\", callback_data: \"cancel_order\" }]] } });\\n' +
'            }\\n' +
'            startCheck(fromId, ctx);\\n' +
'        } catch (e) { ctx.reply(\"❌ Gagal membuat tagihan.\"); }\\n' +
'    });\\n' +
'    // --- VPN INTEGRATION END ---\\n';

if (!code.includes('bot.action(\"buy_vpn\"')) {
    code = code.replace('// ===== CALLBACK QUERIES =====', '// ===== CALLBACK QUERIES =====\\n' + vpnActions);
}

const inputHandler = '\\n' +
'        if (waitingVPN[fromId]) {\\n' +
'            const data = waitingVPN[fromId];\\n' +
'            const user = (msg.text || \"\").trim();\\n' +
'            delete waitingVPN[fromId];\\n' +
'            if (!/^[a-zA-Z0-9]+$/.test(user)) return ctx.reply(\"❌ Username tidak valid. Silakan ulangi dari menu.\");\\n' +
'            const price = parseInt(data.price);\\n' +
'            const payKeyboard = [\\n' +
'                [{ text: \"💳 Otomatis (QRIS)\", callback_data: \"vpn_pay_auto|\" + data.proto + \"|\" + user + \"|\" + price + \"|\" + data.duration + \"|\" + data.payExp }],\\n' +
'                [{ text: \"🏦 Manual\", callback_data: \"vpn_pay_manual|\" + data.proto + \"|\" + user + \"|\" + price + \"|\" + data.duration + \"|\" + data.payExp }]\\n' +
'            ];\\n' +
'            return ctx.reply(\"🛒 *Konfirmasi Pesanan*\\\\n\\\\nProduk: *VPN \" + data.proto.toUpperCase() + \"*\\\\nUser: *\" + user + \"*\\\\nTotal: *Rp\" + toRupiah(price) + \"*\\\\n\\\\nSilakan pilih metode pembayaran:\", { parse_mode: \"Markdown\", reply_markup: { inline_keyboard: payKeyboard } });\\n' +
'        }\\n';

if (!code.includes('waitingVPN[fromId]')) {
    code = code.replace('if (!isCmd) return;', 'if (!isCmd && !waitingVPN[fromId]) return;' + inputHandler);
}

const deliveryLogic = '\\n' +
'            if (o.type === \"vpn_premium\") {\\n' +
'                await ctx.telegram.sendMessage(o.chatId, \"⏳ *Pembayaran Diterima!*\\\\nSedang membuat akun Anda...\", { parse_mode: \"Markdown\" });\\n' +
'                try {\\n' +
'                    const res = await axios.post(\"http://' + IP_VPN + ':8000/create\", { user: o.username, proto: o.proto, duration: o.duration }, { headers: { \"x-api-key\": \"VALL-PREMIUM-KEY-99\" }, timeout: 60000 });\\n' +
'                    if (res.data && res.data.success) {\\n' +
'                        return ctx.telegram.sendMessage(o.chatId, \"✅ *PESANAN SELESAI!*\\\\n\\\\n<pre>\" + res.data.link + \"</pre>\", { parse_mode: \"HTML\" });\\n' +
'                    }\\n' +
'                } catch (err) { return ctx.telegram.sendMessage(o.chatId, \"❌ Gagal membuat akun. Silakan hubungi admin.\"); }\\n' +
'            }\\n';

if (!code.includes('type === \"vpn_premium\"')) {
    code = code.replace('if (o.type === \"panel\") {', deliveryLogic + '            if (o.type === \"panel\") {');
}

fs.writeFileSync(botPath, code);
"""
with open('inject_vpn.js', 'w') as f:
    f.write(js_code)
PYEOF

node inject_vpn.js
rm inject_vpn.js

echo -e "\033[1;32m✅ INTEGRASI BERHASIL! Menghidupkan ulang bot...\033[0m"
pm2 restart all
rm pasang-vpn.sh 2>/dev/null
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "         PROSES SELESAI, CEK BOT ANDA!       "
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
