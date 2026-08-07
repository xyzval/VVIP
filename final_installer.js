const fs = require('fs');

const botPath = 'bot.js';
const bakPath = 'bot.js.bak';

const IP_VPN = process.env.IP_VPN || '104.207.93.176';
const API_KEY = process.env.API_KEY || 'VALL-PREMIUM-KEY-99';

let code = fs.readFileSync(bakPath, 'utf8');

// 1. Add state and axios
if (!code.includes('const waitingVPN = {};')) {
    code = code.replace('const orders = {};', 'const orders = {};\nconst waitingVPN = {};');
}

// 2. Put Button PERMANENTLY (No auto-detect for now, to ensure it shows up)
// We put it in mainKeyboard function
const simpleKeyboardFunc = `const mainKeyboard = (ctx) => {
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
};`;

code = code.replace(/const mainKeyboard = \(ctx\) => \{[\s\S]*?return \{ inline_keyboard: keyboard \};\s+\};/s, simpleKeyboardFunc);

// 3. Revert calls to non-async
code = code.replace(/reply_markup: await mainKeyboard\(ctx\)/g, 'reply_markup: mainKeyboard(ctx)');

// 4. Add the Actions (Buy, Order, Pay)
const vpnActions = `
    // --- VPN INTEGRATION START ---
    bot.action("buy_vpn", async (ctx) => {
        try { await ctx.answerCbQuery().catch(() => {}); } catch (e) {}
        ctx.reply("⏳ *Mengambil daftar produk dari server...*", { parse_mode: "Markdown" });
        try {
            const res = await axios.get("http://${IP_VPN}:8000/products", {
                headers: { "x-api-key": "${API_KEY}" }, timeout: 10000
            });
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
                const res = await axios.post("http://${IP_VPN}:8000/create", { proto, duration: "1" }, { headers: { "x-api-key": "${API_KEY}" }, timeout: 60000 });
                if (res.data && res.data.success) {
                    return ctx.reply("✅ *AKUN TRIAL BERHASIL!*\\n\\nUser: \`" + res.data.user + "\`\\n\\n<pre>" + res.data.link + "</pre>", { parse_mode: "HTML" });
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
code = code.replace('// ===== CALLBACK QUERIES =====', '// ===== CALLBACK QUERIES =====\n' + vpnActions);

// 5. Input Handler
const inputHandler = `
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
code = code.replace('if (!isCmd) return;', 'if (!isCmd && !waitingVPN[fromId]) return;' + inputHandler);

// 6. Delivery Logic
const deliveryLogic = `
            if (o.type === "vpn_premium") {
                await ctx.telegram.sendMessage(o.chatId, "⏳ *Pembayaran Diterima!*\\nSedang membuat akun Anda...", { parse_mode: "Markdown" });
                try {
                    const res = await axios.post("http://${IP_VPN}:8000/create", { user: o.username, proto: o.proto, duration: o.duration }, { headers: { "x-api-key": "VALL-PREMIUM-KEY-99" }, timeout: 60000 });
                    if (res.data && res.data.success) {
                        return ctx.telegram.sendMessage(o.chatId, "✅ *PESANAN SELESAI!*\\n\\n<pre>" + res.data.link + "</pre>", { parse_mode: "HTML" });
                    }
                } catch (err) { return ctx.telegram.sendMessage(o.chatId, "❌ Gagal membuat akun."); }
            }
`;
code = code.replace('if (o.type === "panel") {', deliveryLogic + '\n            if (o.type === "panel") {');

fs.writeFileSync(botPath, code);
console.log('Bot Rebuilt with PERMANENT VPN Button.');
