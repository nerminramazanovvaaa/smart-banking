require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const app = express();

app.use(express.json());
app.use(express.static('.'));

// AWS RDS PostgreSQL bağlantısı
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: Number(process.env.DB_PORT),
    ssl: { rejectUnauthorized: false }
});

// Cədvəlləri avtomatik yoxlayaq və ya yaradaq
async function initDB() {
    try {
        // 1. İstifadəçilər cədvəli
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                email VARCHAR(150) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                card_number VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        console.log("[DB] 'users' cədvəli uğurla yoxlanıldı / yaradıldı.");

        // 2. Tranzaksiyalar cədvəli (AWS buludunda saxlanacaq)
        await pool.query(`
            CREATE TABLE IF NOT EXISTS transactions (
                id SERIAL PRIMARY KEY,
                user_email VARCHAR(150) NOT NULL,
                card_name VARCHAR(100) NOT NULL,
                type VARCHAR(20) NOT NULL,
                description TEXT NOT NULL,
                amount NUMERIC(10, 2) NOT NULL,
                date VARCHAR(50) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
        await pool.query(`
    CREATE TABLE IF NOT EXISTS cards (
        id SERIAL PRIMARY KEY,
        user_email VARCHAR(150) NOT NULL,
        name VARCHAR(100) NOT NULL,
        last4 VARCHAR(4) NOT NULL,
        exp VARCHAR(5) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
`);
await pool.query(`ALTER TABLE transactions ADD COLUMN IF NOT EXISTS card_id INTEGER;`);
console.log("[DB] 'cards' cədvəli hazırdır.");
        console.log("[DB] 'transactions' cədvəli uğurla yoxlanıldı / yaradıldı.");

    } catch (err) {
        console.error("[DB XƏTASI] Cədvəllər yaradılarkən xəta baş verdi:", err);
    }
}
initDB();

const SECRET_KEY = crypto.scryptSync(process.env.SECRET_KEY, 'smart-banking-salt', 32);

function encryptData(text) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', SECRET_KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

// Qeydiyyat API marşrutu (AWS RDS-ə yazır)
app.post('/api/register', async (req, res) => {
    try {
        const { name, email, password, cardNumber, cardName, cardExp } = req.body;

        const hashedPassword = await bcrypt.hash(password, 10);
        const encryptedCard = encryptData(cardNumber);

        const result = await pool.query(
            `INSERT INTO users (name, email, password, card_number)
             VALUES ($1, $2, $3, $4) RETURNING id;`,
            [name, email, hashedPassword, encryptedCard]
        );

        // İlk kartı da cards cədvəlinə yaz (yalnız son 4 rəqəm)
        await pool.query(
            `INSERT INTO cards (user_email, name, last4, exp) VALUES ($1, $2, $3, $4)`,
            [email, cardName, cardNumber.slice(-4), cardExp]
        );

        console.log(`[QEYDİYYAT] ID: ${result.rows[0].id}`);
        res.json({ success: true });
    } catch (err) {
        console.error("[XƏTA]", err);
        if (err.code === '23505') {
            return res.status(400).json({ success: false, message: "Bu e-poçt ilə artıq qeydiyyatdan keçilib!" });
        }
        res.status(500).json({ success: false, message: "Bazaya yazılarkən xəta baş verdi!" });
    }
});

// Giriş API marşrutu (AWS RDS-dən yoxlayır)
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const query = 'SELECT * FROM users WHERE email = $1';
        const result = await pool.query(query, [email]);

        if (result.rows.length === 0) {
            return res.status(400).json({ success: false, message: "E-mail və ya şifrə yanlışdır!" });
        }

        const user = result.rows[0];

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ success: false, message: "E-mail və ya şifrə yanlışdır!" });
        }

        console.log(`[GİRİŞ] İstifadəçi uğurla daxil oldu: ${user.email}`);
        res.json({ 
            success: true, 
            message: "Uğurla daxil oldunuz!",
            user: { name: user.name, email: user.email }
        });
    } catch (err) {
        console.error("[GİRİŞ XƏTASI]", err);
        res.status(500).json({ success: false, message: "Server xətası baş verdi!" });
    }
});

// Tranzaksiya əlavə etmək üçün API (AWS RDS-ə yazır)
app.post('/api/transaction', async (req, res) => {
    try {
        const { email, cardId, cardName, type, description, amount } = req.body;

        if (!['income', 'expense'].includes(type) || !(Number(amount) > 0)) {
            return res.status(400).json({ success: false, message: "Yanlış məlumat!" });
        }

        const result = await pool.query(
            `INSERT INTO transactions (user_email, card_id, card_name, type, description, amount, date)
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id;`,
            [email, cardId, cardName, type, description, amount, new Date().toISOString()]
        );

        console.log(`[TRANZAKSİYA] Bazaya yazıldı ID: ${result.rows[0].id}`);
        res.json({ success: true });
    } catch (err) {
        console.error("[TRANZAKSİYA XƏTASI]", err);
        res.status(500).json({ success: false, message: "Tranzaksiya yadda saxlanılmadı!" });
    }
});

// İstifadəçinin tranzaksiyalarını AWS-dən gətirmək üçün API
app.get('/api/transactions/:email', async (req, res) => {
    try {
        const { email } = req.params;
        const query = 'SELECT * FROM transactions WHERE user_email = $1 ORDER BY id DESC';
        const result = await pool.query(query, [email]);
        res.json({ success: true, transactions: result.rows });
    } catch (err) {
        console.error("[TRANZAKSİYA OXUMA XƏTASI]", err);
        res.status(500).json({ success: false, message: "Məlumatlar oxunmadı!" });
    }
});

app.get('/api/cards/:email', async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, last4, exp FROM cards WHERE user_email = $1 ORDER BY id',
            [req.params.email]
        );
        res.json({ success: true, cards: result.rows });
    } catch (err) {
        console.error("[KART OXUMA XƏTASI]", err);
        res.status(500).json({ success: false });
    }
});

app.post('/api/cards', async (req, res) => {
    try {
        const { email, name, last4, exp } = req.body;
        const result = await pool.query(
            `INSERT INTO cards (user_email, name, last4, exp) VALUES ($1, $2, $3, $4) RETURNING id`,
            [email, name, last4, exp]
        );
        res.json({ success: true, id: result.rows[0].id });
    } catch (err) {
        console.error("[KART YAZMA XƏTASI]", err);
        res.status(500).json({ success: false });
    }
});

app.delete('/api/cards/:id', async (req, res) => {
    try {
        await pool.query('DELETE FROM transactions WHERE card_id = $1', [req.params.id]);
        await pool.query('DELETE FROM cards WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        console.error("[KART SİLMƏ XƏTASI]", err);
        res.status(500).json({ success: false });
    }
});

app.listen(3000, () => {
    console.log("Server işləyir: http://localhost:3000");
});