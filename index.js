require("dotenv").config();
const mysql = require("mysql2/promise");
const express = require("express");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 3000;

// --- KONSTANTA YANG DIPERBARUI ---
const KEY_PREFIX = 'APIKEY_S3CR3T_'; // PREFIX BARU SESUAI PERMINTAAN
const JWT_SECRET = process.env.JWT_SECRET; // Dibaca dari .env (d4jlyyrh_s3cr3t_k3y!)
const EXPIRY_DAYS = 30; // Key berlaku selama 30 hari

app.use(express.json());
app.use(express.static('public'));

// ------------------------------------
// Database Connection Pool
// ------------------------------------
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD, // Menggunakan Akusukses15! dari .env
    database: process.env.DB_NAME,     // Menggunakan key_manager_db dari .env
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

// Middleware untuk verifikasi token Admin
const authenticateAdmin = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
        return res.status(401).json({ message: 'Akses Ditolak: Token tidak ditemukan' });
    }

    try {
        const verified = jwt.verify(token, JWT_SECRET);
        req.admin = verified; 
        next();
    } catch (err) {
        res.status(401).json({ message: 'Token tidak valid' });
    }
};

// ===============================================
//           ADMIN ROUTES (CRUD)
// ===============================================

// 1. Registrasi Admin Baru
app.post('/admin/register', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email dan password harus diisi.' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        
        const sql = "INSERT INTO ADMINS (EMAIL, PASSWORD) VALUES (?, ?)";
        await pool.query(sql, [email, hashedPassword]);

        res.status(201).json({ message: 'Admin berhasil didaftarkan.' });

    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Email sudah terdaftar.' });
        }
        console.error("Error registrasi admin:", error);
        res.status(500).json({ error: 'Gagal mendaftarkan admin.' });
    }
});

// 2. Login Admin & Mendapatkan Token JWT
app.post('/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const sql = "SELECT ID, PASSWORD FROM ADMINS WHERE EMAIL = ?";
        const [rows] = await pool.query(sql, [email]);
        
        if (rows.length === 0) {
            return res.status(401).json({ message: 'Kredensial tidak valid.' });
        }

        const admin = rows[0];
        const isMatch = await bcrypt.compare(password, admin.PASSWORD);

        if (!isMatch) {
            return res.status(401).json({ message: 'Kredensial tidak valid.' });
        }

        // Generate JWT Token
        const token = jwt.sign({ id: admin.ID, email: email }, JWT_SECRET, { expiresIn: '1h' });
        
        res.json({ token, message: 'Login berhasil' });

    } catch (error) {
        console.error("Error login admin:", error);
        res.status(500).json({ error: 'Gagal login' });
    }
});


// 3. Admin Melihat Semua User dan Key (Protected Route)
app.get('/admin/users', authenticateAdmin, async (req, res) => {
    try {
        const sql = `
            SELECT 
                u.ID, u.FIRST_NAME, u.LAST_NAME, u.EMAIL, 
                k.KEY_VALUE, k.START_DATE, k.OUT_OF_DATE, k.STATUS
            FROM USERS u
            JOIN API_KEYS k ON u.API_KEY_ID = k.ID
        `;
        const [rows] = await pool.query(sql);
        res.json(rows);

    } catch (error) {
        console.error("Error melihat user:", error);
        res.status(500).json({ error: 'Gagal mengambil data user' });
    }
});

// Tambahkan rute root (/) untuk memberikan pesan status server
app.get('/', (req, res) => {
    res.json({ 
        message: "API Key Manager Server Berjalan.",
        status: "OK",
        endpoints: ["/admin/register", "/user/register", "/validate-apikey"]
    });
});

// ===============================================
//           USER & API KEY ROUTES
// ===============================================

// 4. Registrasi User & Generate API Key
app.post('/user/register', async (req, res) => {
    const connection = await pool.getConnection();
    try {
        const { firstName, lastName, email } = req.body;

        if (!firstName || !lastName || !email) {
            return res.status(400).json({ error: 'Semua field (firstName, lastName, email) wajib diisi.' });
        }
        
        await connection.beginTransaction();

        // --- 1. Generate API Key & Set Expiry ---
        const randomToken = crypto.randomBytes(16).toString('hex');
        const newApiKey = KEY_PREFIX + randomToken;
        
        const startDate = new Date();
        const expiryDate = new Date();
        expiryDate.setDate(startDate.getDate() + EXPIRY_DAYS); 
        const status = 'Active'; 

        const sqlKey = "INSERT INTO API_KEYS (KEY_VALUE, START_DATE, OUT_OF_DATE, STATUS) VALUES (?, ?, ?, ?)";
        const [keyResult] = await connection.query(sqlKey, [newApiKey, startDate, expiryDate, status]);
        const apiKeyId = keyResult.insertId;

        // --- 2. Simpan User ---
        const sqlUser = "INSERT INTO USERS (FIRST_NAME, LAST_NAME, EMAIL, API_KEY_ID) VALUES (?, ?, ?, ?)";
        await connection.query(sqlUser, [firstName, lastName, email, apiKeyId]);
        
        await connection.commit();
        
        res.status(201).json({ 
            message: 'Registrasi berhasil',
            apiKey: newApiKey,
            expires: expiryDate.toISOString()
        });

    } catch (error) {
        await connection.rollback();
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Email sudah terdaftar.' });
        }
        console.error("Error registrasi user:", error);
        res.status(500).json({ error: 'Gagal mendaftarkan user dan membuat API key' });
    } finally {
        connection.release();
    }
});


// 5. Validasi API Key (Termasuk Cek Kedaluwarsa dan Status)
app.post('/validate-apikey', async (req, res) => {
    try {
        const { apiKeyToValidate } = req.body;

        if (!apiKeyToValidate) {
            return res.status(400).json({ error: 'API key dibutuhkan' });
        }

        // Ambil status dan tanggal kedaluwarsa dari DB
        const sql = "SELECT OUT_OF_DATE, STATUS FROM API_KEYS WHERE KEY_VALUE = ?";
        const [rows] = await pool.query(sql, [apiKeyToValidate]);

        if (rows.length === 0) {
            return res.status(401).json({ valid: false, message: 'API Key Tidak Ditemukan' });
        }

        const keyRecord = rows[0];
        const expiryDate = new Date(keyRecord.OUT_OF_DATE);
        const now = new Date();

        // 1. Cek Status Aktif/Revoked
        if (keyRecord.STATUS !== 'Active') {
             return res.status(403).json({ 
                valid: false, 
                message: `API Key ${keyRecord.STATUS.toLowerCase()}. Akses ditolak.`,
                status: keyRecord.STATUS
            });
        }

        // 2. Cek Kedaluwarsa
        if (now > expiryDate) {
            // Opsional: Update status di DB menjadi Expired (bisa dilakukan di sini)
            return res.status(403).json({ 
                valid: false, 
                message: 'API Key Kedaluwarsa',
                expires: keyRecord.OUT_OF_DATE 
            });
        }
        
        res.json({ 
            valid: true, 
            message: 'API Key Valid dan Aktif',
            expires: keyRecord.OUT_OF_DATE 
        });

    } catch (error) {
        console.error("Error saat validasi key:", error);
        res.status(500).json({ error: 'Gagal memvalidasi key di database' });
    }
});


// ===============================================
//           SERVER START
// ===============================================
app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
    console.log(`Terhubung ke database MySQL '${process.env.DB_NAME}'`);
});