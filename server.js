import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import pg from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
const { Pool } = pg;

app.use(cors());
app.use(express.json());

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
});

// Middleware для проверки токена
function auth(req, res, next) {
    const header = req.headers.authorization;

    if (!header) {
        return res.status(401).json({ error: "Нет токена" });
    }

    const token = header.split(" ")[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch {
        return res.status(401).json({ error: "Неверный токен" });
    }
}

// ========== ТЕСТОВЫЕ МАРШРУТЫ ==========

app.get("/", (req, res) => {
    res.json({ message: "Backend работает" });
});

app.get("/test-db", async (req, res) => {
    try {
        const result = await pool.query("SELECT NOW()");
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// ========== АВТОРИЗАЦИЯ ==========

app.post("/register", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: "Введите логин и пароль" });
        }

        const existingUser = await pool.query(
            "SELECT * FROM users WHERE username = $1",
            [username]
        );

        if (existingUser.rows.length > 0) {
            return res.status(400).json({ error: "Пользователь уже существует" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = await pool.query(
            `INSERT INTO users (username, password_hash)
             VALUES ($1, $2)
             RETURNING id, username`,
            [username, hashedPassword]
        );

        const token = jwt.sign(
            { id: result.rows[0].id, username: result.rows[0].username },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            token,
            user: result.rows[0]
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        const result = await pool.query(
            "SELECT * FROM users WHERE username = $1",
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(400).json({ error: "Пользователь не найден" });
        }

        const user = result.rows[0];

        const validPassword = await bcrypt.compare(password, user.password_hash);

        if (!validPassword) {
            return res.status(400).json({ error: "Неверный пароль" });
        }

        const token = jwt.sign(
            { id: user.id, username: user.username },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            token,
            user: { id: user.id, username: user.username }
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// ========== ПРОЕКТЫ ==========

// Получить все проекты
app.get('/projects', auth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM projects WHERE user_id = $1 ORDER BY id DESC`,
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Создать проект
app.post('/projects', auth, async (req, res) => {
    try {
        const { name, contractAmount, advancePercent, paymentDelay } = req.body;

        const result = await pool.query(
            `INSERT INTO projects (user_id, name, contract_amount, advance_percent, payment_delay)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING *`,
            [req.user.id, name, contractAmount, advancePercent, paymentDelay]
        );

        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Обновить проект
app.put('/projects/:id', auth, async (req, res) => {
    const { id } = req.params;
    const { name, contractAmount, advancePercent, paymentDelay } = req.body;
    
    try {
        const result = await pool.query(
            `UPDATE projects 
             SET name = $1, contract_amount = $2, advance_percent = $3, payment_delay = $4 
             WHERE id = $5 AND user_id = $6
             RETURNING *`,
            [name, contractAmount, advancePercent, paymentDelay, id, req.user.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Проект не найден" });
        }
        
        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Удалить проект
app.delete('/projects/:id', auth, async (req, res) => {
    const { id } = req.params;
    
    try {
        // Сначала удаляем связанные транзакции
        await pool.query('DELETE FROM transactions WHERE project_id = $1', [id]);
        
        // Затем удаляем проект
        const result = await pool.query(
            'DELETE FROM projects WHERE id = $1 AND user_id = $2 RETURNING id',
            [id, req.user.id]
        );
        
        if (result.rows.length === 0) {
            return res.status(404).json({ error: "Проект не найден" });
        }
        
        res.json({ success: true });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// ========== ТРАНЗАКЦИИ ==========

// Получить транзакции для конкретного проекта
app.get("/transactions/:projectId", auth, async (req, res) => {
    try {
        const { projectId } = req.params;

        const result = await pool.query(
            `SELECT t.*
             FROM transactions t
             JOIN projects p ON p.id = t.project_id
             WHERE t.project_id = $1 AND p.user_id = $2
             ORDER BY t.month`,
            [projectId, req.user.id]
        );

        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Получить ВСЕ транзакции пользователя (для сводки)
app.get("/transactions", auth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT t.*
             FROM transactions t
             JOIN projects p ON p.id = t.project_id
             WHERE p.user_id = $1
             ORDER BY t.project_id, t.month`,
            [req.user.id]
        );
        res.json(result.rows);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// Создать или обновить транзакцию
app.post("/transactions", auth, async (req, res) => {
    try {
        const { projectId, month, incomeAccrued, expense, cashIncoming, cashOutgoing } = req.body;

        // Проверяем, есть ли уже такая транзакция
        const existing = await pool.query(
            `SELECT * FROM transactions WHERE project_id = $1 AND month = $2`,
            [projectId, month]
        );

        let result;

        if (existing.rows.length > 0) {
            // Обновляем существующую
            result = await pool.query(
                `UPDATE transactions
                 SET income_accrued = $1, expense = $2, cash_incoming = $3, cash_outgoing = $4
                 WHERE project_id = $5 AND month = $6
                 RETURNING *`,
                [incomeAccrued, expense, cashIncoming, cashOutgoing, projectId, month]
            );
        } else {
            // Создаём новую
            result = await pool.query(
                `INSERT INTO transactions (project_id, month, income_accrued, expense, cash_incoming, cash_outgoing)
                 VALUES ($1, $2, $3, $4, $5, $6)
                 RETURNING *`,
                [projectId, month, incomeAccrued, expense, cashIncoming, cashOutgoing]
            );
        }

        res.json(result.rows[0]);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: err.message });
    }
});

// ========== ЗАПУСК ==========

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`🚀 Сервер запущен на порту ${PORT}`);
});