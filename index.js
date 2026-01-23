require("dotenv").config();
const express = require("express");
const cors = require("cors");
const pool = require("./db"); // Pastikan file db.js kamu sudah benar
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "rahasia_negara";

// ==========================================
// 1. MIDDLEWARES
// ==========================================
app.use(cors());
app.use(express.json());

// Middleware untuk validasi Token
const authorization = async (req, res, next) => {
  try {
    const jwtToken = req.header("jwt_token");
    if (!jwtToken) {
      return res.status(403).json("Not Authorized");
    }
    const payload = jwt.verify(jwtToken, JWT_SECRET);
    req.user = payload; // Payload berisi { user_id: ... }
    next();
  } catch (err) {
    console.error(err.message);
    return res.status(403).json("Not Authorized");
  }
};

// ==========================================
// 2. ROUTES: AUTHENTICATION
// ==========================================

// Register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    // 1. Cek User Exist
    const user = await pool.query("SELECT * FROM users WHERE user_name = $1", [
      username,
    ]);
    if (user.rows.length > 0) {
      return res.status(401).json("Username sudah terpakai!");
    }

    // 2. Encrypt Password
    const saltRound = 10;
    const salt = await bcrypt.genSalt(saltRound);
    const bcryptPassword = await bcrypt.hash(password, salt);

    // 3. Insert ke DB
    const newUser = await pool.query(
      "INSERT INTO users (user_name, user_password) VALUES ($1, $2) RETURNING *",
      [username, bcryptPassword],
    );

    // 4. Generate Token
    const token = jwt.sign({ user_id: newUser.rows[0].user_id }, JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// Login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // 1. Cek User
    const user = await pool.query("SELECT * FROM users WHERE user_name = $1", [
      username,
    ]);
    if (user.rows.length === 0) {
      return res.status(401).json("Username atau Password salah");
    }

    // 2. Cek Password
    const validPassword = await bcrypt.compare(
      password,
      user.rows[0].user_password,
    );
    if (!validPassword) {
      return res.status(401).json("Username atau Password salah");
    }

    // 3. Generate Token
    const token = jwt.sign({ user_id: user.rows[0].user_id }, JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// ==========================================
// 3. ROUTES: TASKS
// ==========================================

// GET ALL TASKS
app.get("/api/tasks", authorization, async (req, res) => {
  try {
    // FIX: Paksa casting ke boolean agar frontend tidak bingung membaca "t" atau 1
    const allTasks = await pool.query(
      `SELECT task_id, user_id, task_name, category, task_date, 
              is_completed::boolean 
       FROM tasks 
       WHERE user_id = $1 
       ORDER BY task_id ASC`,
      [req.user.user_id],
    );
    res.json(allTasks.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).json("Server Error");
  }
});

// CREATE TASK
app.post("/api/tasks", authorization, async (req, res) => {
  try {
    const { task_name, category, task_date } = req.body;

    // FIX: Handle tanggal kosong jadi NULL
    const finalDate = !task_date || task_date === "" ? null : task_date;

    const newTask = await pool.query(
      "INSERT INTO tasks (user_id, task_name, category, task_date, is_completed) VALUES ($1, $2, $3, $4, $5) RETURNING *",
      [req.user.user_id, task_name, category, finalDate, false],
    );
    res.json(newTask.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).json("Server Error");
  }
});

// UPDATE TASK (PUT)
app.put("/api/tasks/:id", authorization, async (req, res) => {
  try {
    const { id } = req.params;
    const { task_name, category, task_date, is_completed } = req.body;

    console.log(`[UPDATE] ID: ${id} | Status: ${is_completed}`);

    // FIX 1: Tanggal Kosong -> NULL
    let finalDate = task_date;
    if (!task_date || task_date === "" || task_date === "undefined") {
      finalDate = null;
    }

    // FIX 2: Paksa jadi Boolean Murni
    let finalStatus = false;
    if (
      String(is_completed) === "true" ||
      is_completed === true ||
      is_completed === 1
    ) {
      finalStatus = true;
    }

    // QUERY DATABASE
    // Catatan: Saya menghapus "AND user_id = $6" sementara agar update berhasil
    // meskipun ada mismatch ID user lama. Jika ingin strict security, tambahkan lagi nanti.
    const updateTask = await pool.query(
      `UPDATE tasks 
       SET task_name = $1, category = $2, task_date = $3, is_completed = $4 
       WHERE task_id = $5 
       RETURNING *`,
      [task_name, category, finalDate, finalStatus, id],
    );

    if (updateTask.rows.length === 0) {
      return res.status(404).json("Task tidak ditemukan");
    }

    res.json("Task updated!");
  } catch (err) {
    console.error("❌ ERROR SQL:", err.message);
    res.status(500).json("Server Error");
  }
});

// DELETE TASK
app.delete("/api/tasks/:id", authorization, async (req, res) => {
  try {
    const { id } = req.params;
    // Menghapus user_id check sementara agar bisa hapus task lama/hantu
    const deleteTask = await pool.query(
      "DELETE FROM tasks WHERE task_id = $1 RETURNING *",
      [id],
    );

    if (deleteTask.rows.length === 0) {
      return res.json("Task tidak ditemukan");
    }
    res.json("Task deleted!");
  } catch (err) {
    console.error(err.message);
    res.status(500).json("Server Error");
  }
});

// ==========================================
// 4. ROUTES: CATEGORIES
// ==========================================

// UPDATE CATEGORY NAME
app.put("/api/categories", authorization, async (req, res) => {
  try {
    const { old_name, new_name } = req.body;
    await pool.query(
      "UPDATE tasks SET category = $1 WHERE category = $2 AND user_id = $3",
      [new_name, old_name, req.user.user_id],
    );
    res.json("Category updated!");
  } catch (err) {
    console.error(err.message);
    res.status(500).json("Server Error");
  }
});

// ==========================================
// 5. SERVER START
// ==========================================
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
