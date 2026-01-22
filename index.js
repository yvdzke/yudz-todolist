require("dotenv").config();
const express = require("express");
const cors = require("cors");
const pool = require("./db");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const authorization = require("./middleware/authorization");

const app = express();
const PORT = process.env.PORT || 5000;

// ================================ Middleware Global
app.use(cors());
app.use(express.json());

// =================== Router
const router = express.Router();
app.use("/api", router);

// ============================================ Auth Start
// Route Register
router.post("/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    // 1. User Check
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

    // 3. Masukkan ke Database
    const newUser = await pool.query(
      "INSERT INTO users (user_name, user_password) VALUES ($1, $2) RETURNING *",
      [username, bcryptPassword],
    );

    // 4. Generate Token
    const token = jwt.sign(
      { user_id: newUser.rows[0].user_id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );

    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// Route Login
router.post("/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    // 1. Cek user
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
    const token = jwt.sign(
      { user_id: user.rows[0].user_id },
      process.env.JWT_SECRET,
      { expiresIn: "1h" },
    );

    res.json({ token });
  } catch (err) {
    console.error(err.message);
    res.status(500).send("Server Error");
  }
});

// =========================================== Task Start
// Get Task
router.get("/tasks", authorization, async (req, res) => {
  try {
    const allTasks = await pool.query(
      "SELECT * FROM tasks WHERE user_id = $1 ORDER BY task_id ASC",
      [req.user.user_id],
    );
    res.json(allTasks.rows);
  } catch (err) {
    console.error(err.message);
    res.status(500).json("Server Error");
  }
});

// Post Task
router.post("/tasks", authorization, async (req, res) => {
  try {
    const { task_name, category, task_date } = req.body;
    const newTask = await pool.query(
      "INSERT INTO tasks (user_id, task_name, category, task_date) VALUES ($1, $2, $3, $4) RETURNING *",
      [req.user.user_id, task_name, category, task_date || null],
    );
    res.json(newTask.rows[0]);
  } catch (err) {
    console.error(err.message);
    res.status(500).json("Server Error");
  }
});

// Edit Task
router.put("/tasks/:id", authorization, async (req, res) => {
  try {
    const { id } = req.params;
    const { task_name, category, task_date, is_completed } = req.body;
    const updateTask = await pool.query(
      "UPDATE tasks SET task_name = $1, category = $2, task_date = $3, is_completed = $4 WHERE task_id = $5 AND user_id = $6 RETURNING *",
      [
        task_name,
        category,
        task_date || null,
        is_completed,
        id,
        req.user.user_id,
      ],
    );

    if (updateTask.rows.length === 0) {
      return res.json("Task tidak ditemukan atau bukan milikmu!");
    }
    res.json("Task updated!");
  } catch (err) {
    console.error(err.message);
    res.status(500).json("Server Error");
  }
});

// Detele Task
router.delete("/tasks/:id", authorization, async (req, res) => {
  try {
    const { id } = req.params;
    const deleteTask = await pool.query(
      "DELETE FROM tasks WHERE task_id = $1 AND user_id = $2 RETURNING *",
      [id, req.user.user_id],
    );

    if (deleteTask.rows.length === 0) {
      return res.json("Task tidak ditemukan atau bukan milikmu!");
    }
    res.json("Task deleted!");
  } catch (err) {
    console.error(err.message);
    res.status(500).json("Server Error");
  }
});

// Categories
router.put("/categories", authorization, async (req, res) => {
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

app.get("/api/auth/register", (req, res) => {
  res.send("Register Server");
});

app.get("/", (req, res) => {
  res.send("Server Running!");
});

// ================================== Running Server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
