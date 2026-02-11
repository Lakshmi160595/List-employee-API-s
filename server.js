const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(bodyParser.json());
app.use(cors());

const SECRET_KEY = "mysecretkey";

// MySQL connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "register_db"
});

db.connect(err => {
  if (err) throw err;
  console.log("MySQL Connected");
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  db.query(
    "INSERT INTO users (email, password) VALUES (?, ?)",
    [email, hashedPassword],
    (err, result) => {
      if (err) return res.status(500).send(err);
      res.json({ message: "User registered successfully" });
    }
  );
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).send(err);
      if (results.length === 0)
        return res.status(401).json({ message: "User not found" });

      const user = results[0];

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch)
        return res.status(401).json({ message: "Invalid credentials" });

      const token = jwt.sign({ id: user.id }, SECRET_KEY, {
        expiresIn: "1h"
      });

      res.json({ token });
    }
  );
});

function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader)
    return res.status(403).json({ message: "Token required" });

  const token = authHeader.split(" ")[1];

  jwt.verify(token, SECRET_KEY, (err, decoded) => {
    if (err) return res.status(401).json({ message: "Invalid token" });
    req.userId = decoded.id;
    next();
  });
}

app.post("/employees", verifyToken, (req, res) => {
  const { name, designation, salary } = req.body;

  db.query(
    "INSERT INTO employees (name, designation, salary) VALUES (?, ?, ?)",
    [name, designation, salary],
    (err, result) => {
      if (err) return res.status(500).send(err);
      res.json({ message: "Employee added" });
    }
  );
});

app.get("/employees", verifyToken, (req, res) => {
  db.query("SELECT * FROM employees", (err, results) => {
    if (err) return res.status(500).send(err);
    res.json(results);
  });
});

app.put("/employees/:id", verifyToken, (req, res) => {
  const { name, designation, salary } = req.body;
  const id = req.params.id;

  db.query(
    "UPDATE employees SET name=?, designation=?, salary=? WHERE id=?",
    [name, designation, salary, id],
    (err, result) => {
      if (err) return res.status(500).send(err);
      res.json({ message: "Employee updated" });
    }
  );
});

app.delete("/employees/:id", verifyToken, (req, res) => {
  const id = req.params.id;

  db.query("DELETE FROM employees WHERE id=?", [id], (err, result) => {
    if (err) return res.status(500).send(err);
    res.json({ message: "Employee deleted" });
  });
});

app.listen(3000, () => {
  console.log("Server running on port 3000");
});

