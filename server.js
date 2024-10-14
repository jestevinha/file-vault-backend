const express = require("express");
const multer = require("multer");
const bcrypt = require("bcrypt");
const path = require("path");
const fs = require("fs");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const server = express();

const SECRET_KEY = "DSwissChallenge"; // Replace with your secret key
const port = 3000;

server.use(express.json());
server.use(express.urlencoded({ extended: true }));

// SQLite database setup
const db = new sqlite3.Database("./database.sqlite");

db.serialize(() => {
  db.run(
    "CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)"
  );
  db.run(
    "CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY, userId INTEGER, filename TEXT, filepath TEXT, size INTEGER, FOREIGN KEY(userId) REFERENCES users(id))"
  );
});

// Middleware to authenticate token (JWT)
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Extract token from "Bearer <token>"

  if (!token) return res.sendStatus(401); // No token provided

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403); // Invalid token

    req.user = user; // Attach the user from the token to the request object
    next();
  });
}

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    // Convert filename to UTF-8 encoding
    cb(null, Buffer.from(file.originalname, "latin1").toString("utf8"));
  },
});
const upload = multer({ storage });

// User login endpoint (generates JWT)
server.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) {
      return res.status(500).send("Error accessing database.");
    }

    if (!user) {
      return res.status(400).send("Invalid username or password.");
    }

    // Compare passwords
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) return res.status(500).send("Error comparing passwords.");

      if (result) {
        // Password matches - generate and return JWT
        const token = jwt.sign(
          { id: user.id, username: user.username },
          SECRET_KEY,
          {
            expiresIn: "1h", // Token expiration time
          }
        );
        res.send({ message: "Login successful!", token });
      } else {
        return res.status(400).send("Invalid username or password.");
      }
    });
  });
});

// User registration endpoint (hash password and store in DB)
server.post("/api/register", (req, res) => {
  const { username, password } = req.body;

  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).send("Error hashing password");

    db.run(
      `INSERT INTO users (username, password) VALUES (?, ?)`,
      [username, hash],
      (err) => {
        if (err) return res.status(500).send("Error registering user");

        res.send({ message: "User registered successfully" });
      }
    );
  });
});

// File upload route (requires JWT authentication)
server.post(
  "/api/upload",
  authenticateToken,
  upload.single("file"),
  (req, res) => {
    if (!req.file) {
      return res.status(400).send("No file uploaded.");
    }

    const userId = req.user.id; // Use the user ID from the decoded JWT
    const { size } = req.file;
    const originalname = Buffer.from(req.file.originalname, "latin1").toString(
      "utf8"
    );

    db.run(
      "INSERT INTO files (userId, filename, filepath, size) VALUES (?, ?, ?, ?)",
      [userId, originalname, req.file.path, size],
      function (err) {
        if (err) {
          return res.status(500).send("Error saving file info to database.");
        }
        res.send({ message: "File uploaded successfully!" });
      }
    );
  }
);

// Get list of files for the logged-in user (requires JWT authentication)
server.get("/api/files", authenticateToken, (req, res) => {
  const userId = req.user.id; // Use the user ID from the decoded JWT

  db.all(
    "SELECT filename, size FROM files WHERE userId = ?",
    [userId],
    (err, files) => {
      if (err) return res.status(500).send("Error retrieving files.");

      res.send(files);
    }
  );
});

// File download route (requires JWT authentication)
server.get("/api/download/:fileName", authenticateToken, (req, res) => {
  const userId = req.user.id; // Use the user ID from the decoded JWT
  const fileName = req.params.fileName;

  db.get(
    "SELECT * FROM files WHERE userId = ? AND filename = ?",
    [userId, fileName],
    (err, file) => {
      if (err) return res.status(500).send("Error retrieving file info.");
      if (!file) return res.status(404).send("File not found.");

      const filePath = path.join(__dirname, "uploads", fileName);
      res.download(filePath);
    }
  );
});

// File delete route (requires JWT authentication)
server.delete("/api/delete/:fileName", authenticateToken, (req, res) => {
  const userId = req.user.id; // Use the user ID from the decoded JWT
  const fileName = req.params.fileName;

  db.get(
    "SELECT * FROM files WHERE userId = ? AND filename = ?",
    [userId, fileName],
    (err, file) => {
      if (err) return res.status(500).send("Error finding file in database.");
      if (!file)
        return res
          .status(404)
          .send("File not found or not authorized to delete.");

      const filePath = path.join(__dirname, "uploads", fileName);
      fs.unlink(filePath, (err) => {
        if (err)
          return res.status(500).send("Error deleting file from filesystem.");

        db.run(
          "DELETE FROM files WHERE userId = ? AND filename = ?",
          [userId, fileName],
          (err) => {
            if (err)
              return res.status(500).send("Error deleting file from database.");

            res.send({ message: "File deleted successfully!" });
          }
        );
      });
    }
  );
});

// Start server
server.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
