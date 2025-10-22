// server.js - Enhanced Version for Code2Cloud
const express = require("express");
const multer = require("multer");
const mysql = require("mysql2");
const cors = require("cors");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const app = express();

// Security Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" }
}));
app.use(cors());
app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true }));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100
});
app.use(limiter);

// Static files
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// Configuration
const PORT = process.env.PORT || 5000;
const UPLOAD_DIR = path.join(__dirname, "uploads");

// Create uploads directory if it doesn't exist
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Improved Database Connection with reconnect
const dbConfig = {
  host: process.env.DB_HOST || "127.0.0.1",
  port: process.env.DB_PORT || 3307,
  user: process.env.DB_USER || "root",
  password: process.env.DB_PASSWORD || "StrongPassword123!",
  database: process.env.DB_NAME || "devops_blog",
  charset: 'utf8mb4',
  connectTimeout: 60000,
  acquireTimeout: 60000,
  timeout: 60000,
  reconnect: true
};

// Create connection with error handling
let db;

function handleDisconnect() {
  db = mysql.createConnection(dbConfig);
  
  db.connect(err => {
    if (err) {
      console.error('Database connection failed:', err.message);
      console.log('Retrying connection in 5 seconds...');
      setTimeout(handleDisconnect, 5000);
    } else {
      console.log('✅ Connected to MySQL Database!');
      
      // Initialize database tables
      initializeDatabase();
    }
  });

  db.on('error', err => {
    console.error('Database error:', err);
    if (err.code === 'PROTOCOL_CONNECTION_LOST' || err.code === 'ECONNRESET') {
      console.log('Database connection lost. Reconnecting...');
      handleDisconnect();
    } else {
      throw err;
    }
  });
}

function initializeDatabase() {
  const createTableSQL = `
    CREATE TABLE IF NOT EXISTS posts (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(255) NOT NULL,
      content TEXT NOT NULL,
      category VARCHAR(100) DEFAULT 'General',
      image VARCHAR(500) NULL,
      read_time INT DEFAULT 5,
      views INT DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )
  `;
  
  db.query(createTableSQL, (err) => {
    if (err) {
      console.error('Error creating posts table:', err.message);
    } else {
      console.log('✅ Posts table ready');
    }
  });
}

handleDisconnect();

// Multer Configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const uniqueName = Date.now() + '-' + Math.round(Math.random() * 1E9) + path.extname(file.originalname);
    cb(null, uniqueName);
  }
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = /jpeg|jpg|png|gif|webp/;
  const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
  const mimetype = allowedTypes.test(file.mimetype);

  if (mimetype && extname) {
    return cb(null, true);
  } else {
    cb(new Error('Only image files are allowed!'), false);
  }
};

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter
});

// Authentication Middleware
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || "admin";
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "1234";

function verifyAdmin(req, res, next) {
  const authHeader = req.headers.authorization;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    const [username, password] = Buffer.from(token, 'base64').toString().split(':');

    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      return next();
    }
  }

  // Fallback to body auth for compatibility
  const { username, password } = req.body;
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    return next();
  }

  res.status(401).json({
    success: false,
    message: "Unauthorized: Invalid admin credentials"
  });
}

// Utility Functions
function sanitizeInput(input) {
  if (typeof input !== 'string') return input;
  return input.trim().replace(/[<>]/g, '');
}

function calculateReadTime(content) {
  const wordsPerMinute = 200;
  const wordCount = content.split(/\s+/).length;
  return Math.ceil(wordCount / wordsPerMinute);
}

// API Routes

// Health Check
app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    message: "Server is running healthy!",
    timestamp: new Date().toISOString()
  });
});

// DEBUG ENDPOINTS - Add these for troubleshooting

// Test database connection
app.get("/api/debug/db", (req, res) => {
  db.query("SELECT 1 as test", (err, results) => {
    if (err) {
      return res.status(500).json({
        success: false,
        message: "Database connection failed",
        error: err.message
      });
    }
    res.json({
      success: true,
      message: "Database connected successfully",
      result: results[0]
    });
  });
});

// Debug endpoint to check posts
app.get("/api/debug/posts", (req, res) => {
  db.query("SELECT * FROM posts", (err, results) => {
    if (err) {
      console.error("Debug - Database error:", err);
      return res.status(500).json({ 
        success: false, 
        error: err.message,
        connection: "Database connection failed"
      });
    }
    
    console.log("Debug - Posts found:", results.length);
    res.json({
      success: true,
      totalPosts: results.length,
      posts: results,
      database: "Connected successfully"
    });
  });
});

// Create sample post for testing
app.post("/api/debug/create-sample", (req, res) => {
  const samplePost = {
    title: "Sample DevOps Post - Test",
    content: "<p>This is a sample post content for testing.</p><p>If you can see this, your backend is working!</p>",
    category: "DevOps",
    read_time: 2,
    views: 0
  };

  const sql = `INSERT INTO posts (title, content, category, read_time, views) VALUES (?, ?, ?, ?, ?)`;
  
  db.query(sql, [samplePost.title, samplePost.content, samplePost.category, samplePost.read_time, samplePost.views], (err, result) => {
    if (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
    
    res.json({
      success: true,
      message: "Sample post created",
      postId: result.insertId
    });
  });
});

// Create a new blog post (Admin only)
app.post("/api/posts", verifyAdmin, upload.single("image"), (req, res) => {
  try {
    let { title, content, category } = req.body;

    if (!title || !content) {
      return res.status(400).json({
        success: false,
        message: "Title and content are required"
      });
    }

    title = sanitizeInput(title);
    content = sanitizeInput(content);
    category = category ? sanitizeInput(category) : 'General';

    const image = req.file ? `/uploads/${req.file.filename}` : null;
    const read_time = calculateReadTime(content);
    const views = 0;

    const sql = `INSERT INTO posts (title, content, category, image, read_time, views)
                 VALUES (?, ?, ?, ?, ?, ?)`;

    db.query(sql, [title, content, category, image, read_time, views], (err, result) => {
      if (err) {
        console.error("Insert Error:", err.message);
        if (req.file) fs.unlinkSync(req.file.path);
        return res.status(500).json({ success: false, message: err.message });
      }

      res.json({
        success: true,
        message: "Post published successfully!",
        postId: result.insertId
      });
    });

  } catch (error) {
    console.error("Create Post Error:", error.message);
    if (req.file) fs.unlinkSync(req.file.path);
    res.status(500).json({
      success: false,
      message: "Internal server error"
    });
  }
});

// Delete post (Admin only)
app.delete("/api/posts/:id", verifyAdmin, (req, res) => {
  const { id } = req.params;

  db.query("SELECT image FROM posts WHERE id = ?", [id], (err, results) => {
    if (err) return res.status(500).json({ success: false, message: "Error fetching post" });
    if (results.length === 0) return res.status(404).json({ success: false, message: "Post not found" });

    const imagePath = results[0].image ? path.join(__dirname, results[0].image) : null;

    db.query("DELETE FROM posts WHERE id = ?", [id], (err2) => {
      if (err2) return res.status(500).json({ success: false, message: "Error deleting post" });

      if (imagePath && fs.existsSync(imagePath)) fs.unlinkSync(imagePath);
      res.json({ success: true, message: "Post deleted successfully!" });
    });
  });
});

// Increment post views
app.post("/api/posts/:id/view", (req, res) => {
  const { id } = req.params;

  db.query("UPDATE posts SET views = COALESCE(views, 0) + 1 WHERE id = ?", [id], (err) => {
    if (err) {
      console.error("View Count Error:", err.message);
      return res.status(500).json({ success: false, message: "Internal server error" });
    }

    res.json({
      success: true,
      message: "View count updated"
    });
  });
});

// Fetch all posts with enhanced data
app.get("/api/posts", (req, res) => {
  const category = req.query.category;

  let sql = "SELECT * FROM posts";
  let params = [];

  if (category && category !== 'all') {
    sql += " WHERE category = ?";
    params.push(category);
  }

  sql += " ORDER BY created_at DESC";

  db.query(sql, params, (err, results) => {
    if (err) {
      console.error("Fetch Error:", err.message);
      return res.status(500).json({ success: false, message: err.message });
    }

    // Add read_time if not exists for backward compatibility
    const enhancedResults = results.map(post => ({
      ...post,
      read_time: post.read_time || calculateReadTime(post.content),
      views: post.views || 0
    }));

    res.json(enhancedResults);
  });
});

// Fetch single post
app.get("/api/posts/:id", (req, res) => {
  const { id } = req.params;

  db.query("SELECT * FROM posts WHERE id = ?", [id], (err, results) => {
    if (err) {
      console.error("Fetch Error:", err.message);
      return res.status(500).json({ success: false, message: err.message });
    }

    if (results.length === 0) {
      return res.status(404).json({ success: false, message: "Post not found" });
    }

    const post = results[0];
    // Enhance post data
    post.read_time = post.read_time || calculateReadTime(post.content);
    post.views = post.views || 0;

    res.json(post);
  });
});

// Get statistics
app.get("/api/stats", (req, res) => {
  const queries = {
    totalPosts: "SELECT COUNT(*) as count FROM posts",
    totalViews: "SELECT COALESCE(SUM(views), 0) as total FROM posts",
    categories: "SELECT category, COUNT(*) as count FROM posts GROUP BY category"
  };

  db.query(queries.totalPosts, (err, postResults) => {
    if (err) return res.status(500).json({ success: false, message: "Error fetching stats" });

    db.query(queries.totalViews, (err, viewResults) => {
      if (err) return res.status(500).json({ success: false, message: "Error fetching stats" });

      db.query(queries.categories, (err, categoryResults) => {
        if (err) return res.status(500).json({ success: false, message: "Error fetching stats" });

        res.json({
          success: true,
          stats: {
            totalPosts: postResults[0].count,
            totalViews: viewResults[0].total,
            categories: categoryResults
          }
        });
      });
    });
  });
});

// Search posts
app.get("/api/search", (req, res) => {
  const query = req.query.q;

  if (!query || query.length < 2) {
    return res.status(400).json({
      success: false,
      message: "Search query must be at least 2 characters long"
    });
  }

  const searchTerm = `%${query}%`;
  const sql = `SELECT * FROM posts
               WHERE title LIKE ? OR content LIKE ? OR category LIKE ?
               ORDER BY created_at DESC
               LIMIT 20`;

  db.query(sql, [searchTerm, searchTerm, searchTerm], (err, results) => {
    if (err) {
      console.error("Search Error:", err.message);
      return res.status(500).json({ success: false, message: "Internal server error" });
    }

    res.json({
      success: true,
      posts: results,
      count: results.length
    });
  });
});

// Admin login
app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;

  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = Buffer.from(`${username}:${password}`).toString('base64');

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: { username }
    });
  } else {
    res.status(401).json({
      success: false,
      message: "Invalid credentials"
    });
  }
});

// Global error handler
app.use((error, req, res, next) => {
  console.error("Global Error:", error.message);

  if (error instanceof multer.MulterError) {
    if (error.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        success: false,
        message: 'File too large. Maximum size is 5MB.'
      });
    }
  }

  res.status(500).json({
    success: false,
    message: "Internal server error"
  });
});

// 404 handler - MUST be last
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "API endpoint not found"
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Enhanced Backend running on port ${PORT}`);
  console.log(`🔍 Health check: http://localhost:${PORT}/api/health`);
  console.log(`🐛 Debug endpoints available:`);
  console.log(`   http://localhost:${PORT}/api/debug/db`);
  console.log(`   http://localhost:${PORT}/api/debug/posts`);
  console.log(`👤 Admin username: ${ADMIN_USERNAME}`);
});
