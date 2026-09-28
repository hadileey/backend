require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();

// Middleware
app.use(express.json());
app.use(cors());

// Environment variables
const PORT = process.env.PORT || 5000;
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;

// Check JWT secret
if (!JWT_SECRET) {
  console.error("❌ JWT_SECRET is missing in .env");
  process.exit(1);
}

// MongoDB connection
mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log("✅ MongoDB Connected");
  })
  .catch((error) => {
    console.error("❌ MongoDB Connection Error:", error);
  });

// User Schema
const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: true,
      unique: true,
      trim: true,
    },

    password: {
      type: String,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

const User = mongoose.model("User", userSchema);

// =====================================================
// REGISTER
// =====================================================

app.post("/register", async (req, res) => {
  try {
    const { username, password } = req.body;

    // Validation
    if (!username || !password) {
      return res.status(400).json({
        message: "Username and password are required",
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        message: "Password must contain at least 6 characters",
      });
    }

    // Check existing user
    const existingUser = await User.findOne({ username });

    if (existingUser) {
      return res.status(409).json({
        message: "Username already exists",
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const user = new User({
      username,
      password: hashedPassword,
    });

    await user.save();

    console.log("✅ USER REGISTERED");
    console.log("Username:", username);

    res.status(201).json({
      message: "Registration Successful!",
    });
  } catch (error) {
    console.error("❌ REGISTER ERROR:", error);

    res.status(500).json({
      message: "Registration failed",
    });
  }
});

// =====================================================
// LOGIN
// =====================================================

app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    console.log("\n========== LOGIN ==========");
    console.log("Username:", username);

    // Validation
    if (!username || !password) {
      return res.status(400).json({
        message: "Username and password are required",
      });
    }

    // Find user
    const user = await User.findOne({ username });

    if (!user) {
      console.log("❌ USER NOT FOUND");

      return res.status(401).json({
        message: "Invalid username or password",
      });
    }

    // Compare password with bcrypt hash
    const validPassword = await bcrypt.compare(
      password,
      user.password
    );

    console.log("Password valid:", validPassword);

    if (!validPassword) {
      console.log("❌ INVALID PASSWORD");

      return res.status(401).json({
        message: "Invalid username or password",
      });
    }

    // Generate JWT
    const token = jwt.sign(
      {
        userId: user._id.toString(),
        username: user.username,
      },
      JWT_SECRET,
      {
        expiresIn: "1h",
      }
    );

    console.log("✅ PASSWORD VERIFIED");
    console.log("✅ JWT GENERATED");
    console.log("===========================\n");

    res.status(200).json({
      message: "JWT Authentication Successful!",
      token: token,
    });
  } catch (error) {
    console.error("❌ LOGIN ERROR:", error);

    res.status(500).json({
      message: "Server error",
    });
  }
});

// =====================================================
// JWT AUTHENTICATION MIDDLEWARE
// =====================================================

const authenticate = (req, res, next) => {
  const authHeader = req.headers.authorization;

  // Check Authorization header
  if (!authHeader) {
    return res.status(401).json({
      message: "Access denied. No token provided.",
    });
  }

  // Expected format:
  // Authorization: Bearer TOKEN

  const parts = authHeader.split(" ");

  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({
      message: "Invalid authorization format.",
    });
  }

  const token = parts[1];

  try {
    // Verify JWT
    const decoded = jwt.verify(token, JWT_SECRET);

    req.user = decoded;

    console.log("✅ JWT VERIFIED");

    next();
  } catch (error) {
    console.log("❌ JWT VERIFICATION FAILED");

    return res.status(401).json({
      message: "Invalid or expired JWT token",
    });
  }
};

// =====================================================
// PROTECTED PROFILE ROUTE
// =====================================================

app.get("/profile", authenticate, (req, res) => {
  res.status(200).json({
    message: "JWT Verified Successfully!",
    userId: req.user.userId,
    username: req.user.username,
  });
});

// =====================================================
// TEST ROUTE
// =====================================================

app.get("/", (req, res) => {
  res.json({
    message: "JWT Authentication API is running",
  });
});

// =====================================================
// START SERVER
// =====================================================

app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});